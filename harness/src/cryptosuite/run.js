#!/usr/bin/env node
/**
 * Scenario A re-run against the full W3C bbs-2023 cryptosuite.
 *
 *   node src/cryptosuite/run.js          human-readable report
 *   node src/cryptosuite/run.js --json   machine-readable results
 */
import {readFileSync, writeFileSync} from 'node:fs';
import {clusteringAttack, conjunctionAttack, fieldTable} from '../harness.js';
import {h1, h2, LEAK_COLUMNS, table} from '../report.js';
import {TARGET} from '../world.js';
import {POLICIES} from './mandate.js';
import {buildCorpus, issueCohort} from './scenario.js';
import {
  cohortMonteCarlo, collusion, crossHopProbe, labelShuffleSweep, mandatoryQuadTable, orderingProbe, probeRows,
  proofRandomisation, revocationReachability
} from './probes.js';

const version = pkg => JSON.parse(readFileSync(
  new URL(`../../node_modules/${pkg}/package.json`, import.meta.url))).version;
const LIBS = ['@digitalbazaar/bbs-2023-cryptosuite', '@digitalbazaar/data-integrity',
  '@digitalbazaar/vc', '@digitalbazaar/di-sd-primitives', '@digitalbazaar/bls12-381-multikey',
  '@digitalbazaar/bbs-signatures', 'jsonld', 'rdf-canonize'].map(p => ({p, v: version(p)}));

const json = process.argv.includes('--json');
const out = [];
const say = s => out.push(s);
const t0 = Date.now();

const results = [];
for(const [key, policy] of Object.entries(POLICIES)) {
  const {cohort, corpus, verification} = await buildCorpus(policy);
  const tbl = fieldTable({corpus, target: TARGET});
  const clustering = clusteringAttack({corpus, target: TARGET});
  const conjunction = conjunctionAttack({corpus, target: TARGET});
  // Only the policies not already deterministically falsified need the
  // (expensive) cohort-level Monte Carlo; for the others it would be 1.00.
  const monteCarlo = policy.docShape === 'per-credential' ? null
    : await cohortMonteCarlo({policy, reps: 30, issueCohort});
  const randomisation = proofRandomisation(corpus);
  const coll = await collusion({cohort, corpus, policy});
  const revocation = await revocationReachability({cohort, policy});
  const hard = tbl.filter(r => r.leak === 'Y');
  const mechanisms = [
    ...hard.map(h => h.path),
    ...(conjunction.exactLinkage && !hard.length ? ['conjunction of partial fields'] : []),
    ...(coll.linked ? ['issuer collusion'] : []),
    ...(monteCarlo?.unique ? [`HMAC label tag (target unique in ${monteCarlo.unique}/${monteCarlo.reps} cohorts)`] : [])
  ];
  const verdict = (mechanisms.length || clustering.exactLinkage || !randomisation.pass)
    ? 'FALSIFIED' : 'NOT-FALSIFIED';
  results.push({
    key, policy, corpus, table: tbl, clustering, conjunction, monteCarlo, mechanisms,
    randomisation, collusion: coll,
    revocation, probes: probeRows(tbl), mandatoryQuads: mandatoryQuadTable(corpus),
    verified: verification.filter(v => v.verified).length,
    firstError: verification.find(v => !v.verified)?.error ?? null,
    hard, verdict
  });
}
const sweep = await labelShuffleSweep({trials: 30});
const crossHop = [];
for(const key of ['hardened', 'hardenedFlat']) {
  crossHop.push({key, ...(await crossHopProbe({policy: POLICIES[key], issueCohort, reps: 20}))});
}
const ordering = await orderingProbe({trials: 3});
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

const report = {
    libraries: LIBS, spec: 'W3C Data Integrity BBS Cryptosuites v1.0, Candidate Recommendation Draft 10 September 2026 (consulted); implementation covers the bbs-2023 baseline feature only (derived-proof CBOR tag d95d03)',
    policies: results.map(r => ({
      key: r.key, label: r.policy.label, mandatoryPointers: r.policy.mandatoryPointers,
      selectivePointers: r.policy.selectivePointers, verdict: r.verdict,
      verified: `${r.verified}/${r.corpus.length}`, table: r.table,
      mitigationCandidate: !!r.policy.mitigationCandidate, mechanisms: r.mechanisms,
      clustering: r.clustering, conjunction: r.conjunction, monteCarlo: r.monteCarlo,
      randomisation: r.randomisation, collusion: r.collusion,
      revocation: r.revocation, mandatoryQuads: r.mandatoryQuads,
      sampleDerivedCredential: r.corpus.find(p => p.subject === TARGET).payload
    })),
    sweep, ordering,
    crossHop: crossHop.map(x => ({key: x.key, hop2Pointers: x.hop2Pointers, reps: x.reps,
      unique: x.unique, pUnique: x.pUnique, pass: x.detail.pass,
      hardCorrelators: x.detail.hardCorrelators, narrowing: x.detail.narrowingCorrelators})),
    elapsed
  };
const jsonIdx = process.argv.indexOf('--write-json');
if(jsonIdx > 0) {
  // same run, same HMAC keys: the text and JSON outputs describe identical data
  writeFileSync(process.argv[jsonIdx + 1], JSON.stringify(report, null, 2) + '\n');
}
if(json) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

say(h1('Open Core -- P1 re-run against the W3C bbs-2023 cryptosuite (Scenario A)'));
for(const {p, v} of LIBS) {
  say(`  ${p.padEnd(40)} ${v}`);
}
say('spec     : W3C Data Integrity BBS Cryptosuites v1.0, CR Draft 10 Sep 2026 (consulted);');
say('           implementation: bbs-2023 BASELINE feature only (derived-proof tag d95d03)');
say(`cohort   : 6 dependents (target = ${TARGET}), 4 relying parties; target presents 6x`);
say('payload  : the derived VC exactly as received, PLUS `decoded.*` = what any verifier');
say('           obtains by parsing proof.proofValue (the BBS proof is inside it)');
say('This harness attempts to FALSIFY P1. It cannot prove it.');

for(const r of results) {
  say(h1(`POLICY ${r.key}: ${r.policy.label}`));
  say(`mandatoryPointers : ${JSON.stringify(r.policy.mandatoryPointers)}`);
  say(`selectivePointers : ${JSON.stringify(r.policy.selectivePointers)}`);
  say(`presentations     : ${r.corpus.length}, verified by @digitalbazaar/vc: ` +
    `${r.verified}/${r.corpus.length}${r.firstError ? `  (first error: ${r.firstError})` : ''}`);

  say(h2(`Leak table (${r.key})`));
  say('k = number of distinct dependents sharing this value (k=1 exact linkage, k=6 none)');
  say(table(r.table, LEAK_COLUMNS));

  say(`\n(c) randomisation: ${r.randomisation.distinctBbsProof}/${r.randomisation.total} ` +
    `distinct bbsProof, ${r.randomisation.distinctProofValue}/${r.randomisation.total} ` +
    `distinct proofValue -> ${r.randomisation.pass ? 'PASS' : 'HARD FAIL'}`);

  const c = r.clustering;
  say('\nGeneric clustering adversary (no allowlist):');
  if(c.bestSingleField) {
    say(`  best single field: ${c.bestSingleField.path}  -> precision ` +
      `${c.bestSingleField.precision.toFixed(2)}, recall ${c.bestSingleField.recall.toFixed(2)}`);
  }
  say(`  -> ${c.exactLinkage ? 'EXACT LINKAGE of the target\'s presentations'
    : c.partialLinkage ? 'partial narrowing only' : 'no linkage recovered'}`);
  const j = r.conjunction;
  say(`Conjunction adversary (tuple of all ${j.pathsUsed} non-random fields): target group ` +
    `${j.groupSize} payloads from ${j.subjectsInGroup} dependent(s), precision ` +
    `${j.precision.toFixed(2)}, recall ${j.recall.toFixed(2)} -> ` +
    `${j.exactLinkage ? 'EXACT LINKAGE' : 'no exact linkage'}`);
  if(r.monteCarlo) {
    const mc = r.monteCarlo;
    say(`Cohort Monte Carlo (${mc.reps} fresh cohorts, new HMAC keys each): target exactly ` +
      `linkable in ${mc.unique}/${mc.reps} = ${(100 * mc.pUnique).toFixed(0)}% ` +
      `(proof-internal parts alone: ${mc.uniqueProofPartsOnly}/${mc.reps})`);
  }

  say('\n(d) issuer + verifier collusion:');
  for(const f of r.collusion.findings) {
    say(`  [${f.leak ? 'LEAK' : ' ok '}] ${f.check}: ${f.result}`);
  }

  const short = rows => rows.length
    ? rows.map(x => `    ${x.path.padEnd(34)} constant=${x.constant ? 'yes' : 'no '} ` +
      `k=${String(x.anonymitySet ?? '-').padEnd(2)} leak=${x.leak}`).join('\n')
    : '    (no matching fields)';
  say('\n(h) mandatory-disclosed statements, their count and hash:');
  say(short(r.probes.h));
  say('    per mandatory N-Quad (as the verifier canonicalises it):');
  for(const q of r.mandatoryQuads) {
    say(`      k=${q.k}/${q.cohort}  ${q.quad.length > 110 ? `${q.quad.slice(0, 110)}...` : q.quad}`);
  }
  if(!r.mandatoryQuads.length) {
    say('      (no mandatory statements)');
  }
  say('\n(i) proof object / proofValue envelope:');
  say(short(r.probes.i));
  say('\n(j) document structure fingerprint:');
  say(short(r.probes.j));
  say('\n(k) HMAC label replacement and index lists:');
  say(short(r.probes.k));

  say(`\nrevocation: status entry in credential=${r.revocation.statusEntryInCredential}, ` +
    `disclosed=${r.revocation.statusEntryDisclosed}, revoked credential accepted=` +
    `${r.revocation.acceptedAfterRevocation ? 'YES' : 'no'} -- ${r.revocation.note}`);

  say(`\nVERDICT (${r.key}): ${r.verdict}` + (r.mechanisms.length
    ? ` via ${r.mechanisms.join('; ')}` : ''));
}

say(h1('(k) Monte Carlo: identifying entropy of the HMAC blank-node shuffle'));
say('Identical claims issued 30x per shape; only the cryptosuite\'s per-credential');
say('HMAC key differs. Each distinct tag is repeated on EVERY presentation of that');
say('credential. N = blank nodes in the credential, m = blank nodes revealed.');
say(table(sweep, [
  {header: 'shape', get: r => `${r.key} ${r.label}`},
  {header: 'N', get: r => r.N},
  {header: 'm', get: r => r.m},
  {header: 'distinct tags / 30', get: r => r.distinctTags},
  {header: 'labelMaps', get: r => r.distinctLabelMaps},
  {header: 'selIdx', get: r => r.distinctSelectiveIndexes},
  {header: 'theory N!/(N-m)!', get: r => r.theory},
  {header: 'spec bound C(N,m)', get: r => r.specBound},
  {header: 'bits', get: r => r.bits.toFixed(2)},
  {header: 'P(target unique in 6)', get: r => r.pUniqueIn6.toFixed(2)},
  {header: 'verified', get: r => r.sanityVerified}
]));

say(h2('ordering side channel: hidden sibling in a multi-valued property'));
for(const o of ordering.results) {
  say(`  hidden="${o.hidden}"  revealed=${o.revealedSubject}  selectiveIndexes=${o.selectiveIndexes.join(' ')}`);
}
say(`  revealed documents identical: ${ordering.revealedDocumentsIdentical ? 'yes' : 'NO'}; ` +
  `selective indexes differ: ${ordering.indexesDiffer ? 'YES -- the index leaks how the hidden value sorts' : 'no'}` +
  `${ordering.deterministic ? ' (deterministic across issuances)' : ''}`);

say(h1('(e) CROSS-HOP (optional Scenario B probe): guardian vs parent proof in a chain'));
say('Hop 1 = guardian discloses scope. Hop 2 = parent-mandate proof inside a sub-carer');
say('chain, additionally disclosing guardianKey (hop binding, as B-unlinkable-stable).');
say('Raw-scheme result for this pairing (FINDINGS_2026-08 4.6): PASS.');
for(const x of crossHop) {
  say(h2(`${x.key}: ${POLICIES[x.key].label}`));
  const rows = x.detail.correlators.filter(c => c.anonymitySet < c.cohortSize);
  if(rows.length) {
    say(table(rows, [
      {header: 'shared atom', get: r => r.atom},
      {header: 'k', get: r => r.anonymitySet},
      {header: 'hop1 field', get: r => r.hop1Paths[0]},
      {header: 'hop2 field', get: r => r.hop2Paths[0]},
      {header: 'leak', get: r => r.hard ? 'Y' : 'partial'}
    ]));
  } else {
    say('  no shared value narrows the anonymity set');
  }
  say(`  single-atom check in this cohort: ${x.detail.pass ? 'PASS (no k=1 atom)' : 'FAIL'}`);
  say(`  joint blank-node ranks, Monte Carlo over ${x.reps} cohorts: target linkable across ` +
    `hops in ${x.unique}/${x.reps} = ${(100 * x.pUnique).toFixed(0)}%`);
  say(`  (e) CROSS-HOP UNLINKABILITY: ${(x.detail.pass && x.unique === 0) ? 'PASS' : 'FAIL'}`);
}

say(h1('SUMMARY'));
say(table(results.map(r => ({
  policy: r.key + (r.policy.mitigationCandidate ? ' *' : ''), verdict: r.verdict,
  mech: r.mechanisms.join('; ') || '-',
  mc: r.monteCarlo ? `${r.monteCarlo.unique}/${r.monteCarlo.reps}` : 'n/a (deterministic)',
  d3: r.collusion.findings.find(f => f.check.startsWith('d3 ')).result
})), [
  {header: 'policy', get: r => r.policy},
  {header: 'P1 verdict', get: r => r.verdict},
  {header: 'mechanism', get: r => r.mech},
  {header: 'cohorts linkable (MC)', get: r => r.mc},
  {header: 'issuer collusion (d3)', get: r => r.d3}
]));
say('* mitigation candidate added after probe (k); not one of the three requested policies');
say(`\nruntime: ${elapsed}s`);
say('\nNOTE: the HMAC key is drawn fresh by the cryptosuite at every issuance and');
say('cannot be seeded, so labelMap-derived k values vary between runs. The Monte');
say('Carlo table gives the stable number. "NOT-FALSIFIED" is not a proof.');
console.log(out.join('\n'));

// Sanity gate. A finding is not a failure -- but an HONEST presentation that
// fails to verify means the harness itself is broken, and its tables would be
// measuring garbage. Exit non-zero in that case only.
const broken = results.filter(r => r.verified !== r.corpus.length);
if(broken.length) {
  console.error(`HARNESS MALFUNCTION: honest presentations failed to verify in ` +
    `${broken.map(r => r.key).join(', ')}`);
  process.exit(1);
}
