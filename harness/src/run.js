#!/usr/bin/env node
/**
 * Entry point. Runs the whole falsification attempt and prints the report.
 *
 *   node src/run.js          human-readable report
 *   node src/run.js --json   machine-readable results
 */
import {buildWorld} from './world.js';
import {runCrossHop, runScenarioA, runScenarioB} from './scenarios.js';
import {
  runAttenuationAttacks, runCascadingRevocation, runSingleHopRevocation,
  runTransportAttacks
} from './attacks.js';
import {h1, h2, renderAnalysis, renderCrossHop, table} from './report.js';
import {CIPHERSUITE} from './bbs.js';
import {readFileSync} from 'node:fs';

// read the pinned version straight out of node_modules (the package does not
// export ./package.json, so `require()` on it fails under Node's exports map)
const libVersion = JSON.parse(readFileSync(
  new URL('../node_modules/@digitalbazaar/bbs-signatures/package.json', import.meta.url)
)).version;

const json = process.argv.includes('--json');
const out = [];
const say = s => out.push(s);

const t0 = Date.now();
const world = await buildWorld();

const scenarioA = await runScenarioA(world);
const scenarioB = await runScenarioB(world);
const crossHop = runCrossHop({scenarioA, scenarioB});
const attenuation = await runAttenuationAttacks(world);
const transports = await runTransportAttacks(world);
const cascading = await runCascadingRevocation(world);
const singleHopRevocation = await runSingleHopRevocation(world);
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

if(json) {
  console.log(JSON.stringify({
    library: {name: '@digitalbazaar/bbs-signatures', version: libVersion, ciphersuite: CIPHERSUITE},
    scenarioA: scenarioA.map(r => ({key: r.key, functional: r.functional, analysis: strip(r.analysis)})),
    scenarioB: scenarioB.map(r => ({key: r.key, functional: r.functional, analysis: strip(r.analysis)})),
    crossHop, attenuation, transports, cascading, singleHopRevocation, elapsed
  }, null, 2));
  process.exit(0);
}

say(h1('Open Core -- P1 repeat-presentation unlinkability: falsification harness'));
say(`primitive : @digitalbazaar/bbs-signatures@${libVersion} (IETF draft-irtf-cfrg-bbs-signatures-06)`);
say(`ciphersuite: ${CIPHERSUITE}`);
say(`cohort    : ${world.subjects.length} dependents (target = ${world.target}), ` +
  `${world.verifiers.length} relying parties`);
say('This harness attempts to FALSIFY the unlinkability claim. It cannot prove it.');

/* ---------------------------------- A ------------------------------------ */
say(h1('SCENARIO A -- single hop (guardian presents the mandate)'));
for(const r of scenarioA) {
  say(`\n### profile: ${r.key} -- ${r.profile.label}`);
  say(`presentations: ${r.functional.presentations}, accepted by verifiers: ` +
    `${r.functional.accepted}/${r.functional.presentations}`);
  say(renderAnalysis(r.analysis));
}

say(h2('Revocation reachability, single hop (context for P3)'));
say(table(singleHopRevocation, [
  {header: 'profile', get: r => r.profile},
  {header: 'revoked mandate still accepted?', get: r => r.acceptedAfterRevocation ? 'YES' : 'no'},
  {header: 'revocation enforced?', get: r => r.revocationEnforced ? 'yes' : 'NO'},
  {header: 'note', get: r => r.note}
]));

/* ---------------------------------- B ------------------------------------ */
say(h1('SCENARIO B -- two hops (guardian -> temporary sub-carer)'));
for(const r of scenarioB) {
  say(`\n### profile: ${r.key} -- ${r.profile.label}`);
  say(`presentations: ${r.functional.presentations}, accepted: ${r.functional.accepted}` +
    `, verifier could check attenuation in ${r.functional.attenuationCheckable}` +
    `, could check parent revocation in ${r.functional.parentRevocationCheckable}`);
  if(r.functional.firstRejection) {
    say(`first rejection reason: ${r.functional.firstRejection}`);
  }
  say(renderAnalysis(r.analysis));
}

say(h1('(e) CROSS-HOP UNLINKABILITY'));
for(const x of crossHop) {
  say(renderCrossHop(x));
}

say(h1('(f) ATTENUATION -- active scope-escalation attempts'));
say(table(attenuation, [
  {header: 'chain profile', get: r => r.profile},
  {header: 'attack', get: r => r.attack},
  {header: 'accepted?', get: r => r.accepted ? 'YES' : 'no'},
  {header: 'expected', get: r => r.expected ? 'accept' : 'reject'},
  {header: 'result', get: r => (r.accepted === r.expected) ? 'PASS' : 'FAIL'},
  {header: 'outcome', get: r => r.outcome}
]));
const attFailures = attenuation.filter(r => r.accepted !== r.expected);
say(`\n(f) ATTENUATION: ${attFailures.length === 0 ? 'PASS for every chain profile'
  : `FAIL -- ${attFailures.length} escalation(s) succeeded`}`);
for(const f of attFailures) {
  say(`    FAIL: [${f.profile}] ${f.attack} -> ${f.outcome}`);
}

say(h2('delegation transport attacks (how hop 2 obtains a hop-1 proof)'));
for(const t of transports) {
  say(`  [${t.accepted === t.expected ? 'PASS' : 'FAIL'}] ${t.attack}`);
  say(`         ${t.outcome}`);
  if(t.extra) {
    say(`         accepted by a verifier that does not check nonce freshness: ` +
      `${t.extra.acceptedByLaxVerifier ? 'YES' : 'no'}`);
    say(`         parent proof bytes identical across two verifiers: ` +
      `${t.extra.parentProofBytesIdenticalAcrossVerifiers ? 'YES (hard linkability leak)' : 'no'}`);
  }
}

say(h1('(g) CASCADING REVOCATION -- revoke the parent, re-present as sub-carer'));
say(table(cascading, [
  {header: 'chain profile', get: r => r.profile},
  {header: 'ok before revocation', get: r => r.acceptedBeforeRevocation ? 'yes' : 'NO'},
  {header: 'still accepted after', get: r => r.acceptedAfterRevocation ? 'YES' : 'no'},
  {header: 'result', get: r => r.pass ? 'PASS' : 'FAIL'},
  {header: 'note', get: r => r.note}
]));
const casFail = cascading.filter(r => !r.pass);
say(`\n(g) CASCADING REVOCATION: ${casFail.length === 0 ? 'PASS for every chain profile'
  : `FAIL for ${casFail.map(r => r.profile).join(', ')}`}`);

/* ------------------------------- summary --------------------------------- */
say(h1('SUMMARY'));
const summaryRows = [
  ...scenarioA.map(r => ({
    scenario: 'A single-hop', profile: r.key, verdict: r.analysis.verdict,
    detail: r.analysis.hardLeaks.length
      ? `${r.analysis.hardLeaks.length} hard correlator(s): ` +
        r.analysis.hardLeaks.map(l => l.path).slice(0, 3).join(', ')
      : 'no k=1 correlator found in this harness'
  })),
  ...scenarioB.map(r => ({
    scenario: 'B multi-hop', profile: r.key, verdict: r.analysis.verdict,
    detail: r.analysis.hardLeaks.length
      ? `${r.analysis.hardLeaks.length} hard correlator(s): ` +
        r.analysis.hardLeaks.map(l => l.path).slice(0, 3).join(', ')
      : 'no k=1 correlator found in this harness'
  }))
];
say(table(summaryRows, [
  {header: 'scenario', get: r => r.scenario},
  {header: 'profile', get: r => r.profile},
  {header: 'P1 verdict', get: r => r.verdict},
  {header: 'detail', get: r => r.detail}
]));

say(table(crossHop.map((x, i) => ({
  pair: ['naive x auditable', 'hardened x unlinkableStable', 'hardened x unlinkableFresh'][i],
  e: x.pass ? 'PASS' : 'FAIL',
  n: x.hardCorrelators.length
})), [
  {header: 'cross-hop pair', get: r => r.pair},
  {header: '(e) cross-hop unlinkability', get: r => r.e},
  {header: 'hard correlators', get: r => r.n}
]));

const CHAIN_ORDER = ['auditable', 'unlinkableStable', 'unlinkableFresh'];
say(table(CHAIN_ORDER.map(k => ({
  profile: k,
  p1: scenarioB.find(r => r.key === k).analysis.verdict,
  f: attenuation.filter(r => r.profile === k).every(r => r.accepted === r.expected) ? 'PASS' : 'FAIL',
  g: cascading.find(r => r.profile === k).pass ? 'PASS' : 'FAIL',
  e: crossHop[CHAIN_ORDER.indexOf(k)].pass ? 'PASS' : 'FAIL'
})), [
  {header: 'chain profile', get: r => r.profile},
  {header: 'P1 within hop 2', get: r => r.p1},
  {header: '(e) cross-hop unlinkable', get: r => r.e},
  {header: '(f) attenuation holds', get: r => r.f},
  {header: '(g) cascading revocation', get: r => r.g}
]));
say('\nNote on (e) vs "P1 within hop 2": (e) only asks whether a GUARDIAN presentation');
say('can be tied to a SUB-CARER presentation. A profile can pass (e) and still be');
say('FALSIFIED for P1, because the sub-carer\'s own presentations link to each other.');

say(`\nruntime: ${elapsed}s`);
say('\nNOTE: a "NOT-FALSIFIED" verdict means this harness found no structural ' +
  'correlator.\nIt is NOT a proof of unlinkability. See FINDINGS.md for limitations.');

console.log(out.join('\n'));

/** Drop bulky per-payload detail from the JSON output. */
function strip(a) {
  return {
    name: a.name, verdict: a.verdict, table: a.table,
    proofs: {...a.proofs, collisions: a.proofs.collisions.length},
    clustering: a.clustering, collusion: a.collusion
  };
}
