/**
 * Cryptosuite-specific probes (h)-(k), the issuer-collusion checks re-done for
 * bbs-2023, and a Monte Carlo sweep that measures how much identifying entropy
 * the HMAC blank-node shuffle puts into every derived proof.
 */
import * as vc from '@digitalbazaar/vc';
import {canonicalize} from '@digitalbazaar/di-sd-primitives';
import {flatten} from '../harness.js';
import {TARGET} from '../world.js';
import {ISSUER, MANDATE_CONTEXT_URL, documentLoader, signSuite} from './env.js';
import {adversaryView, decodeBaseProofValue, decodeDerivedProofValue} from './decode.js';
import {crossHopAnalysis} from '../crosshop.js';
import {derive, verify} from './scenario.js';

/* ------------------------- (h)(i)(j)(k) summaries ------------------------- */

const pick = (table, pred) => table.filter(r => pred(r.path));

export function probeRows(table) {
  return {
    h: pick(table, p => /^decoded\.(mandatory|revealedNQuad)/.test(p) ||
      ['validUntil', 'issuer'].includes(p) || p.startsWith('credentialStatus.')),
    i: pick(table, p => p.startsWith('proof.') || p === 'decoded.cborTag' ||
      p === 'decoded.presentationHeader' || p === 'decoded.bbsProof'),
    j: pick(table, p => ['decoded.documentShape', 'decoded.revealedNQuadCount',
      'decoded.proofValueByteLength', 'decoded.bbsProofByteLength',
      'decoded.labelMapSize', '@context', 'type'].includes(p)),
    k: pick(table, p => ['decoded.labelMap', 'decoded.selectiveIndexes',
      'decoded.mandatoryIndexes', 'decoded.mandatoryHash'].includes(p))
  };
}

/** Per-statement anonymity set for the target's mandatory N-Quads (probe h). */
export function mandatoryQuadTable(corpus) {
  const quadsOf = p => JSON.parse(p.payload.decoded.mandatoryNQuads);
  const subjects = [...new Set(corpus.map(p => p.subject))];
  const target = corpus.find(p => p.subject === TARGET);
  return quadsOf(target).map(q => ({
    quad: q.trim(),
    k: subjects.filter(s => corpus.some(p => p.subject === s && quadsOf(p).includes(q))).length,
    cohort: subjects.length
  }));
}

/** (c) for bbs-2023: the randomised part must differ every time. */
export function proofRandomisation(corpus) {
  const seen = new Set();
  let dupes = 0;
  for(const p of corpus) {
    const v = p.payload.decoded.bbsProof;
    if(seen.has(v)) {
      dupes++;
    }
    seen.add(v);
  }
  const pv = new Set(corpus.map(p => p.payload.proof.proofValue));
  return {total: corpus.length, distinctBbsProof: seen.size, distinctProofValue: pv.size,
    pass: dupes === 0};
}

/* ----------------------------- (d) collusion ------------------------------ */

/**
 * The issuer holds every signed base credential: BBS signature, BBS header,
 * the per-credential HMAC key, all claims. It also knows the pointer policy.
 */
export async function collusion({cohort, corpus, policy}) {
  const findings = [];
  const hay = new Map(corpus.map(p => [p.id, [...flatten(p.payload).values()].join('')]));

  // d1: do base-proof secrets reappear in any presentation?
  let hits = 0;
  for(const {signed} of cohort) {
    const b = decodeBaseProofValue(signed.proof.proofValue);
    for(const needle of [b.bbsSignature, b.hmacKey, b.bbsHeader].map(
      x => Buffer.from(x).toString('base64'))) {
      for(const h of hay.values()) {
        if(h.includes(needle)) {
          hits++;
        }
      }
    }
  }
  findings.push({check: 'd1 base-proof material (BBS signature, BBS header, HMAC key) reappears',
    result: hits ? `YES (${hits})` : 'no', leak: hits > 0});

  // d2: withheld claim values surfacing anyway.
  const withheld = [];
  for(const {dependent, credential} of cohort) {
    const full = flatten(credential);
    for(const p of corpus.filter(c => c.subject === dependent.id)) {
      const revealed = flatten(p.payload);
      for(const [path, value] of full) {
        if(revealed.has(path) || value.length < 8) {
          continue;
        }
        if(hay.get(p.id).includes(value)) {
          withheld.push(path);
        }
      }
    }
  }
  const w = [...new Set(withheld)];
  findings.push({check: 'd2 a withheld claim value appears in the payload anyway',
    result: w.length ? `YES: ${w.join(', ')}` : 'no', leak: w.length > 0});

  // d3: issuer re-derivation match. The issuer derives from every base credential
  // with the known selective pointers and compares everything that is NOT
  // freshly randomised: labelMap, both index lists, and the revealed document.
  const fingerprint = async (derived) => {
    const d = decodeDerivedProofValue(derived.proof.proofValue);
    // compare the document a verifier received -- drop the proof and our own
    // `decoded` view, which is not part of what was transmitted
    const {proof, decoded, ...doc} = derived;
    return JSON.stringify([[...d.labelMap.entries()], d.mandatoryIndexes,
      d.selectiveIndexes, doc]);
  };
  const issuerPrints = [];
  for(const {dependent, signed} of cohort) {
    const re = await derive({signed, policy, nonce: 'issuer-rederivation'});
    issuerPrints.push({dependent: dependent.id, print: await fingerprint(re)});
  }
  const sets = [];
  let correct = 0;
  for(const p of corpus.filter(c => c.subject === TARGET)) {
    const mine = await fingerprint(p.payload);
    const matches = issuerPrints.filter(x => x.print === mine);
    sets.push(matches.length);
    if(matches.length === 1 && matches[0].dependent === TARGET) {
      correct++;
    }
  }
  findings.push({
    check: 'd3 issuer re-derives every credential, matches non-random proof parts',
    result: `anonymity set ${sets.join('/')} of ${cohort.length}` +
      (correct ? ` -- ${correct}/${sets.length} presentations pinned to dep:Y by name` : ''),
    leak: Math.min(...sets) === 1
  });

  // d3b: which non-random part does the work? (labelMap + indexes only, document ignored)
  const proofOnly = async (derived) => {
    const d = decodeDerivedProofValue(derived.proof.proofValue);
    return JSON.stringify([[...d.labelMap.entries()], d.mandatoryIndexes, d.selectiveIndexes]);
  };
  const issuerProofPrints = [];
  for(const {dependent, signed} of cohort) {
    issuerProofPrints.push({dependent: dependent.id,
      print: await proofOnly(await derive({signed, policy, nonce: 'issuer-rederivation'}))});
  }
  const sets2 = [];
  for(const p of corpus.filter(c => c.subject === TARGET)) {
    const mine = await proofOnly(p.payload);
    sets2.push(issuerProofPrints.filter(x => x.print === mine).length);
  }
  findings.push({
    check: 'd3b same, using ONLY labelMap + mandatory/selective indexes (document ignored)',
    result: `anonymity set ${sets2.join('/')} of ${cohort.length}`,
    leak: Math.min(...sets2) === 1
  });

  return {findings, linked: findings.some(f => f.leak)};
}

/* ----------------------- revocation reachability -------------------------- */

export async function revocationReachability({cohort, policy}) {
  const target = cohort.find(c => c.dependent.id === TARGET);
  const status = target.credential.credentialStatus;
  const revoked = new Set(status ? [`${status.statusListCredential}#${status.statusListIndex}`] : []);
  const derived = await derive({signed: target.signed, policy, nonce: 'revocation-probe'});
  const r = await verify({derived, nonce: 'revocation-probe', revoked});
  return {
    statusEntryInCredential: !!status,
    statusEntryDisclosed: !!derived.credentialStatus,
    acceptedAfterRevocation: r.verified,
    note: !status ? 'no status entry exists (short-lived credential model)'
      : r.verified ? 'revoked credential still verifies: status entry not disclosed'
        : `rejected: ${r.error}`
  };
}

/* ---------------- Monte Carlo: entropy of the HMAC label shuffle ----------- */

/**
 * Issue the IDENTICAL claims K times. Only the per-credential HMAC key (drawn
 * fresh by the cryptosuite at every issuance) differs. Then derive with the same
 * pointers and count distinct (labelMap, selectiveIndexes, mandatoryIndexes).
 * Every distinct value is a tag the holder will repeat on every presentation of
 * that credential. N = blank nodes in the full credential, m = revealed ones;
 * theory predicts N!/(N-m)! equiprobable labelMaps.
 */
const CTX = ['https://www.w3.org/ns/credentials/v2', MANDATE_CONTEXT_URL];
const nested = {
  type: 'Guardian', guardianKey: 'k'.repeat(24),
  actsFor: {type: 'Dependent', dependentId: 'dep:Y'},
  mandate: {type: 'Mandate', scope: 'school_enrolment'}
};
const flat = {type: 'Guardian', guardianKey: 'k'.repeat(24), dependentId: 'dep:Y',
  scope: 'school_enrolment'};
const vcOf = (extra, subject) => ({
  '@context': CTX, type: ['VerifiableCredential', 'GuardianshipMandateCredential'],
  issuer: ISSUER, validUntil: '2026-09-30T23:59:59Z', ...extra, credentialSubject: subject
});

export const SWEEP_SHAPES = [
  {key: 'S1', label: 'nested subject + per-credential id (as in C-naive/C-minimal)',
    credential: vcOf({id: 'urn:uuid:00000000-0000-4000-a000-000000000001'}, nested),
    selectivePointers: ['/credentialSubject/mandate/scope']},
  {key: 'S2', label: 'nested subject, no credential id (as in C-hardened)',
    credential: vcOf({}, nested),
    selectivePointers: ['/credentialSubject/mandate/scope']},
  {key: 'S3', label: 'flat subject, no credential id',
    credential: vcOf({}, flat),
    selectivePointers: ['/credentialSubject/scope']},
  {key: 'S4', label: 'flat subject + epoch-scoped (cohort-wide) credential id',
    credential: vcOf({id: 'urn:kinship-caps:mandate-epoch:2026-Q3'}, flat),
    selectivePointers: ['/credentialSubject/scope']}
];

const factorialRatio = (n, m) => {
  let r = 1;
  for(let i = n - m + 1; i <= n; i++) {
    r *= i;
  }
  return r;
};

const binomial = (n, k) => {
  if(k > n) {
    return 0;
  }
  let r = 1;
  for(let i = 1; i <= k; i++) {
    r = r * (n - k + i) / i;
  }
  return Math.round(r);
};

async function blankNodeCount(credential) {
  const nq = await canonicalize(credential, {documentLoader});
  return new Set(nq.match(/_:c14n\d+/g) ?? []).size;
}

export async function labelShuffleSweep({trials = 30} = {}) {
  const rows = [];
  for(const s of SWEEP_SHAPES) {
    const policy = {mandatoryPointers: ['/issuer', '/validUntil'],
      selectivePointers: s.selectivePointers};
    const N = await blankNodeCount(s.credential);
    const tags = new Map();
    const labelMaps = new Set();
    const selIdx = new Set();
    let m = 0;
    let verified = 0;
    for(let t = 0; t < trials; t++) {
      const signed = await vc.issue({credential: structuredClone(s.credential),
        suite: await signSuite(policy.mandatoryPointers), documentLoader});
      const nonce = `sweep:${s.key}:${t}`;
      const derived = await derive({signed, policy, nonce});
      if(t < 3) {
        verified += (await verify({derived, nonce})).verified ? 1 : 0;
      }
      const d = decodeDerivedProofValue(derived.proof.proofValue);
      m = d.labelMap.size;
      labelMaps.add(JSON.stringify([...d.labelMap.entries()]));
      selIdx.add(JSON.stringify(d.selectiveIndexes));
      const tag = JSON.stringify([[...d.labelMap.entries()], d.selectiveIndexes, d.mandatoryIndexes]);
      tags.set(tag, (tags.get(tag) ?? 0) + 1);
    }
    const theory = factorialRatio(N, m);
    // Probability a given credential's tag is unique in a cohort of 6, if tags are
    // uniform over `theory` values -- the chance the target is singled out.
    const pUniqueIn6 = theory <= 1 ? 0 : Math.pow((theory - 1) / theory, 5);
    rows.push({
      key: s.key, label: s.label, N, m, trials,
      distinctTags: tags.size, distinctLabelMaps: labelMaps.size,
      distinctSelectiveIndexes: selIdx.size, theory, specBound: binomial(N, m),
      bits: Math.log2(Math.max(1, theory)),
      pUniqueIn6, sanityVerified: `${verified}/3`
    });
  }
  return rows;
}

/**
 * Ordering side channel: two credentials that differ ONLY in a hidden sibling
 * value of a multi-valued property. Disclose one value; do the selective
 * indexes reveal how the hidden value sorts? Uses the S4 shape (one blank node,
 * so labels are fixed and cannot mask the effect).
 */
export async function orderingProbe({trials = 3} = {}) {
  const results = [];
  for(const hidden of ['aaa_hidden_scope', 'zzz_hidden_scope']) {
    const subject = {...flat, scope: ['school_enrolment', hidden]};
    const credential = vcOf({id: 'urn:kinship-caps:mandate-epoch:2026-Q3'}, subject);
    const policy = {mandatoryPointers: ['/issuer'], selectivePointers: ['/credentialSubject/scope/0']};
    const seen = new Set();
    let revealed = null;
    for(let t = 0; t < trials; t++) {
      const signed = await vc.issue({credential: structuredClone(credential),
        suite: await signSuite(policy.mandatoryPointers), documentLoader});
      const derived = await derive({signed, policy, nonce: `order:${hidden}:${t}`});
      revealed = JSON.stringify(derived.credentialSubject);
      seen.add(JSON.stringify(decodeDerivedProofValue(derived.proof.proofValue).selectiveIndexes));
    }
    results.push({hidden, revealedSubject: revealed, selectiveIndexes: [...seen]});
  }
  const [a, b] = results;
  return {
    results,
    revealedDocumentsIdentical: a.revealedSubject === b.revealedSubject,
    indexesDiffer: JSON.stringify(a.selectiveIndexes) !== JSON.stringify(b.selectiveIndexes),
    deterministic: a.selectiveIndexes.length === 1 && b.selectiveIndexes.length === 1
  };
}

/**
 * Cohort-level Monte Carlo: how often does the target end up UNIQUELY
 * identifiable when everything a verifier sees except the fresh BBS proof is
 * combined? Re-issues the whole 6-credential cohort `reps` times (new HMAC keys
 * each time) and derives one presentation per credential. Every presentation of
 * a credential carries the same non-random parts (shown by the leak tables), so
 * "the target's tuple is unique in the cohort" == "all of the target's
 * presentations are exactly linkable".
 */
export async function cohortMonteCarlo({policy, reps = 30, issueCohort}) {
  let unique = 0;
  let uniqueProofPartsOnly = 0;
  for(let r = 0; r < reps; r++) {
    const cohort = await issueCohort(policy);
    const prints = [];
    for(const {dependent, signed} of cohort) {
      const derived = await derive({signed, policy, nonce: `mc:${r}:${dependent.id}`});
      const d = decodeDerivedProofValue(derived.proof.proofValue);
      const {proof, ...doc} = derived;
      const parts = [[...d.labelMap.entries()], d.mandatoryIndexes, d.selectiveIndexes];
      prints.push({id: dependent.id, all: JSON.stringify([parts, doc]),
        proofOnly: JSON.stringify(parts)});
    }
    const t = prints.find(p => p.id === TARGET);
    if(prints.filter(p => p.all === t.all).length === 1) {
      unique++;
    }
    if(prints.filter(p => p.proofOnly === t.proofOnly).length === 1) {
      uniqueProofPartsOnly++;
    }
  }
  return {reps, unique, pUnique: unique / reps,
    uniqueProofPartsOnly, pUniqueProofPartsOnly: uniqueProofPartsOnly / reps};
}

/* ---------------------- (e) cross-hop, cryptosuite-only -------------------- */

/**
 * The raw run found (e) PASS for hardened x B-unlinkable-stable: the guardian's
 * own presentations and the parent-mandate proofs inside the sub-carer's chain
 * shared no value. Re-test that with bbs-2023.
 *
 * Hop 1: the guardian discloses the scope only.
 * Hop 2: the parent proof inside a chain also discloses guardianKey (so the
 *        verifier can bind the hops, as in B-unlinkable-stable).
 * Different pointer sets -> different revealed documents and different
 * labelMaps. The question is whether anything still matches across them.
 */
export async function crossHopProbe({policy, issueCohort, reps = 20}) {
  const hop2Pointers = policy.docShape === 'cohort-flat'
    ? ['/credentialSubject/scope', '/credentialSubject/guardianKey']
    : ['/credentialSubject/mandate/scope', '/credentialSubject/guardianKey'];
  const hop2Policy = {...policy, selectivePointers: hop2Pointers};

  const corpora = async (cohort, tag) => {
    const hop1 = [];
    const hop2 = [];
    for(const {dependent, signed} of cohort) {
      for(let i = 0; i < 2; i++) {
        const a = await derive({signed, policy, nonce: `${tag}:h1:${dependent.id}:${i}`});
        hop1.push({id: `${dependent.id}#h1-${i}`, subject: dependent.id, verifierId: `rp:${i}`,
          payload: {...a, decoded: await adversaryView(a)}});
        const b = await derive({signed, policy: hop2Policy, nonce: `${tag}:h2:${dependent.id}:${i}`});
        hop2.push({id: `${dependent.id}#h2-${i}`, subject: dependent.id, verifierId: `rp:${i + 2}`,
          payload: {parent: {...b, decoded: await adversaryView(b)}}});
      }
    }
    return {hop1, hop2};
  };

  // one detailed run
  const {hop1, hop2} = await corpora(await issueCohort(policy), 'x0');
  const detail = crossHopAnalysis({hop1, hop2, target: TARGET, label: policy.label});

  // Monte Carlo: does the JOINT rank of the blank nodes both hops reveal
  // identify the target? (Ranks are per credential, so this is stable per
  // credential and comparable across hops.)
  let unique = 0;
  for(let r = 0; r < reps; r++) {
    const cohort = await issueCohort(policy);
    const joint = [];
    for(const {dependent, signed} of cohort) {
      const a = await derive({signed, policy, nonce: `mc-e:${r}:${dependent.id}:1`});
      const b = await derive({signed, policy: hop2Policy, nonce: `mc-e:${r}:${dependent.id}:2`});
      const ra = (await adversaryView(a)).bnodeRank;
      const rb = (await adversaryView(b)).bnodeRank;
      const shared = Object.keys(ra).filter(k => k in rb).sort();
      const agree = shared.every(k => ra[k] === rb[k]);
      joint.push({id: dependent.id, key: shared.map(k => ra[k]).join('|'), agree});
    }
    const t = joint.find(j => j.id === TARGET);
    if(t.agree && joint.filter(j => j.key === t.key).length === 1) {
      unique++;
    }
  }
  return {hop2Pointers, detail, reps, unique, pUnique: unique / reps};
}
