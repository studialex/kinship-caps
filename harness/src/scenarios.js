/**
 * Scenario drivers: build the presentation corpora, sanity-check that every
 * presentation actually verifies (a harness that measures rejected garbage
 * measures nothing), then hand the corpora to the linkability harness.
 */
import {CHAIN_PROFILES, SINGLE_HOP_PROFILES} from './schema.js';
import {presentChain, presentMandate} from './holder.js';
import {analyse} from './harness.js';
import {crossHopAnalysis} from './crosshop.js';
import {chainPlanFor, makeSubCarer, planFor, SUB_SCOPE_FOR, TARGET} from './world.js';

const verifierById = (world, id) => world.verifiers.find(v => v.id === id);

/* --------------------------- Scenario A: single hop ----------------------- */

export async function buildSingleHopCorpus(world, profile) {
  const corpus = [];
  for(const subject of world.subjects) {
    const isTarget = subject.id === TARGET;
    let n = 0;
    for(const vId of planFor(subject.id, isTarget)) {
      const verifier = verifierById(world, vId);
      const nonce = verifier.newNonce(world.rng);
      const payload = await presentMandate({
        record: subject.record, profile, verifier: {id: vId, nonce}
      });
      corpus.push({
        id: `${subject.id}#${n++}`, subject: subject.id, verifierId: vId, payload
      });
    }
  }
  return corpus;
}

export async function runScenarioA(world) {
  const results = [];
  for(const [key, profile] of Object.entries(SINGLE_HOP_PROFILES)) {
    const corpus = await buildSingleHopCorpus(world, profile);

    // sanity: all presentations must actually verify
    const accepted = [];
    for(const p of corpus) {
      const subject = world.subjects.find(s => s.id === p.subject);
      const r = await verifierById(world, p.verifierId)
        .verifySingle(p.payload, {requiredScope: subject.scope});
      accepted.push(r.ok);
    }

    const analysis = await analyse({
      name: profile.label, corpus, target: TARGET,
      issuerRecords: world.issuer.records, headerMode: profile.headerMode
    });
    results.push({
      key, profile, corpus, analysis,
      functional: {
        presentations: corpus.length,
        accepted: accepted.filter(Boolean).length
      }
    });
  }
  return results;
}

/* --------------------------- Scenario B: two hops ------------------------- */

export async function buildChainCorpus(world, profile) {
  const corpus = [];
  for(const subject of world.subjects) {
    const isTarget = subject.id === TARGET;
    let n = 0;
    for(const vId of chainPlanFor(isTarget)) {
      // The `unlinkableFresh` profile re-issues the sub-mandate under a throwaway
      // delegator key for every single presentation -- the only way to stop that
      // key acting as a cross-presentation correlator.
      const subCarer = await makeSubCarer({
        subject, profile,
        freshSeed: profile.freshDelegatorKey ? `fresh:${subject.id}:${n}` : null
      });
      const verifier = verifierById(world, vId);
      const nonce = verifier.newNonce(world.rng);
      const payload = await presentChain({
        guardian: subject.guardian, subCarer, profile, verifier: {id: vId, nonce}
      });
      corpus.push({
        id: `${subject.id}~chain#${n++}`, subject: subject.id, verifierId: vId, payload
      });
    }
  }
  return corpus;
}

export async function runScenarioB(world) {
  const results = [];
  for(const [key, profile] of Object.entries(CHAIN_PROFILES)) {
    const corpus = await buildChainCorpus(world, profile);

    const accepted = [];
    for(const p of corpus) {
      const subject = world.subjects.find(s => s.id === p.subject);
      const r = await verifierById(world, p.verifierId).verifyChain(p.payload, {
        profile, requiredScope: SUB_SCOPE_FOR(subject.scope)
      });
      accepted.push(r);
    }

    const analysis = await analyse({
      name: profile.label, corpus, target: TARGET,
      issuerRecords: world.issuer.records, headerMode: profile.headerMode
    });
    results.push({
      key, profile, corpus, analysis,
      functional: {
        presentations: corpus.length,
        accepted: accepted.filter(r => r.ok).length,
        attenuationCheckable: accepted.filter(r => r.attenuationChecked).length,
        parentRevocationCheckable: accepted.filter(r => r.parentRevocationChecked).length,
        firstRejection: accepted.find(r => !r.ok)?.reasons?.[0] ?? null
      }
    });
  }
  return results;
}

/* ------------------------ (e) cross-hop unlinkability --------------------- */

/**
 * Pair each chain profile with the single-hop profile that shares its header
 * strategy -- i.e. what a deployment would actually ship together.
 */
export const CROSS_HOP_PAIRS = [
  {hop1: 'naive', hop2: 'auditable'},
  {hop1: 'hardened', hop2: 'unlinkableStable'},
  {hop1: 'hardened', hop2: 'unlinkableFresh'}
];

export function runCrossHop({scenarioA, scenarioB}) {
  return CROSS_HOP_PAIRS.map(({hop1, hop2}) => {
    const a = scenarioA.find(r => r.key === hop1);
    const b = scenarioB.find(r => r.key === hop2);
    return crossHopAnalysis({
      hop1: a.corpus, hop2: b.corpus, target: TARGET,
      label: `${a.profile.label}  x  ${b.profile.label}`
    });
  });
}
