/**
 * Scenario A (single hop) against the full bbs-2023 cryptosuite.
 *
 * Same cohort as the raw-scheme run (6 dependents, 4 relying parties), same
 * presentation plan (target: 6 presentations to 4 RPs incl. 2 repeat visits;
 * decoys: 3 each). Every presentation is a genuine bbs-2023 derived credential
 * produced by @digitalbazaar/vc `derive`, and every one is verified by
 * @digitalbazaar/vc `verifyCredential` before it is analysed.
 */
import * as vc from '@digitalbazaar/vc';
import {DEPENDENTS, planFor, TARGET} from '../world.js';
import {DeterministicRng} from '../rng.js';
import {documentLoader, discloseSuite, signSuite, verifySuite} from './env.js';
import {buildCredential, NOW} from './mandate.js';
import {adversaryView} from './decode.js';

const te = new TextEncoder();

/** Relying-party status check. Only reachable if the status entry was disclosed. */
export function makeStatusChecker(revoked) {
  return async ({credential}) => {
    const s = credential.credentialStatus;
    if(!s) {
      return {verified: true};
    }
    const entries = Array.isArray(s) ? s : [s];
    const hit = entries.some(e => revoked.has(`${e.statusListCredential}#${e.statusListIndex}`));
    return hit ? {verified: false, error: new Error('credential is revoked')} : {verified: true};
  };
}

export async function issueCohort(policy) {
  const rng = new DeterministicRng(`cryptosuite-cohort:${policy.docShape}`);
  const out = [];
  let statusIndex = 0;
  for(const dependent of DEPENDENTS) {
    const credential = buildCredential({
      dependent,
      guardianKeyB64: Buffer.from(new DeterministicRng(`gk:${dependent.id}`).bytes(96)).toString('base64'),
      statusIndex: statusIndex++,
      docShape: policy.docShape,
      rng
    });
    const signed = await vc.issue({
      credential, suite: await signSuite(policy.mandatoryPointers), documentLoader
    });
    out.push({dependent, credential, signed});
  }
  return out;
}

export async function derive({signed, policy, nonce}) {
  return vc.derive({
    verifiableCredential: signed,
    suite: discloseSuite({
      selectivePointers: policy.selectivePointers, presentationHeader: te.encode(nonce)
    }),
    documentLoader
  });
}

export async function verify({derived, nonce, revoked = new Set()}) {
  const r = await vc.verifyCredential({
    credential: derived,
    suite: verifySuite({expectedPresentationHeader: te.encode(nonce)}),
    documentLoader, now: NOW, checkStatus: makeStatusChecker(revoked)
  });
  let error = null;
  if(!r.verified) {
    error = r.statusResult && r.statusResult.verified === false
      ? 'status check failed: credential is revoked'
      : (r.error?.errors?.[0]?.message ?? r.error?.message ??
        r.results?.[0]?.error?.message ?? 'proof verification failed');
  }
  return {verified: r.verified, error};
}

export async function buildCorpus(policy) {
  const cohort = await issueCohort(policy);
  const rng = new DeterministicRng(`cryptosuite-nonces:${policy.label}`);
  const corpus = [];
  const verification = [];
  for(const {dependent, signed} of cohort) {
    const isTarget = dependent.id === TARGET;
    let n = 0;
    for(const vId of planFor(dependent.id, isTarget)) {
      const nonce = `nonce:${vId}:${rng.hex(12)}`;
      const derived = await derive({signed, policy, nonce});
      verification.push(await verify({derived, nonce}));
      // The payload is the derived credential exactly as a verifier receives it,
      // plus the fields any verifier obtains by parsing proof.proofValue.
      const payload = {...structuredClone(derived), decoded: await adversaryView(derived)};
      corpus.push({id: `${dependent.id}#${n++}`, subject: dependent.id, verifierId: vId, payload});
    }
  }
  return {cohort, corpus, verification};
}
