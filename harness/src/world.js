/**
 * Builds the test world: one issuer, a cohort of dependents (Y + decoys), a
 * guardian per dependent, a sub-carer per dependent, and a set of relying parties.
 *
 * The decoy cohort is not decoration -- see harness.js: without it, "constant"
 * cannot be distinguished from "identifying".
 */
import {DeterministicRng} from './rng.js';
import {Issuer} from './issuer.js';
import {Guardian, makeKeyPair, SubCarer} from './holder.js';
import {Verifier} from './verifier.js';
import {b64} from './bbs.js';

export const TARGET = 'dep:Y';

/** Y plus five decoys. Scopes deliberately overlap so the cohort is realistic. */
export const DEPENDENTS = [
  {id: 'dep:Y', scope: 'school_enrolment', expiry: '2026-09-14'},
  {id: 'dep:D1', scope: 'school_enrolment', expiry: '2026-09-02'},
  {id: 'dep:D2', scope: 'school_enrolment', expiry: '2026-08-27'},
  {id: 'dep:D3', scope: 'medical_consent', expiry: '2026-09-21'},
  {id: 'dep:D4', scope: 'school_enrolment', expiry: '2026-09-08'},
  {id: 'dep:D5', scope: 'medical_consent', expiry: '2026-08-30'}
];

/** Narrowed authority handed to the temporary sub-carer. */
const SUB_SCOPE_FOR = scope =>
  scope === 'medical_consent' ? 'medical_records_read' : 'school_pickup';
const SUB_EXPIRY = '2026-08-12';

export async function buildWorld() {
  const rng = new DeterministicRng('world');
  const issuer = await new Issuer(new DeterministicRng('issuer-ids')).init();

  const subjects = [];
  for(const d of DEPENDENTS) {
    const guardianKeyPair = await makeKeyPair(`guardian:${d.id}`);
    const subCarerKeyPair = await makeKeyPair(`subcarer:${d.id}`);
    const record = await issuer.issueMandate({
      dependentId: d.id,
      guardianKeyB64: b64(guardianKeyPair.publicKey),
      scope: d.scope,
      exactExpiry: d.expiry
    });
    subjects.push({
      ...d, record, guardianKeyPair, subCarerKeyPair,
      guardian: new Guardian({record, keyPair: guardianKeyPair, rng})
    });
  }

  const verifiers = ['rp:school', 'rp:clinic', 'rp:sportsclub', 'rp:library']
    .map(id => new Verifier({
      id, trustedIssuerPublicKey: issuer.keyPair.publicKey, statusChecker: issuer
    }));

  return {rng, issuer, subjects, verifiers, target: TARGET};
}

/**
 * Presentation plan. Y visits four different RPs and revisits two of them --
 * the "twice to the same verifier" leg of the brief. Decoys visit three RPs each.
 */
export function planFor(subjectId, isTarget) {
  return isTarget
    ? ['rp:school', 'rp:clinic', 'rp:sportsclub', 'rp:library', 'rp:school', 'rp:clinic']
    : ['rp:school', 'rp:clinic', 'rp:library'];
}

export function chainPlanFor(isTarget) {
  return isTarget
    ? ['rp:school', 'rp:sportsclub', 'rp:library', 'rp:school', 'rp:clinic', 'rp:sportsclub']
    : ['rp:school', 'rp:sportsclub'];
}

/** Attenuated sub-mandate for a subject, under a given chain profile. */
export async function makeSubCarer({subject, profile, freshSeed = null}) {
  const signerKeyPair = freshSeed
    ? await makeKeyPair(freshSeed) : subject.guardianKeyPair;
  const subMandate = await subject.guardian.issueSubMandate({
    subScope: SUB_SCOPE_FOR(subject.scope),
    subValidUntil: SUB_EXPIRY,
    subCarerKeyB64: b64(subject.subCarerKeyPair.publicKey),
    headerMode: profile.headerMode,
    signerKeyPair
  });
  return new SubCarer({keyPair: subject.subCarerKeyPair, subMandate});
}

export {SUB_SCOPE_FOR, SUB_EXPIRY};
