/**
 * Credential schemas + presentation profiles.
 *
 * A BBS signature signs an ORDERED list of messages. We fix that order here and
 * encode each attribute as UTF-8 `key=value`. The index of an attribute is
 * therefore stable and public -- which itself matters for the harness: the
 * *set of disclosed indexes* is visible to a verifier.
 */
import {utf8} from './bbs.js';

/** Attribute order of the guardianship mandate (issuer -> guardian). */
export const MANDATE_ATTRS = [
  'type',              // 0 constant for the whole scheme
  'dependent_id',      // 1 pseudonym for dependent Y -- the thing we must not correlate
  'mandate_scope',     // 2 e.g. "school_enrolment"
  'valid_until',       // 3 expiry
  'guardian_key',      // 4 base64 BBS public key of the guardian (holder binding / delegation anchor)
  'issuer_key_id',     // 5 e.g. "did:example:issuer#bbs-1"
  'revocation_handle', // 6 status-list entry for THIS credential
  'credential_id'      // 7 urn:uuid of THIS credential
];

/** Attribute order of the attenuated sub-mandate (guardian -> temporary sub-carer). */
export const SUBMANDATE_ATTRS = [
  'type',                 // 0
  'dependent_id',         // 1 same dependent Y
  'sub_scope',            // 2 narrowed, e.g. "school_pickup"
  'sub_valid_until',      // 3 shorter validity
  'subcarer_key',         // 4
  'delegator_key',        // 5 the guardian's key -- what binds hop 2 to hop 1
  'parent_credential_id', // 6 pointer to the parent mandate
  'parent_revocation_handle' // 7 needed for cascading revocation checks
];

/**
 * Scope lattice. `subsumes(a, b)` == "authority a includes authority b".
 * Used by the verifier for the functional attenuation check (f).
 */
export const SCOPE_LATTICE = {
  school_enrolment: ['school_enrolment', 'school_pickup', 'school_records_read'],
  medical_consent: ['medical_consent', 'medical_records_read'],
  school_pickup: ['school_pickup'],
  school_records_read: ['school_records_read'],
  medical_records_read: ['medical_records_read']
};

export function subsumes(parentScope, childScope) {
  return (SCOPE_LATTICE[parentScope] ?? []).includes(childScope);
}

/** Encode a claim object into the ordered BBS message array. */
export function encodeMessages(attrOrder, claims) {
  return attrOrder.map(k => {
    if(!(k in claims)) {
      throw new Error(`missing claim "${k}"`);
    }
    return utf8(`${k}=${claims[k]}`);
  });
}

export function decodeMessage(u8) {
  return Buffer.from(u8).toString('utf8');
}

export const idxOf = (attrOrder, names) => names.map(n => {
  const i = attrOrder.indexOf(n);
  if(i < 0) {
    throw new Error(`unknown attribute "${n}"`);
  }
  return i;
}).sort((a, b) => a - b);

/* -------------------------------------------------------------------------- */
/* Presentation profiles                                                       */
/* -------------------------------------------------------------------------- */
/**
 * Each profile is a candidate COMPOSITION of the standard primitives -- the
 * thing actually under test. The BBS maths is identical in all of them; what
 * differs is what our protocol wraps around it.
 *
 * `disclose`      : which mandate attributes go into the BBS derived proof.
 * `headerMode`    : what goes into the BBS `header`. The header is bound at
 *                   signing time and MUST be reproduced verbatim by the verifier,
 *                   so ANY per-credential content in it is transmitted, in clear,
 *                   to every verifier, forever. This is the single most important
 *                   composition choice in the whole harness.
 * `envelope`      : extra protocol fields shipped alongside the proof.
 */
export const SINGLE_HOP_PROFILES = {
  /**
   * v0 "strawman": the composition you get if you translate a normal VC
   * (credentialStatus, credential id, issuer kid, holder DID) straight onto BBS
   * and assume the BBS proof alone delivers unlinkability.
   */
  naive: {
    label: 'A-naive (VC-shaped envelope around a BBS proof)',
    disclose: ['type', 'mandate_scope', 'valid_until', 'issuer_key_id',
      'revocation_handle', 'credential_id'],
    headerMode: 'per-credential',
    envelope: {credentialId: true, credentialStatus: true, holderKeyId: true, issuerKeyId: true}
  },
  /**
   * v1 "hardened": everything per-credential is removed from both the header and
   * the envelope; `valid_until` is bucketed to a cohort-wide issuance epoch so it
   * cannot act as a quasi-identifier; revocation degrades to short-lived
   * credentials (no per-credential status handle is shipped).
   */
  hardened: {
    label: 'A-hardened (cohort-wide header, no status handle, bucketed expiry)',
    disclose: ['type', 'mandate_scope', 'valid_until'],
    headerMode: 'cohort',
    envelope: {credentialId: false, credentialStatus: false, holderKeyId: false, issuerKeyId: false}
  }
};

export const CHAIN_PROFILES = {
  /**
   * B-auditable: the sub-carer shows a proof of the parent mandate and a proof of
   * the sub-mandate. Both hops disclose enough for the verifier to (i) bind hop 2
   * to hop 1 via the guardian's key and (ii) check the parent's revocation status.
   */
  auditable: {
    label: 'B-auditable (delegation pointer + parent status disclosed)',
    parentDisclose: ['type', 'mandate_scope', 'valid_until', 'guardian_key',
      'revocation_handle', 'credential_id'],
    subDisclose: ['type', 'sub_scope', 'sub_valid_until', 'subcarer_key',
      'delegator_key', 'parent_credential_id', 'parent_revocation_handle'],
    headerMode: 'per-credential',
    bindHops: true,
    checkParentRevocation: true,
    freshDelegatorKey: false
  },
  /**
   * B-unlinkable-stable: strip the parent credential id and the parent status
   * handle, but keep disclosing the guardian's key so the verifier can still bind
   * the two hops and therefore still check attenuation.
   */
  unlinkableStable: {
    label: 'B-unlinkable-stable (hop binding kept, parent ids/status removed)',
    parentDisclose: ['type', 'mandate_scope', 'valid_until', 'guardian_key'],
    subDisclose: ['type', 'sub_scope', 'sub_valid_until', 'delegator_key'],
    headerMode: 'cohort',
    bindHops: true,
    checkParentRevocation: false,
    freshDelegatorKey: false
  },
  /**
   * B-unlinkable-fresh: also hide the guardian's key, re-issuing the sub-mandate
   * under a freshly generated delegator key for every presentation. Nothing
   * per-subject survives -- and, as attack (f) shows, nothing binds the hops either.
   */
  unlinkableFresh: {
    label: 'B-unlinkable-fresh (hop binding removed, fresh delegator key per presentation)',
    parentDisclose: ['type', 'mandate_scope', 'valid_until'],
    subDisclose: ['type', 'sub_scope', 'sub_valid_until'],
    headerMode: 'cohort',
    bindHops: false,
    checkParentRevocation: false,
    freshDelegatorKey: true
  }
};
