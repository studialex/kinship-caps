/**
 * The guardianship mandate as a real VCDM 2.0 JSON-LD Verifiable Credential, and
 * the mandatoryPointers policies under test.
 *
 * Same attributes as the raw-scheme harness (dependent identifier, scope,
 * validity, issuer, status, guardian key, credential id), expressed as a VC.
 */
import {ISSUER, MANDATE_CONTEXT_URL} from './env.js';
import {DeterministicRng} from '../rng.js';

export const EPOCH_EXPIRY = '2026-09-30T23:59:59Z';
export const STATUS_LIST = 'https://status.example/mandates/2026-Q3';
export const EPOCH_CREDENTIAL_ID = 'urn:kinship-caps:mandate-epoch:2026-Q3';
/** Verifier clock, pinned so the run is reproducible whatever today's date is. */
export const NOW = '2026-08-01T00:00:00Z';

/**
 * Two document shapes, mirroring the raw run:
 *  per-credential : credential `id`, exact expiry, a per-credential status entry
 *  cohort         : no credential `id`, expiry bucketed to the epoch, no status entry
 * The credentialSubject nesting is identical in both.
 */
export function buildCredential({dependent, guardianKeyB64, statusIndex, docShape, rng}) {
  const base = {
    '@context': ['https://www.w3.org/ns/credentials/v2', MANDATE_CONTEXT_URL],
    type: ['VerifiableCredential', 'GuardianshipMandateCredential'],
    issuer: ISSUER,
    validFrom: '2026-07-01T00:00:00Z',
    credentialSubject: {
      type: 'Guardian',
      guardianKey: guardianKeyB64,
      actsFor: {type: 'Dependent', dependentId: dependent.id},
      mandate: {type: 'Mandate', scope: dependent.scope}
    }
  };
  if(docShape === 'per-credential') {
    return {
      ...base,
      id: (rng ?? new DeterministicRng(`vc-id:${dependent.id}`)).uuid(),
      validUntil: `${dependent.expiry}T23:59:59Z`,
      credentialStatus: {
        id: `${STATUS_LIST}#${statusIndex}`,
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: String(statusIndex),
        statusListCredential: STATUS_LIST
      }
    };
  }
  if(docShape === 'cohort') {
    return {...base, validUntil: EPOCH_EXPIRY};
  }
  if(docShape === 'cohort-flat') {
    // Mitigation candidate, derived from probe (k): exactly ONE blank node in the
    // whole credential. The subject is flattened (no nested objects), and the
    // credential carries an epoch-scoped id shared by the whole cohort, so the
    // root is an IRI rather than a second blank node. See FINDINGS for the cost.
    return {
      ...base,
      id: EPOCH_CREDENTIAL_ID,
      validUntil: EPOCH_EXPIRY,
      credentialSubject: {
        type: 'Guardian',
        guardianKey: guardianKeyB64,
        dependentId: dependent.id,
        scope: dependent.scope
      }
    };
  }
  throw new Error(`unknown docShape ${docShape}`);
}

/**
 * mandatoryPointers policies (issuer side) + the holder's selectivePointers.
 * The holder always discloses the scope and nothing else it can avoid.
 */
export const POLICIES = {
  naive: {
    label: 'C-naive (mandatory: /issuer, /validUntil, /credentialStatus)',
    docShape: 'per-credential',
    mandatoryPointers: ['/issuer', '/validUntil', '/credentialStatus'],
    selectivePointers: ['/credentialSubject/mandate/scope']
  },
  minimal: {
    // bbs-2023 itself requires no mandatory pointer. VCDM verification needs
    // `issuer`, so the holder discloses it selectively instead.
    label: 'C-minimal (mandatory: none -- the cryptosuite minimum)',
    docShape: 'per-credential',
    mandatoryPointers: [],
    selectivePointers: ['/issuer', '/credentialSubject/mandate/scope']
  },
  hardened: {
    // Only what verification strictly needs, and only cohort-wide values:
    // the issuer, plus an expiry bucketed to the issuance epoch. No credential
    // id and no per-credential status entry exist in the document at all.
    label: 'C-hardened (mandatory: /issuer + epoch-bucketed /validUntil; no id, no status)',
    docShape: 'cohort',
    mandatoryPointers: ['/issuer', '/validUntil'],
    selectivePointers: ['/credentialSubject/mandate/scope']
  },
  hardenedFlat: {
    // NOT one of the three policies the brief asked for: a mitigation candidate
    // added after probe (k) found the blank-node shuffle leaking in C-hardened.
    label: 'C-hardened+flat (mitigation candidate: 1 blank node, epoch-scoped id)',
    docShape: 'cohort-flat',
    mandatoryPointers: ['/issuer', '/validUntil'],
    selectivePointers: ['/credentialSubject/scope'],
    mitigationCandidate: true
  }
};
