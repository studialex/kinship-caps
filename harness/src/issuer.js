/**
 * Mock issuer of guardianship mandate attestations + the population ("cohort")
 * of credentials that the linkability harness measures anonymity sets against.
 *
 * The cohort matters. A value that is constant across all of dependent Y's
 * presentations is only a LEAK if it also *singles Y out*. The issuer key, the
 * scheme type string and a bucketed expiry are all constant too, but every other
 * dependent shows the same value, so they narrow nothing. Without decoys a naive
 * checker flags those as leaks and misses the point.
 */
import {DeterministicRng} from './rng.js';
import {encodeMessages, MANDATE_ATTRS} from './schema.js';
import {b64, generateKeyPair, sign, utf8} from './bbs.js';

export const ISSUER_KEY_ID = 'did:example:mandate-registry#bbs-2026Q3';
export const EPOCH = '2026-Q3';
/** Cohort-wide bucketed expiry: every mandate in this epoch shares it. */
export const EPOCH_EXPIRY = '2026-09-30';

/** The BBS `header` a given profile binds into the signature. */
export function headerFor(headerMode, credentialId) {
  if(headerMode === 'per-credential') {
    // A perfectly ordinary-looking choice: domain-separate per credential.
    return utf8(`open-core/mandate/v1|issuer=${ISSUER_KEY_ID}|cred=${credentialId}`);
  }
  if(headerMode === 'cohort') {
    // Domain separation only down to the issuance epoch.
    return utf8(`open-core/mandate/v1|issuer=${ISSUER_KEY_ID}|epoch=${EPOCH}`);
  }
  throw new Error(`unknown headerMode ${headerMode}`);
}

export class Issuer {
  constructor(rng = new DeterministicRng('issuer')) {
    this.rng = rng;
    this.keyPair = null;
    /** statusListIndex -> revoked? */
    this.statusList = new Map();
    /** everything the issuer retains -- used by the collusion simulation (d). */
    this.records = [];
  }

  async init() {
    this.keyPair = await generateKeyPair(new DeterministicRng('issuer-key').bytes(32));
    return this;
  }

  /**
   * Issue one mandate. Signs TWICE -- once under a per-credential header and once
   * under a cohort header -- so both single-hop profiles can be exercised against
   * the identical claim set. (A real deployment picks one; carrying both here
   * keeps the comparison honest: nothing differs except the composition.)
   */
  async issueMandate({dependentId, guardianKeyB64, scope, exactExpiry}) {
    const credentialId = this.rng.uuid();
    const statusIndex = this.statusList.size;
    this.statusList.set(statusIndex, false);
    const revocationHandle = `https://status.example/mandates/${EPOCH}#${statusIndex}`;

    const claimsPerCredential = {
      type: 'GuardianshipMandate',
      dependent_id: dependentId,
      mandate_scope: scope,
      // per-credential profile keeps the true, high-entropy expiry date
      valid_until: exactExpiry,
      guardian_key: guardianKeyB64,
      issuer_key_id: ISSUER_KEY_ID,
      revocation_handle: revocationHandle,
      credential_id: credentialId
    };
    // hardened profile buckets the expiry to the cohort-wide epoch end
    const claimsCohort = {...claimsPerCredential, valid_until: EPOCH_EXPIRY};

    const variants = {};
    for(const [mode, claims] of [
      ['per-credential', claimsPerCredential], ['cohort', claimsCohort]
    ]) {
      const header = headerFor(mode, credentialId);
      const messages = encodeMessages(MANDATE_ATTRS, claims);
      const signature = await sign({
        secretKey: this.keyPair.secretKey,
        publicKey: this.keyPair.publicKey,
        header, messages
      });
      variants[mode] = {header, messages, signature, claims};
    }

    const record = {
      credentialId, statusIndex, revocationHandle, dependentId,
      guardianKeyB64, scope, variants,
      issuerPublicKey: this.keyPair.publicKey
    };
    this.records.push(record);
    return record;
  }

  revokeByStatusIndex(statusIndex) {
    this.statusList.set(statusIndex, true);
  }

  isRevokedHandle(handle) {
    const m = /#(\d+)$/.exec(handle ?? '');
    if(!m) {
      return null; // unknown / not checkable
    }
    return this.statusList.get(Number(m[1])) === true;
  }

  get publicKeyB64() {
    return b64(this.keyPair.publicKey);
  }
}
