/**
 * Relying party.
 *
 * A verifier here is deliberately strict about the things a real RP can check
 * cheaply (proof validity, nonce freshness, scope policy, status when it is
 * given a handle) and deliberately honest about the things it CANNOT check when
 * the composition hides them (which delegator key is authorised, whether the
 * parent mandate is still valid). Those gaps are the point of Scenario B.
 */
import {unb64, utf8, verifyProof} from './bbs.js';
import {subsumes} from './schema.js';

const claim = (disclosedMessages, key) => {
  for(const v of Object.values(disclosedMessages)) {
    if(v.startsWith(`${key}=`)) {
      return v.slice(key.length + 1);
    }
  }
  return undefined;
};

const indexes = s => s.split(',').filter(x => x !== '').map(Number);
const messagesOf = (disclosedMessages, idxs) =>
  idxs.map(i => utf8(disclosedMessages[String(i)]));

export class Verifier {
  /**
   * @param id          relying-party identifier
   * @param trustedIssuerPublicKey  out-of-band trust anchor (NOT taken from the payload)
   * @param statusChecker  optional {isRevokedHandle(handle) -> bool|null}
   */
  constructor({id, trustedIssuerPublicKey, statusChecker = null}) {
    this.id = id;
    this.trustedIssuerPublicKey = trustedIssuerPublicKey;
    this.statusChecker = statusChecker;
    this.issuedNonces = new Set();
    this.seenNonces = new Set();
    this.log = [];
  }

  /** Fresh nonce per presentation request. */
  newNonce(rng) {
    const n = `nonce:${this.id}:${rng.hex(12)}`;
    this.issuedNonces.add(n);
    return n;
  }

  #checkNonce(phB64, reasons) {
    const ph = Buffer.from(phB64, 'base64').toString('utf8');
    if(!this.issuedNonces.has(ph)) {
      reasons.push('presentation-header is not a nonce this verifier issued');
      return false;
    }
    if(this.seenNonces.has(ph)) {
      reasons.push('nonce replay');
      return false;
    }
    this.seenNonces.add(ph);
    return true;
  }

  /* ---------------- single hop ---------------- */

  async verifySingle(payload, {requiredScope, checkNonce = true} = {}) {
    const reasons = [];
    const {bbs} = payload;

    if(bbs.issuerPublicKey !== Buffer.from(this.trustedIssuerPublicKey).toString('base64')) {
      reasons.push('issuer public key is not the trusted anchor');
      return {ok: false, reasons};
    }
    if(checkNonce && !this.#checkNonce(bbs.presentationHeader, reasons)) {
      return {ok: false, reasons};
    }

    const idxs = indexes(bbs.disclosedIndexes);
    const ok = await verifyProof({
      publicKey: this.trustedIssuerPublicKey,
      proof: unb64(bbs.proof),
      header: unb64(bbs.header),
      presentationHeader: unb64(bbs.presentationHeader),
      disclosedMessages: messagesOf(bbs.disclosedMessages, idxs),
      disclosedMessageIndexes: idxs
    });
    if(!ok) {
      reasons.push('BBS derived proof failed to verify');
      return {ok: false, reasons};
    }

    const scope = claim(bbs.disclosedMessages, 'mandate_scope');
    if(requiredScope && scope !== requiredScope) {
      reasons.push(`scope "${scope}" != required "${requiredScope}"`);
      return {ok: false, reasons};
    }

    // Revocation is only checkable if the composition shipped a handle.
    const handle = claim(bbs.disclosedMessages, 'revocation_handle') ??
      (payload.envelope?.credentialStatus
        ? `${payload.envelope.credentialStatus.statusListCredential}#${payload.envelope.credentialStatus.statusListIndex}`
        : undefined);
    let revocationChecked = false;
    if(handle && this.statusChecker) {
      const revoked = this.statusChecker.isRevokedHandle(handle);
      if(revoked === true) {
        reasons.push('mandate is revoked');
        return {ok: false, reasons, revocationChecked: true};
      }
      revocationChecked = revoked !== null;
    }
    return {ok: true, reasons, revocationChecked};
  }

  /* ---------------- two hops ---------------- */

  async verifyChain(payload, {profile, requiredScope, checkNonce = true} = {}) {
    const reasons = [];
    const {parent, sub} = payload;

    if(parent.issuerPublicKey !== Buffer.from(this.trustedIssuerPublicKey).toString('base64')) {
      reasons.push('issuer public key is not the trusted anchor');
      return {ok: false, reasons};
    }
    if(checkNonce && !this.#checkNonce(parent.presentationHeader, reasons)) {
      return {ok: false, reasons};
    }
    if(sub.presentationHeader !== parent.presentationHeader) {
      reasons.push('hop proofs are bound to different presentation headers');
      return {ok: false, reasons};
    }

    // hop 1
    const pIdx = indexes(parent.disclosedIndexes);
    if(!await verifyProof({
      publicKey: this.trustedIssuerPublicKey,
      proof: unb64(parent.proof),
      header: unb64(parent.header),
      presentationHeader: unb64(parent.presentationHeader),
      disclosedMessages: messagesOf(parent.disclosedMessages, pIdx),
      disclosedMessageIndexes: pIdx
    })) {
      reasons.push('parent (hop 1) proof failed to verify');
      return {ok: false, reasons};
    }

    // Which key signed the sub-mandate?
    const guardianKey = claim(parent.disclosedMessages, 'guardian_key');
    const delegatorClaim = claim(sub.disclosedMessages, 'delegator_key');
    let delegatorKeyB64;
    let hopsBound = false;
    if(profile.bindHops) {
      if(!guardianKey || !delegatorClaim) {
        reasons.push('profile claims hop binding but a hop key is not disclosed');
        return {ok: false, reasons};
      }
      if(guardianKey !== delegatorClaim) {
        reasons.push('sub-mandate delegator key != guardian key in the parent mandate');
        return {ok: false, reasons};
      }
      delegatorKeyB64 = guardianKey;
      hopsBound = true;
    } else {
      // Nothing authenticates this key. The verifier takes it on faith.
      delegatorKeyB64 = sub.delegatorPublicKey;
      if(!delegatorKeyB64) {
        reasons.push('no delegator key available');
        return {ok: false, reasons};
      }
    }

    // hop 2
    const sIdx = indexes(sub.disclosedIndexes);
    if(!await verifyProof({
      publicKey: unb64(delegatorKeyB64),
      proof: unb64(sub.proof),
      header: unb64(sub.header),
      presentationHeader: unb64(sub.presentationHeader),
      disclosedMessages: messagesOf(sub.disclosedMessages, sIdx),
      disclosedMessageIndexes: sIdx
    })) {
      reasons.push('sub-mandate (hop 2) proof failed to verify');
      return {ok: false, reasons};
    }

    // Attenuation policy.
    const subScope = claim(sub.disclosedMessages, 'sub_scope');
    if(requiredScope && subScope !== requiredScope) {
      reasons.push(`sub scope "${subScope}" != required "${requiredScope}"`);
      return {ok: false, reasons};
    }
    const parentScope = claim(parent.disclosedMessages, 'mandate_scope');
    let attenuationChecked = false;
    if(hopsBound && parentScope) {
      if(!subsumes(parentScope, subScope)) {
        reasons.push(`sub scope "${subScope}" is not subsumed by parent scope "${parentScope}"`);
        return {ok: false, reasons};
      }
      attenuationChecked = true;
    }

    // Cascading revocation: only possible if a parent handle was shipped.
    const parentHandle = claim(parent.disclosedMessages, 'revocation_handle') ??
      claim(sub.disclosedMessages, 'parent_revocation_handle');
    let parentRevocationChecked = false;
    if(parentHandle && this.statusChecker) {
      const revoked = this.statusChecker.isRevokedHandle(parentHandle);
      if(revoked === true) {
        reasons.push('parent mandate is revoked');
        return {ok: false, reasons, parentRevocationChecked: true};
      }
      parentRevocationChecked = revoked !== null;
    }

    return {ok: true, reasons, hopsBound, attenuationChecked, parentRevocationChecked};
  }
}
