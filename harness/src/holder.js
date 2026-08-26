/**
 * Holders: the guardian (hop 1) and the temporary sub-carer (hop 2).
 *
 * Everything a holder emits is a *presentation payload*: a plain JSON object
 * containing exactly the bytes a verifier receives. The harness never looks at
 * holder-side state -- only at these payloads -- because that is precisely the
 * adversary's view.
 */
import {b64, deriveProof, generateKeyPair, sign, utf8} from './bbs.js';
import {
  encodeMessages, idxOf, MANDATE_ATTRS, SUBMANDATE_ATTRS
} from './schema.js';
import {EPOCH, headerFor, ISSUER_KEY_ID} from './issuer.js';
import {DeterministicRng} from './rng.js';

/** Sub-mandate header. Mirrors the mandate's two header strategies. */
export function subHeaderFor(headerMode, parentCredentialId) {
  if(headerMode === 'per-credential') {
    return utf8(`open-core/sub-mandate/v1|parent=${parentCredentialId}`);
  }
  return utf8(`open-core/sub-mandate/v1|epoch=${EPOCH}`);
}

/* -------------------------------------------------------------------------- */
/* Hop 1: the guardian presents the mandate directly                           */
/* -------------------------------------------------------------------------- */

/**
 * Build one single-hop presentation payload.
 *
 * @param record   issuer record for the mandate
 * @param profile  entry from SINGLE_HOP_PROFILES
 * @param verifier {id, nonce}  -- nonce is fresh per presentation (verifier-supplied)
 */
export async function presentMandate({record, profile, verifier}) {
  const variant = record.variants[profile.headerMode];
  const disclosedIndexes = idxOf(MANDATE_ATTRS, profile.disclose);
  const presentationHeader = utf8(verifier.nonce);

  const proof = await deriveProof({
    publicKey: record.issuerPublicKey,
    signature: variant.signature,
    header: variant.header,
    messages: variant.messages,
    presentationHeader,
    disclosedMessageIndexes: disclosedIndexes
  });

  const disclosedMessages = {};
  for(const i of disclosedIndexes) {
    disclosedMessages[String(i)] = Buffer.from(variant.messages[i]).toString('utf8');
  }

  const payload = {
    bbs: {
      issuerPublicKey: b64(record.issuerPublicKey),
      header: b64(variant.header),
      presentationHeader: b64(presentationHeader),
      disclosedIndexes: disclosedIndexes.join(','),
      disclosedMessages,
      totalMessageCount: variant.messages.length,
      proof: b64(proof),
      proofByteLength: proof.length
    },
    envelope: {}
  };

  // Protocol fields our composition adds around the BBS proof.
  if(profile.envelope.credentialId) {
    payload.envelope.credentialId = record.credentialId;
  }
  if(profile.envelope.credentialStatus) {
    payload.envelope.credentialStatus = {
      type: 'StatusList2021Entry',
      statusListCredential: `https://status.example/mandates/${EPOCH}`,
      statusListIndex: record.statusIndex
    };
  }
  if(profile.envelope.issuerKeyId) {
    payload.envelope.issuerKeyId = ISSUER_KEY_ID;
  }
  if(profile.envelope.holderKeyId) {
    // "holder binding" as commonly implemented: a stable DID for the guardian.
    payload.envelope.holderKeyId = `did:key:z${record.guardianKeyB64.slice(0, 24)}`;
  }
  return payload;
}

/* -------------------------------------------------------------------------- */
/* Delegation: guardian -> sub-carer                                            */
/* -------------------------------------------------------------------------- */

export class Guardian {
  constructor({record, keyPair, rng}) {
    this.record = record;          // the parent mandate (issuer-signed)
    this.keyPair = keyPair;        // guardian's own BBS key pair
    this.rng = rng ?? new DeterministicRng('guardian');
  }

  /**
   * Issue an attenuated sub-mandate. `signerKeyPair` defaults to the guardian's
   * stable key; the `freshDelegatorKey` profile passes a throwaway key instead.
   */
  async issueSubMandate({subScope, subValidUntil, subCarerKeyB64, headerMode,
    signerKeyPair = this.keyPair}) {
    const claims = {
      type: 'GuardianshipSubMandate',
      dependent_id: this.record.dependentId,
      sub_scope: subScope,
      sub_valid_until: subValidUntil,
      subcarer_key: subCarerKeyB64,
      delegator_key: b64(signerKeyPair.publicKey),
      parent_credential_id: this.record.credentialId,
      parent_revocation_handle: this.record.revocationHandle
    };
    const header = subHeaderFor(headerMode, this.record.credentialId);
    const messages = encodeMessages(SUBMANDATE_ATTRS, claims);
    const signature = await sign({
      secretKey: signerKeyPair.secretKey,
      publicKey: signerKeyPair.publicKey,
      header, messages
    });
    return {
      claims, header, messages, signature,
      delegatorPublicKey: signerKeyPair.publicKey
    };
  }

  /**
   * Derive a fresh proof of the PARENT mandate for a sub-carer presentation.
   *
   * NOTE (transport T3): this requires the guardian to be reachable at the moment
   * the sub-carer presents, because only the guardian holds the parent signature.
   * The two offline alternatives are modelled as attacks in attacks.js:
   *  T1 hand the sub-carer the parent signature  -> destroys attenuation
   *  T2 hand the sub-carer a pre-derived proof   -> static bytes, replayable + linkable
   */
  async deriveParentProof({profile, presentationHeader}) {
    const variant = this.record.variants[profile.headerMode];
    const disclosedIndexes = idxOf(MANDATE_ATTRS, profile.parentDisclose);
    const proof = await deriveProof({
      publicKey: this.record.issuerPublicKey,
      signature: variant.signature,
      header: variant.header,
      messages: variant.messages,
      presentationHeader,
      disclosedMessageIndexes: disclosedIndexes
    });
    const disclosedMessages = {};
    for(const i of disclosedIndexes) {
      disclosedMessages[String(i)] = Buffer.from(variant.messages[i]).toString('utf8');
    }
    return {
      issuerPublicKey: b64(this.record.issuerPublicKey),
      header: b64(variant.header),
      presentationHeader: b64(presentationHeader),
      disclosedIndexes: disclosedIndexes.join(','),
      disclosedMessages,
      proof: b64(proof),
      proofByteLength: proof.length
    };
  }
}

export class SubCarer {
  constructor({keyPair, subMandate}) {
    this.keyPair = keyPair;
    this.subMandate = subMandate;
  }

  async deriveSubProof({profile, presentationHeader}) {
    const disclosedIndexes = idxOf(SUBMANDATE_ATTRS, profile.subDisclose);
    const proof = await deriveProof({
      publicKey: this.subMandate.delegatorPublicKey,
      signature: this.subMandate.signature,
      header: this.subMandate.header,
      messages: this.subMandate.messages,
      presentationHeader,
      disclosedMessageIndexes: disclosedIndexes
    });
    const disclosedMessages = {};
    for(const i of disclosedIndexes) {
      disclosedMessages[String(i)] =
        Buffer.from(this.subMandate.messages[i]).toString('utf8');
    }
    const out = {
      header: b64(this.subMandate.header),
      presentationHeader: b64(presentationHeader),
      disclosedIndexes: disclosedIndexes.join(','),
      disclosedMessages,
      proof: b64(proof),
      proofByteLength: proof.length
    };
    if(!profile.bindHops) {
      // Nothing in either proof identifies the delegator, so the verifier has to
      // be handed a public key out of band -- unauthenticated. See attack (f2).
      out.delegatorPublicKey = b64(this.subMandate.delegatorPublicKey);
    }
    return out;
  }
}

/**
 * Build one two-hop (chain) presentation payload.
 * The sub-mandate is (re-)issued here for the `freshDelegatorKey` profile.
 */
export async function presentChain({guardian, subCarer, profile, verifier}) {
  const presentationHeader = utf8(verifier.nonce);
  const parent = await guardian.deriveParentProof({profile, presentationHeader});
  const sub = await subCarer.deriveSubProof({profile, presentationHeader});
  return {parent, sub};
}

export async function makeKeyPair(seedLabel) {
  return generateKeyPair(new DeterministicRng(seedLabel).bytes(32));
}
