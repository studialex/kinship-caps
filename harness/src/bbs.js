/**
 * Thin wrapper over @digitalbazaar/bbs-signatures (IETF draft-irtf-cfrg-bbs-signatures-06).
 *
 * HARD CONSTRAINT OF THIS PROJECT: we implement no cryptography. Every function
 * here forwards directly to the library. The only thing added is (a) a fixed
 * ciphersuite, (b) UTF-8 encoding of attribute strings into BBS messages, and
 * (c) base64 helpers so presentations can be serialised as JSON -- i.e. so the
 * harness can inspect "exactly the bytes a verifier receives".
 */
import * as bbs from '@digitalbazaar/bbs-signatures';

export const CIPHERSUITE = bbs.CIPHERSUITES.BLS12381_SHA256;

const TE = new TextEncoder();

export const utf8 = s => TE.encode(s);
export const b64 = u8 => Buffer.from(u8).toString('base64');
export const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

export async function generateKeyPair(seed) {
  return bbs.generateKeyPair({seed, ciphersuite: CIPHERSUITE});
}

export async function sign({secretKey, publicKey, header, messages}) {
  return bbs.sign({secretKey, publicKey, header, messages, ciphersuite: CIPHERSUITE});
}

export async function verifySignature({publicKey, signature, header, messages}) {
  return bbs.verifySignature({
    publicKey, signature, header, messages, ciphersuite: CIPHERSUITE});
}

/** Selective disclosure: produce a fresh, randomised zero-knowledge derived proof. */
export async function deriveProof({
  publicKey, signature, header, messages, presentationHeader, disclosedMessageIndexes
}) {
  return bbs.deriveProof({
    publicKey, signature, header, messages, presentationHeader,
    disclosedMessageIndexes, ciphersuite: CIPHERSUITE
  });
}

export async function verifyProof({
  publicKey, proof, header, presentationHeader, disclosedMessages, disclosedMessageIndexes
}) {
  try {
    return await bbs.verifyProof({
      publicKey, proof, header, presentationHeader, disclosedMessages,
      disclosedMessageIndexes, ciphersuite: CIPHERSUITE
    });
  } catch(e) {
    // A malformed / forged proof throws rather than returning false; for the
    // attack scripts a throw and a `false` are the same outcome: rejected.
    return false;
  }
}
