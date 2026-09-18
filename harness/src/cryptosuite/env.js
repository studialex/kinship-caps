/**
 * Offline JSON-LD environment for the bbs-2023 run: document loader, issuer key,
 * and the three suite factories (sign / disclose / verify).
 *
 * Nothing here is cryptography. Every signature, derivation and verification is
 * a call into @digitalbazaar/bbs-2023-cryptosuite via @digitalbazaar/vc and
 * @digitalbazaar/data-integrity. The only thing this file adds is a document
 * loader, so the run never touches the network and is reproducible.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  createDiscloseCryptosuite, createSignCryptosuite, createVerifyCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {contexts as credentialsContexts} from '@digitalbazaar/credentials-context';
import {contexts as multikeyContexts} from '@digitalbazaar/multikey-context';
import {contexts as securityContexts} from '@digitalbazaar/security-context';
import {DeterministicRng} from '../rng.js';

export const ISSUER = 'https://issuer.example/mandate-registry';
export const MANDATE_CONTEXT_URL = 'https://kinship-caps.example/contexts/mandate/v1';

/**
 * Application context for the mandate vocabulary. `@protected` like the VC
 * contexts, so no term can be silently redefined downstream.
 */
export const MANDATE_CONTEXT = {
  '@context': {
    '@protected': true,
    kc: 'https://kinship-caps.example/vocab#',
    GuardianshipMandateCredential: 'kc:GuardianshipMandateCredential',
    Guardian: 'kc:Guardian',
    Dependent: 'kc:Dependent',
    Mandate: 'kc:Mandate',
    guardianKey: 'kc:guardianKey',
    actsFor: {'@id': 'kc:actsFor', '@type': '@id'},
    dependentId: 'kc:dependentId',
    mandate: {'@id': 'kc:mandate', '@type': '@id'},
    scope: 'kc:scope'
  }
};

let issuerKey = null;
let controllerDoc = null;

/** Deterministic issuer key (seeded) so the verificationMethod is stable across runs. */
export async function getIssuerKey() {
  if(issuerKey) {
    return issuerKey;
  }
  issuerKey = await Bls12381Multikey.generateBbsKeyPair({
    algorithm: Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256,
    controller: ISSUER,
    seed: new DeterministicRng('cryptosuite-issuer-key').bytes(32)
  });
  const publicKey = await issuerKey.export({publicKey: true, includeContext: true});
  controllerDoc = {
    '@context': [
      'https://w3id.org/security/v2',
      'https://w3id.org/security/multikey/v1'
    ],
    id: ISSUER,
    assertionMethod: [publicKey]
  };
  return issuerKey;
}

const STATIC = new Map([
  ...credentialsContexts,
  ...multikeyContexts,
  ...securityContexts,
  [MANDATE_CONTEXT_URL, MANDATE_CONTEXT]
]);

export async function documentLoader(url) {
  if(STATIC.has(url)) {
    return {contextUrl: null, documentUrl: url, document: STATIC.get(url)};
  }
  await getIssuerKey();
  if(url === ISSUER) {
    return {contextUrl: null, documentUrl: url, document: controllerDoc};
  }
  if(url.startsWith(`${ISSUER}#`)) {
    const vm = controllerDoc.assertionMethod.find(k => k.id === url);
    if(vm) {
      return {contextUrl: null, documentUrl: url, document: vm};
    }
  }
  throw new Error(`documentLoader: offline, refusing to fetch "${url}"`);
}

export async function signSuite(mandatoryPointers) {
  const signer = (await getIssuerKey()).signer();
  return new DataIntegrityProof({
    signer, cryptosuite: createSignCryptosuite({mandatoryPointers})
  });
}

export function discloseSuite({selectivePointers, presentationHeader}) {
  return new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({selectivePointers, presentationHeader})
  });
}

export function verifySuite({expectedPresentationHeader} = {}) {
  return new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite({expectedPresentationHeader})
  });
}
