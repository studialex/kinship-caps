/**
 * The adversary's view of a bbs-2023 derived credential.
 *
 * A verifier receives one JSON document. The interesting per-credential material
 * is NOT visible as a top-level field: it is inside `proof.proofValue`, a
 * multibase/CBOR blob that also contains the randomised BBS proof. Compared as a
 * whole string, proofValue is unique on every presentation -- so a checker that
 * only diffs raw bytes would report "no correlator" and be wrong.
 *
 * Any verifier can decode it (it has to, in order to verify). So we decode it
 * too, and hand both the raw payload and the decoded components to the checker.
 * This is parsing, not cryptography.
 *
 * We also reproduce the verifier's own canonical N-Quads (with the holder's
 * label map applied) by calling the same di-sd-primitives functions the
 * cryptosuite's verifier calls, so probe (h) can inspect exactly the statements
 * that feed `mandatoryHash`.
 */
import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';
import {
  createLabelMapFunction, hashMandatory, labelReplacementCanonicalizeJsonLd
} from '@digitalbazaar/di-sd-primitives';
import {documentLoader} from './env.js';

const DERIVED_PREFIX = [0xd9, 0x5d, 0x03];
const TAGS = [];
TAGS[64] = b => b;

export function decodeDerivedProofValue(proofValue) {
  if(typeof proofValue !== 'string' || proofValue[0] !== 'u') {
    throw new Error('proofValue must be a base64url multibase string');
  }
  const raw = base64url.decode(proofValue.slice(1));
  for(let i = 0; i < 3; i++) {
    if(raw[i] !== DERIVED_PREFIX[i]) {
      throw new Error('not a bbs-2023 baseline derived proof (unexpected CBOR tag)');
    }
  }
  const [bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes,
    presentationHeader] = cborg.decode(raw.subarray(3), {useMaps: true, tags: TAGS});
  const labelMap = new Map();
  for(const [k, v] of compressedLabelMap.entries()) {
    labelMap.set(`c14n${k}`, `b${v}`);
  }
  return {
    cborTag: Buffer.from(raw.subarray(0, 3)).toString('hex'),
    bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader,
    proofValueByteLength: raw.length
  };
}

/** The canonical N-Quads a verifier computes, split into mandatory / non-mandatory. */
export async function verifierQuads(derived) {
  const decoded = decodeDerivedProofValue(derived.proof.proofValue);
  const {proof, ...document} = derived;
  const labelMapFactoryFunction = await createLabelMapFunction({labelMap: decoded.labelMap});
  const nquads = await labelReplacementCanonicalizeJsonLd({
    document, labelMapFactoryFunction, options: {documentLoader}
  });
  const mandatory = nquads.filter((_, i) => decoded.mandatoryIndexes.includes(i));
  const nonMandatory = nquads.filter((_, i) => !decoded.mandatoryIndexes.includes(i));
  const {mandatoryHash} = await hashMandatory({mandatory});
  return {nquads, mandatory, nonMandatory, mandatoryHash: Buffer.from(mandatoryHash).toString('hex')};
}

/**
 * Structural fingerprint of a JSON document: the sorted set of key paths with
 * values removed. Two documents with the same shape share a fingerprint.
 */
export function shapeOf(obj, prefix = '', out = []) {
  if(Array.isArray(obj)) {
    out.push(`${prefix}[${obj.length}]`);
    obj.forEach((v, i) => typeof v === 'object' && v !== null && shapeOf(v, `${prefix}[${i}]`, out));
  } else if(obj && typeof obj === 'object') {
    for(const k of Object.keys(obj).sort()) {
      const p = prefix ? `${prefix}.${k}` : k;
      out.push(p);
      if(typeof obj[k] === 'object' && obj[k] !== null) {
        shapeOf(obj[k], p, out);
      }
    }
  }
  return out;
}

/**
 * Flattenable "decoded view" that the adversary adds next to the raw payload.
 * Paths are prefixed `decoded.` so the leak table shows which rows only
 * become visible after parsing proofValue.
 */
/**
 * HMAC rank of every revealed blank node, keyed by the node's rdf:type. The
 * ranks (`bN`) are assigned over the WHOLE credential, not over what was
 * revealed -- so the same node carries the same rank in every derivation of
 * that credential, whatever the pointer set. That makes them comparable across
 * different disclosures, e.g. across delegation hops (probe e).
 */
export function blankNodeRanks(nquads) {
  const TYPE = '<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>';
  const roles = new Map();
  for(const q of nquads) {
    const m = /^(_:b\d+) (\S+) <([^>]+)>/.exec(q);
    if(m && m[2] === TYPE) {
      const local = m[3].split(/[#/]/).pop();
      roles.set(m[1], [...(roles.get(m[1]) ?? []), local].sort());
    }
  }
  const out = {};
  for(const [label, types] of roles) {
    out[types.join('+')] = `${types.join('+')}@${label.slice(2)}`;
  }
  return out;
}

export async function adversaryView(derived) {
  const d = decodeDerivedProofValue(derived.proof.proofValue);
  const q = await verifierQuads(derived);
  const {proof, ...doc} = derived;
  return {
    cborTag: d.cborTag,
    bbsProof: Buffer.from(d.bbsProof).toString('base64'),
    bbsProofByteLength: d.bbsProof.length,
    proofValueByteLength: d.proofValueByteLength,
    labelMap: JSON.stringify([...d.labelMap.entries()]),
    labelMapSize: d.labelMap.size,
    mandatoryIndexes: JSON.stringify(d.mandatoryIndexes),
    selectiveIndexes: JSON.stringify(d.selectiveIndexes),
    presentationHeader: Buffer.from(d.presentationHeader).toString('utf8'),
    revealedNQuadCount: q.nquads.length,
    mandatoryNQuadCount: q.mandatory.length,
    mandatoryHash: q.mandatoryHash,
    mandatoryNQuads: JSON.stringify(q.mandatory),
    documentShape: shapeOf(doc).join('|'),
    bnodeRank: blankNodeRanks(q.nquads)
  };
}

const BASE_PREFIX = [0xd9, 0x5d, 0x02];

/** Issuer-side: parse a base proof (what the issuer and holder hold, never a verifier). */
export function decodeBaseProofValue(proofValue) {
  const raw = base64url.decode(proofValue.slice(1));
  for(let i = 0; i < 3; i++) {
    if(raw[i] !== BASE_PREFIX[i]) {
      throw new Error('not a bbs-2023 baseline base proof');
    }
  }
  const [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers] =
    cborg.decode(raw.subarray(3), {useMaps: true, tags: TAGS});
  return {bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers};
}
