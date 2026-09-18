/**
 * Tests for the bbs-2023 re-run: the harness additions, and the cryptosuite
 * behaviours the findings rest on. Each library test issues/derives real
 * bbs-2023 credentials, so this file takes a few seconds.
 */
import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import * as vc from '@digitalbazaar/vc';
import {conjunctionAttack} from '../src/harness.js';
import {blankNodeRanks, decodeDerivedProofValue} from '../src/cryptosuite/decode.js';
import {documentLoader, ISSUER, MANDATE_CONTEXT_URL, signSuite} from '../src/cryptosuite/env.js';
import {derive, verify} from '../src/cryptosuite/scenario.js';

const mk = (id, subject, verifierId, payload) => ({id, subject, verifierId, payload});
const credential = extra => ({
  '@context': ['https://www.w3.org/ns/credentials/v2', MANDATE_CONTEXT_URL],
  type: ['VerifiableCredential', 'GuardianshipMandateCredential'],
  issuer: ISSUER, validUntil: '2026-09-30T23:59:59Z', ...extra,
  credentialSubject: {
    type: 'Guardian', guardianKey: 'k'.repeat(24),
    actsFor: {type: 'Dependent', dependentId: 'dep:Y'},
    mandate: {type: 'Mandate', scope: 'school_enrolment'}
  }
});
const policy = {mandatoryPointers: ['/issuer'], selectivePointers: ['/credentialSubject/mandate/scope']};
const issue = async c => vc.issue({credential: c, suite: await signSuite(policy.mandatoryPointers), documentLoader});

describe('conjunctionAttack', () => {
  it('links via a combination of fields that are each only partial', () => {
    // a: shared by Y and D1; b: shared by Y and D2 -> (a,b) unique to Y
    const corpus = [
      mk('y0', 'Y', 'v1', {a: 'A1', b: 'B1'}), mk('y1', 'Y', 'v2', {a: 'A1', b: 'B1'}),
      mk('d0', 'D1', 'v1', {a: 'A1', b: 'B2'}), mk('d1', 'D2', 'v2', {a: 'A2', b: 'B1'})
    ];
    assert.equal(conjunctionAttack({corpus, target: 'Y'}).exactLinkage, true);
  });
  it('ignores fields determined by the receiving verifier', () => {
    const corpus = [
      mk('y0', 'Y', 'v1', {len: '10', s: 'x'}), mk('y1', 'Y', 'v2', {len: '20', s: 'x'}),
      mk('d0', 'D1', 'v1', {len: '10', s: 'x'}), mk('d1', 'D1', 'v2', {len: '20', s: 'x'})
    ];
    const r = conjunctionAttack({corpus, target: 'Y'});
    assert.equal(r.recall, 1);           // len did not split Y's own presentations
    assert.equal(r.exactLinkage, false); // and nothing else identifies Y
  });
});

describe('blankNodeRanks', () => {
  it('keys each blank node by its rdf:type', () => {
    const r = blankNodeRanks([
      '_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://x.example/v#Mandate> .',
      '_:b2 <https://x.example/v#scope> "s" .'
    ]);
    assert.deepEqual(r, {Mandate: 'Mandate@b2'});
  });
});

describe('bbs-2023 behaviours the findings rest on', () => {
  it('derives, verifies, and decodes a baseline derived proof', async () => {
    const signed = await issue(credential({}));
    const d = await derive({signed, policy, nonce: 'n1'});
    assert.equal((await verify({derived: d, nonce: 'n1'})).verified, true);
    const p = decodeDerivedProofValue(d.proof.proofValue);
    assert.equal(p.cborTag, 'd95d03');
    assert.ok(p.labelMap.size >= 1);
  });

  it('reveals a node `id` on the selected path without any pointer asking for it', async () => {
    const signed = await issue(credential({id: 'urn:uuid:00000000-0000-4000-a000-00000000abcd'}));
    const d = await derive({signed, policy, nonce: 'n2'});
    assert.equal(d.id, 'urn:uuid:00000000-0000-4000-a000-00000000abcd');
  });

  it('repeats labelMap and selectiveIndexes on every derivation of one credential', async () => {
    const signed = await issue(credential({}));
    const a = decodeDerivedProofValue((await derive({signed, policy, nonce: 'a'})).proof.proofValue);
    const b = decodeDerivedProofValue((await derive({signed, policy, nonce: 'b'})).proof.proofValue);
    assert.deepEqual([...a.labelMap], [...b.labelMap]);
    assert.deepEqual(a.selectiveIndexes, b.selectiveIndexes);
    assert.notDeepEqual(Buffer.from(a.bbsProof), Buffer.from(b.bbsProof));
  });

  it('never emits proof.created (would be a per-credential timestamp)', async () => {
    const signed = await issue(credential({}));
    assert.equal(signed.proof.created, undefined);
    const d = await derive({signed, policy, nonce: 'n3'});
    assert.equal(d.proof.created, undefined);
  });
});
