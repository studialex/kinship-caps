/**
 * Tests for the harness itself.
 *
 * Two kinds:
 *  1. the harness detects a leak that we plant on purpose, and does not flag a
 *     value that is constant but cohort-wide (guards against a checker that
 *     always says "green" or always says "red");
 *  2. the BBS library behaves the way the whole argument assumes it does.
 */
import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {
  clusteringAttack, fieldTable, flatten, proofUniqueness
} from '../src/harness.js';
import {atoms, crossHopAnalysis} from '../src/crosshop.js';
import {
  CIPHERSUITE, deriveProof, generateKeyPair, sign, utf8, verifyProof
} from '../src/bbs.js';
import {subsumes} from '../src/schema.js';

const mk = (id, subject, verifierId, payload) => ({id, subject, verifierId, payload});

describe('flatten', () => {
  it('relabels disclosed BBS messages by attribute name', () => {
    const f = flatten({bbs: {disclosedMessages: {'2': 'mandate_scope=school_enrolment'}}});
    assert.equal(f.get('bbs.disclosed[mandate_scope]'), 'mandate_scope=school_enrolment');
  });
});

describe('fieldTable', () => {
  const corpus = [
    mk('y0', 'Y', 'v1', {a: 'CONSTANT-COHORT', b: 'only-Y', c: 'r1'}),
    mk('y1', 'Y', 'v2', {a: 'CONSTANT-COHORT', b: 'only-Y', c: 'r2'}),
    mk('d0', 'D1', 'v1', {a: 'CONSTANT-COHORT', b: 'only-D1', c: 'r3'}),
    mk('d1', 'D2', 'v1', {a: 'CONSTANT-COHORT', b: 'only-D2', c: 'r4'})
  ];
  const rows = fieldTable({corpus, target: 'Y'});
  const row = p => rows.find(r => r.path === p);

  it('flags a constant value unique to the subject as a hard leak', () => {
    assert.equal(row('b').leak, 'Y');
    assert.equal(row('b').anonymitySet, 1);
  });
  it('does NOT flag a value that is constant but shared cohort-wide', () => {
    assert.equal(row('a').leak, 'N');
    assert.equal(row('a').anonymitySet, 3);
  });
  it('does not flag a value that varies per presentation', () => {
    assert.equal(row('c').leak, 'N');
    assert.equal(row('c').constant, false);
  });
  it('reports partial narrowing when a value is shared by a strict subset', () => {
    const c2 = [
      mk('y0', 'Y', 'v1', {s: 'school'}), mk('y1', 'Y', 'v2', {s: 'school'}),
      mk('d0', 'D1', 'v1', {s: 'school'}), mk('d1', 'D2', 'v1', {s: 'clinic'})
    ];
    assert.equal(fieldTable({corpus: c2, target: 'Y'})
      .find(r => r.path === 's').leak, 'partial');
  });
});

describe('clusteringAttack', () => {
  it('recovers exact linkage from a single unique constant field', () => {
    const corpus = [
      mk('y0', 'Y', 'v1', {id: 'Y-handle', s: 'school'}),
      mk('y1', 'Y', 'v2', {id: 'Y-handle', s: 'school'}),
      mk('d0', 'D1', 'v1', {id: 'D1-handle', s: 'school'}),
      mk('d1', 'D2', 'v1', {id: 'D2-handle', s: 'clinic'})
    ];
    const r = clusteringAttack({corpus, target: 'Y'});
    assert.equal(r.exactLinkage, true);
    assert.equal(r.bestSingleField.path, 'id');
    assert.equal(r.bestSingleField.precision, 1);
    assert.equal(r.bestSingleField.recall, 1);
  });

  it('does not claim exact linkage when nothing distinguishes the subject', () => {
    const corpus = [
      mk('y0', 'Y', 'v1', {s: 'school', n: 'a'}),
      mk('y1', 'Y', 'v2', {s: 'school', n: 'b'}),
      mk('d0', 'D1', 'v1', {s: 'school', n: 'c'}),
      mk('d1', 'D2', 'v1', {s: 'school', n: 'd'})
    ];
    assert.equal(clusteringAttack({corpus, target: 'Y'}).exactLinkage, false);
  });
});

describe('proofUniqueness', () => {
  it('hard-fails on duplicated proof bytes', () => {
    const dup = [
      mk('y0', 'Y', 'v1', {bbs: {proof: 'AAAA'}}),
      mk('y1', 'Y', 'v2', {bbs: {proof: 'AAAA'}})
    ];
    assert.equal(proofUniqueness({corpus: dup}).pass, false);
  });
  it('passes when every proof differs', () => {
    const ok = [
      mk('y0', 'Y', 'v1', {bbs: {proof: 'AAAA'}}),
      mk('y1', 'Y', 'v2', {bbs: {proof: 'BBBB'}})
    ];
    assert.equal(proofUniqueness({corpus: ok}).pass, true);
  });
});

describe('crossHopAnalysis', () => {
  it('catches the same secret surfacing under two different field names', () => {
    const hop1 = [mk('y0', 'Y', 'v1', {guardian_key: 'guardian_key=KEYMATERIAL-123456'}),
      mk('d0', 'D1', 'v1', {guardian_key: 'guardian_key=OTHERKEY-99999999'})];
    const hop2 = [mk('y1', 'Y', 'v2', {delegator_key: 'delegator_key=KEYMATERIAL-123456'}),
      mk('d1', 'D1', 'v2', {delegator_key: 'delegator_key=OTHERKEY-99999999'})];
    const r = crossHopAnalysis({hop1, hop2, target: 'Y', label: 't'});
    assert.equal(r.pass, false);
    assert.ok(r.hardCorrelators.some(c => c.atom.includes('KEYMATERIAL')));
  });
  it('passes when the two hops share only cohort-wide values', () => {
    const hop1 = [mk('y0', 'Y', 'v1', {t: 'type=Mandate', k: 'issuerpubkey-shared'}),
      mk('d0', 'D1', 'v1', {t: 'type=Mandate', k: 'issuerpubkey-shared'})];
    const hop2 = [mk('y1', 'Y', 'v2', {t: 'type=Mandate', k: 'issuerpubkey-shared'}),
      mk('d1', 'D1', 'v2', {t: 'type=Mandate', k: 'issuerpubkey-shared'})];
    assert.equal(crossHopAnalysis({hop1, hop2, target: 'Y', label: 't'}).pass, true);
  });
  it('extracts value fragments from a composite header string', () => {
    const a = atoms('open-core/mandate/v1|issuer=did:example:x|cred=urn:uuid:abcdef12');
    assert.ok(a.has('urn:uuid:abcdef12'));
    assert.ok(a.has('did:example:x'));
  });
});

describe('scope lattice', () => {
  it('school_enrolment subsumes school_pickup but not the reverse', () => {
    assert.equal(subsumes('school_enrolment', 'school_pickup'), true);
    assert.equal(subsumes('school_pickup', 'school_enrolment'), false);
  });
});

describe('BBS library assumptions (the properties the whole claim rests on)', () => {
  const messages = ['type=M', 'dependent_id=Y', 'mandate_scope=s', 'valid_until=x']
    .map(utf8);
  const header = utf8('hdr');

  it('derives randomised proofs: identical inputs still yield different bytes', async () => {
    const kp = await generateKeyPair(new Uint8Array(32).fill(3));
    const sig = await sign({secretKey: kp.secretKey, publicKey: kp.publicKey, header, messages});
    const args = {
      publicKey: kp.publicKey, signature: sig, header, messages,
      presentationHeader: utf8('same-nonce'), disclosedMessageIndexes: [0, 2]
    };
    const p1 = await deriveProof(args);
    const p2 = await deriveProof(args);
    assert.notEqual(Buffer.from(p1).toString('base64'), Buffer.from(p2).toString('base64'));
  });

  it('the derived proof does not contain the original signature bytes', async () => {
    const kp = await generateKeyPair(new Uint8Array(32).fill(4));
    const sig = await sign({secretKey: kp.secretKey, publicKey: kp.publicKey, header, messages});
    const proof = await deriveProof({
      publicKey: kp.publicKey, signature: sig, header, messages,
      presentationHeader: utf8('n'), disclosedMessageIndexes: [0]
    });
    assert.ok(!Buffer.from(proof).includes(Buffer.from(sig)));
  });

  it('rejects a proof replayed under a different header', async () => {
    const kp = await generateKeyPair(new Uint8Array(32).fill(5));
    const sig = await sign({secretKey: kp.secretKey, publicKey: kp.publicKey, header, messages});
    const proof = await deriveProof({
      publicKey: kp.publicKey, signature: sig, header, messages,
      presentationHeader: utf8('n'), disclosedMessageIndexes: [0]
    });
    const base = {
      publicKey: kp.publicKey, proof, presentationHeader: utf8('n'),
      disclosedMessages: [messages[0]], disclosedMessageIndexes: [0]
    };
    assert.equal(await verifyProof({...base, header}), true);
    assert.equal(await verifyProof({...base, header: utf8('other')}), false);
  });

  it('rejects a proof presented with a tampered disclosed message', async () => {
    const kp = await generateKeyPair(new Uint8Array(32).fill(6));
    const sig = await sign({secretKey: kp.secretKey, publicKey: kp.publicKey, header, messages});
    const proof = await deriveProof({
      publicKey: kp.publicKey, signature: sig, header, messages,
      presentationHeader: utf8('n'), disclosedMessageIndexes: [2]
    });
    assert.equal(await verifyProof({
      publicKey: kp.publicKey, proof, header, presentationHeader: utf8('n'),
      disclosedMessages: [utf8('mandate_scope=WIDER')], disclosedMessageIndexes: [2]
    }), false);
  });

  it('uses the expected ciphersuite', () => {
    assert.equal(CIPHERSUITE, 'BLS12-381-SHA-256');
  });
});
