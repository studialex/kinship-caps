/**
 * Active attacks: (f) scope escalation by the sub-carer, (g) cascading revocation,
 * and two DELEGATION TRANSPORT attacks.
 *
 * Why transports matter: plain BBS has no delegation. Hop 2 can only prove that
 * hop 1 exists if it can produce a proof over the PARENT signature -- which only
 * the guardian holds. There are exactly three ways out, and two of them are
 * attacks:
 *   T1  give the sub-carer the parent signature        -> attenuation destroyed
 *   T2  give the sub-carer a pre-derived parent proof  -> static bytes: replayable + linkable
 *   T3  the guardian derives a fresh parent proof per presentation (online)
 * Everything in scenarios.js uses T3. T1/T2 are exercised here.
 */
import {b64, deriveProof, unb64, utf8} from './bbs.js';
import {Guardian, makeKeyPair, presentChain, presentMandate, SubCarer} from './holder.js';
import {Verifier} from './verifier.js';
import {CHAIN_PROFILES, idxOf, MANDATE_ATTRS, SINGLE_HOP_PROFILES} from './schema.js';
import {makeSubCarer, SUB_SCOPE_FOR, TARGET} from './world.js';

const freshVerifier = (world, id) => new Verifier({
  id, trustedIssuerPublicKey: world.issuer.keyPair.publicKey, statusChecker: world.issuer
});

const targetOf = world => world.subjects.find(s => s.id === TARGET);

async function legitChain({world, profile, verifier, subject}) {
  const nonce = verifier.newNonce(world.rng);
  const subCarer = await makeSubCarer({
    subject, profile, freshSeed: profile.freshDelegatorKey ? 'fresh:attack' : null
  });
  const payload = await presentChain({
    guardian: subject.guardian, subCarer, profile, verifier: {id: verifier.id, nonce}
  });
  return {payload, subCarer, nonce};
}

/* ------------------------- (f) attenuation attacks ------------------------ */

export async function runAttenuationAttacks(world) {
  const subject = targetOf(world);
  const parentScope = subject.scope;             // "school_enrolment"
  const subScope = SUB_SCOPE_FOR(parentScope);   // "school_pickup"
  const results = [];

  for(const [key, profile] of Object.entries(CHAIN_PROFILES)) {
    /* f1 -- claim inflation: rewrite the disclosed sub_scope string, keep the proof. */
    {
      const v = freshVerifier(world, 'rp:school');
      const {payload} = await legitChain({world, profile, verifier: v, subject});
      const idx = Object.keys(payload.sub.disclosedMessages)
        .find(i => payload.sub.disclosedMessages[i].startsWith('sub_scope='));
      payload.sub.disclosedMessages[idx] = `sub_scope=${parentScope}`;
      const r = await v.verifyChain(payload, {profile, requiredScope: parentScope});
      results.push({
        profile: key, attack: 'f1 rewrite the disclosed sub_scope value',
        accepted: r.ok, expected: false,
        outcome: r.ok ? 'ESCALATION SUCCEEDED' : `rejected: ${r.reasons[0]}`
      });
    }

    /* f2 -- self-issued sub-mandate: the sub-carer signs its own, broader mandate. */
    {
      const v = freshVerifier(world, 'rp:school');
      const attackerKey = await makeKeyPair('attacker:subcarer');
      const rogueGuardian = new Guardian({
        record: subject.record, keyPair: attackerKey
      });
      const rogueSub = await rogueGuardian.issueSubMandate({
        subScope: parentScope,               // <-- broader than what was delegated
        subValidUntil: '2027-12-31',         // <-- and longer
        subCarerKeyB64: b64(subject.subCarerKeyPair.publicKey),
        headerMode: profile.headerMode,
        signerKeyPair: attackerKey
      });
      // The attacker still needs a hop-1 proof; it re-uses the one the honest
      // guardian produced for this very presentation (worst realistic case).
      const nonce = v.newNonce(world.rng);
      const parent = await subject.guardian.deriveParentProof({
        profile, presentationHeader: utf8(nonce)
      });
      const rogueCarer = new SubCarer({
        keyPair: subject.subCarerKeyPair, subMandate: rogueSub
      });
      const sub = await rogueCarer.deriveSubProof({
        profile, presentationHeader: utf8(nonce)
      });
      if(!profile.bindHops) {
        sub.delegatorPublicKey = b64(attackerKey.publicKey);
      }
      const r = await v.verifyChain({parent, sub}, {profile, requiredScope: parentScope});
      results.push({
        profile: key, attack: 'f2 sub-carer self-issues a broader sub-mandate under its own key',
        accepted: r.ok, expected: false,
        outcome: r.ok ? 'ESCALATION SUCCEEDED' : `rejected: ${r.reasons[0]}`
      });
    }

    /* f3 -- message substitution: keep the proof, swap in the parent's scope
       message at the sub_scope index (tests that index/value binding holds). */
    {
      const v = freshVerifier(world, 'rp:school');
      const {payload} = await legitChain({world, profile, verifier: v, subject});
      const idx = Object.keys(payload.sub.disclosedMessages)
        .find(i => payload.sub.disclosedMessages[i].startsWith('sub_scope='));
      payload.sub.disclosedMessages[idx] = `mandate_scope=${parentScope}`;
      const r = await v.verifyChain(payload, {profile, requiredScope: parentScope});
      results.push({
        profile: key, attack: 'f3 substitute a different signed attribute at the scope index',
        accepted: r.ok, expected: false,
        outcome: r.ok ? 'ESCALATION SUCCEEDED' : `rejected: ${r.reasons[0]}`
      });
    }

    /* f4 -- honest baseline: the delegated (narrow) scope must still work. */
    {
      const v = freshVerifier(world, 'rp:school');
      const {payload} = await legitChain({world, profile, verifier: v, subject});
      const r = await v.verifyChain(payload, {profile, requiredScope: subScope});
      results.push({
        profile: key, attack: 'f4 baseline: honest presentation at the delegated scope',
        accepted: r.ok, expected: true,
        outcome: r.ok ? 'accepted (correct)' : `WRONGLY REJECTED: ${r.reasons[0]}`
      });
    }
  }
  return results;
}

/* ---------------------- transport attacks T1 and T2 ----------------------- */

export async function runTransportAttacks(world) {
  const subject = targetOf(world);
  const out = [];

  /* T1: the guardian hands over the parent SIGNATURE so the sub-carer can work
     offline. The sub-carer is now indistinguishable from the guardian. */
  {
    const profile = SINGLE_HOP_PROFILES.hardened;
    const v = freshVerifier(world, 'rp:school');
    const nonce = v.newNonce(world.rng);
    // The sub-carer, holding the parent signature, simply presents the parent
    // mandate at its FULL scope. No attenuation is involved at all.
    const payload = await presentMandate({
      record: subject.record, profile, verifier: {id: v.id, nonce}
    });
    const r = await v.verifySingle(payload, {requiredScope: subject.scope});
    out.push({
      attack: 'T1 guardian shares the parent BBS signature with the sub-carer',
      accepted: r.ok, expected: false,
      outcome: r.ok
        ? 'ESCALATION SUCCEEDED - sub-carer presents the full parent mandate'
        : `rejected: ${r.reasons[0]}`
    });
  }

  /* T2: the guardian pre-derives ONE parent proof so the sub-carer can work
     offline. Those proof bytes are now static. */
  {
    const profile = CHAIN_PROFILES.unlinkableStable;
    const staticPh = utf8('static-parent-proof-ph');
    const parentStatic = await subject.guardian.deriveParentProof({
      profile, presentationHeader: staticPh
    });
    const subCarer = await makeSubCarer({subject, profile});
    const results = [];
    for(const rpId of ['rp:school', 'rp:library']) {
      const strict = freshVerifier(world, rpId);
      const sub = await subCarer.deriveSubProof({profile, presentationHeader: staticPh});
      const payload = {parent: structuredClone(parentStatic), sub};
      const rStrict = await strict.verifyChain(payload, {
        profile, requiredScope: SUB_SCOPE_FOR(subject.scope)
      });
      const lax = freshVerifier(world, rpId);
      const rLax = await lax.verifyChain(payload, {
        profile, requiredScope: SUB_SCOPE_FOR(subject.scope), checkNonce: false
      });
      results.push({payload, rStrict, rLax});
    }
    const identicalParentProof =
      results[0].payload.parent.proof === results[1].payload.parent.proof;
    out.push({
      attack: 'T2 guardian pre-derives a static parent proof (offline sub-carer)',
      accepted: results.every(r => r.rStrict.ok), expected: false,
      outcome: results.every(r => r.rStrict.ok)
        ? 'accepted by a nonce-checking verifier'
        : `rejected by a nonce-checking verifier: ${results[0].rStrict.reasons[0]}`,
      extra: {
        acceptedByLaxVerifier: results.every(r => r.rLax.ok),
        parentProofBytesIdenticalAcrossVerifiers: identicalParentProof
      }
    });
  }
  return out;
}

/* --------------------- (g) cascading revocation --------------------------- */

export async function runCascadingRevocation(world) {
  const subject = targetOf(world);
  const results = [];
  for(const [key, profile] of Object.entries(CHAIN_PROFILES)) {
    // 1. sanity: before revocation the chain must verify
    const vBefore = freshVerifier(world, 'rp:school');
    const before = await legitChain({world, profile, verifier: vBefore, subject});
    const rBefore = await vBefore.verifyChain(before.payload, {
      profile, requiredScope: SUB_SCOPE_FOR(subject.scope)
    });

    // 2. revoke the PARENT mandate at the issuer
    world.issuer.revokeByStatusIndex(subject.record.statusIndex);

    // 3. the sub-carer presents again, to a fresh verifier
    const vAfter = freshVerifier(world, 'rp:library');
    const after = await legitChain({world, profile, verifier: vAfter, subject});
    const rAfter = await vAfter.verifyChain(after.payload, {
      profile, requiredScope: SUB_SCOPE_FOR(subject.scope)
    });

    // restore state for any later test
    world.issuer.statusList.set(subject.record.statusIndex, false);

    results.push({
      profile: key,
      acceptedBeforeRevocation: rBefore.ok,
      acceptedAfterRevocation: rAfter.ok,
      parentStatusVisibleToVerifier: rAfter.parentRevocationChecked === true ||
        rAfter.reasons?.includes('parent mandate is revoked'),
      pass: rBefore.ok && !rAfter.ok,
      note: rAfter.ok
        ? 'sub-carer proof STILL VERIFIES after the parent mandate was revoked'
        : `rejected after revocation: ${rAfter.reasons[0]}`
    });
  }
  return results;
}

/* --------------- extra: does the single-hop mandate honour revocation? ----- */

export async function runSingleHopRevocation(world) {
  const subject = targetOf(world);
  const out = [];
  for(const [key, profile] of Object.entries(SINGLE_HOP_PROFILES)) {
    world.issuer.revokeByStatusIndex(subject.record.statusIndex);
    const v = freshVerifier(world, 'rp:school');
    const nonce = v.newNonce(world.rng);
    const payload = await presentMandate({
      record: subject.record, profile, verifier: {id: v.id, nonce}
    });
    const r = await v.verifySingle(payload, {requiredScope: subject.scope});
    world.issuer.statusList.set(subject.record.statusIndex, false);
    out.push({
      profile: key, acceptedAfterRevocation: r.ok,
      revocationEnforced: !r.ok,
      note: r.ok
        ? 'revoked mandate still verifies: no status handle is shipped to the verifier'
        : `rejected: ${r.reasons[0]}`
    });
  }
  return out;
}

export {deriveProof, idxOf, MANDATE_ATTRS, unb64};
