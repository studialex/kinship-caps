# FINDINGS — falsification attempt against P1 (repeat-presentation unlinkability)

**Harness:** [`harness/`](../harness) in this repository (`open-core-p1-harness`).
**Primitive:** `@digitalbazaar/bbs-signatures@3.1.0`, ciphersuite `BLS12-381-SHA-256`,
IETF `draft-irtf-cfrg-bbs-signatures-06`. No cryptography was implemented here.
**Population:** 6 dependents (target `dep:Y` + 5 decoys), 4 relying parties.
Target presents 6 times: to 4 different RPs, and twice each to 2 of them.
**Raw output:** [`harness/sample-output/run-output.txt`](../harness/sample-output/run-output.txt).

Throughout, **k** is the anonymity set: the number of distinct dependents in the
corpus sharing the target's value at that field. `k = 1` means the field alone
identifies the dependent — a hard linkability leak. `k = 6` (the whole cohort)
means the field narrows nothing.

---

## 1. Headline

**The BBS layer did not leak. Our composition around it did.**

Every check aimed at the primitive passed: derived proofs were unique within
every corpus — 21/21 in each single-hop profile and 32/32 in each of the three
chain profiles, including the repeat visits to the same verifier — the issuer's
signature bytes never reappeared in a presentation, and no withheld attribute
value surfaced in a payload. Every leak found was introduced by protocol
plumbing we added — a credential id, a status handle, an exact expiry date, a
per-credential domain separator in the BBS `header`, a delegation pointer, a
stable delegation key.

Worth stressing: **`dependent_id` was withheld from the BBS disclosure in every
profile tested**, and check (d2) confirms it never surfaced in any payload. The
leaks below are therefore *not* the obvious mistake of publishing the dependent's
identifier. They are the surrounding plumbing, which is the harder thing to see.

Two are worth singling out because they are easy to ship by accident:

- **The BBS `header` is a broadcast channel.** The header is bound at signing
  time and must be reproduced verbatim by the verifier, so it travels in clear
  with *every* presentation, forever. Domain-separating it per credential —
  an entirely ordinary-looking engineering choice — makes it a perfect,
  permanent correlator. In the harness it was the single most discriminating
  field in the naive profile: precision 1.00, recall 1.00.
- **Delegation needs a key that links the hops, and that key is the correlator.**
  With plain BBS there is no way to prove "hop 2 was authorised by whoever holds
  hop 1" without disclosing something stable that both hops share.

---

## 2. VERDICT per scenario

### Scenario A — single hop (guardian presents the mandate)

| Composition | Verdict |
|---|---|
| `A-naive` | **FALSIFIED: 7 hard correlators.** The strongest is the BBS `header` (per-credential domain separator); also `credential_id`, `revocation_handle`, exact `valid_until`, `envelope.credentialId`, `credentialStatus.statusListIndex`, `holderKeyId`. A generic clustering adversary with no field allowlist recovered the target's presentations **exactly** (precision 1.00, recall 1.00) from `bbs.header` alone. Under issuer collusion the anonymity set collapses to **1 of 6**. |
| `A-hardened` | **No obvious correlator found in this harness — passes the basic empirical check. This is NOT a soundness proof.** Best single field left is `mandate_scope`, which narrows the target to 4 of 6 (precision 0.40, recall 1.00) — real anonymity-set erosion, not linkage. Under issuer collusion the trial-verification attack yields an anonymity set of **6 of 6**: the issuer, holding every signature, gained nothing. |

### Scenario B — multi-hop (guardian → temporary sub-carer)

| Composition | P1 within hop 2 | (e) cross-hop | (f) attenuation | (g) cascading revocation |
|---|---|---|---|---|
| `B-auditable` | **FALSIFIED** (10 hard correlators) | **FAIL** (7 correlators) | **PASS** | **PASS** |
| `B-unlinkable-stable` | **FALSIFIED** (2 hard correlators) | PASS | **PASS** | **FAIL** |
| `B-unlinkable-fresh` | **No obvious correlator found** | PASS | **FAIL** | **FAIL** |

**Scenario B verdict: FALSIFIED.** No composition tested achieved unlinkability,
attenuation and cascading revocation at the same time. Each of the three columns
can be bought, but only by paying with one of the others.

> **Read (e) carefully.** `B-unlinkable-stable` passes (e) yet is FALSIFIED for
> P1. (e) only asks whether a *guardian* presentation can be tied to a
> *sub-carer* presentation. It passes there only because the paired single-hop
> profile does not disclose `guardian_key` — so the two hops share nothing. The
> sub-carer's own presentations still link perfectly to each other via
> `guardian_key` / `delegator_key` (k = 1). Passing (e) is not passing P1.

---

## 3. The trilemma (the substantive result for Scenario B)

Plain BBS derived proofs give per-credential unlinkability. They do **not** give
delegation. To let hop 2 prove that hop 1 authorised it, the verifier must be
able to tie the two proofs together — and with only selective disclosure
available, "tie together" means "disclose a shared stable value".

Empirically, from the run:

- **Bind the hops with the guardian's key** → the verifier can check attenuation
  (`f2` self-issued broader sub-mandate is rejected: *"sub-mandate delegator key
  != guardian key in the parent mandate"*), but `guardian_key` is constant and
  unique to the dependent (k = 1). P1 falsified.
- **Hide the key, re-issue under a throwaway delegator key** → nothing links the
  presentations (P1 not falsified, (e) passes), but the verifier has no
  authenticated delegator key. Attack **f2 succeeded**: the sub-carer generated
  its own key pair, self-issued a sub-mandate with `sub_scope =
  school_enrolment` (the *parent's* full scope) and `sub_valid_until =
  2027-12-31`, paired it with the honest guardian's hop-1 proof, and the
  verifier **accepted**. Full scope escalation.
- **Ship the parent's status handle so revocation cascades** → (g) passes, but
  the handle is per-credential and permanent: k = 1.

Cascading revocation is the same trade in another guise. Revoking the parent can
only stop hop 2 if the verifier can see *which* parent to check — and that
pointer is precisely the correlator. In the run, `B-auditable` correctly rejected
after revocation; both unlinkable profiles reported *"sub-carer proof STILL
VERIFIES after the parent mandate was revoked"*. The same tension appears in
Scenario A: `A-hardened` also accepts a revoked mandate, because it ships no
status handle at all — its only defence is short validity.

### Delegation transport — a prerequisite problem, before any of the above

Only the guardian holds the parent signature, so hop 2 cannot produce a hop-1
proof by itself. There are three options and two are broken:

| Transport | Result |
|---|---|
| **T1** guardian hands the sub-carer the parent **signature** so it can work offline | **FAIL — escalation succeeded.** The sub-carer is now indistinguishable from the guardian and simply presented the parent mandate at full scope. Attenuation is not weakened, it is absent. |
| **T2** guardian pre-derives one parent proof and hands it over | Rejected by a nonce-checking verifier (*"presentation-header is not a nonce this verifier issued"*), but **accepted by a verifier that does not check nonce freshness**, and the parent proof bytes were **byte-identical across two verifiers** — a hard linkability leak plus a replay primitive for anyone who observes one presentation. |
| **T3** guardian derives a fresh parent proof per presentation | Works. Requires the **guardian to be online at the moment the sub-carer presents** — which defeats much of the point of handing authority to a temporary carer. All Scenario B runs use T3. |

---

## 4. Tables

### 4.1 Scenario A — `A-naive`

| field (path in the payload) | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `bbs.header` | yes | 1 | yes | **Y** |
| `bbs.disclosed[credential_id]` | yes | 1 | yes | **Y** |
| `bbs.disclosed[revocation_handle]` | yes | 1 | yes | **Y** |
| `bbs.disclosed[valid_until]` | yes | 1 | yes | **Y** |
| `envelope.credentialId` | yes | 1 | yes | **Y** |
| `envelope.credentialStatus.statusListIndex` | yes | 1 | yes | **Y** |
| `envelope.holderKeyId` | yes | 1 | yes | **Y** |
| `bbs.disclosed[mandate_scope]` | yes | 4 | yes | partial |
| `bbs.disclosed[type]` | yes | 6 | no | N |
| `bbs.disclosed[issuer_key_id]` | yes | 6 | no | N |
| `bbs.issuerPublicKey` | yes | 6 | no | N |
| `bbs.disclosedIndexes` | yes | 6 | no | N |
| `bbs.totalMessageCount` | yes | 6 | no | N |
| `bbs.proofByteLength` | yes | 6 | no | N |
| `envelope.issuerKeyId` | yes | 6 | no | N |
| `envelope.credentialStatus.statusListCredential` | yes | 6 | no | N |
| `envelope.credentialStatus.type` | yes | 6 | no | N |
| `bbs.presentationHeader` | no | – | no | N |
| `bbs.proof` | no | – | no | N |

- (c) proof randomisation: 21/21 distinct, 2 repeat-visit pairs → **PASS**
- (d) collusion: d1 no, d2 no, **d3 anonymity set 1/1/1 of 6 → LEAK**

### 4.2 Scenario A — `A-hardened`

| field (path in the payload) | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `bbs.disclosed[mandate_scope]` | yes | 4 | yes | partial |
| `bbs.header` | yes | 6 | no | N |
| `bbs.disclosed[valid_until]` | yes | 6 | no | N |
| `bbs.disclosed[type]` | yes | 6 | no | N |
| `bbs.issuerPublicKey` | yes | 6 | no | N |
| `bbs.disclosedIndexes` | yes | 6 | no | N |
| `bbs.totalMessageCount` | yes | 6 | no | N |
| `bbs.proofByteLength` | yes | 6 | no | N |
| `bbs.presentationHeader` | no | – | no | N |
| `bbs.proof` | no | – | no | N |

- (c) proof randomisation: 21/21 distinct, 2 repeat-visit pairs → **PASS**
- (d) collusion: d1 no, d2 no, d3 anonymity set 6/6/6 of 6 → no linkage

### 4.3 Scenario B — `B-auditable` (hard correlators only; full table in the sample output)

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `parent.header` | yes | 1 | yes | **Y** |
| `parent.disclosed[credential_id]` | yes | 1 | yes | **Y** |
| `parent.disclosed[guardian_key]` | yes | 1 | yes | **Y** |
| `parent.disclosed[revocation_handle]` | yes | 1 | yes | **Y** |
| `parent.disclosed[valid_until]` | yes | 1 | yes | **Y** |
| `sub.header` | yes | 1 | yes | **Y** |
| `sub.disclosed[delegator_key]` | yes | 1 | yes | **Y** |
| `sub.disclosed[parent_credential_id]` | yes | 1 | yes | **Y** |
| `sub.disclosed[parent_revocation_handle]` | yes | 1 | yes | **Y** |
| `sub.disclosed[subcarer_key]` | yes | 1 | yes | **Y** |
| `parent.disclosed[mandate_scope]`, `sub.disclosed[sub_scope]` | yes | 4 | yes | partial |
| everything else (type, issuer key, indexes, lengths, `sub_valid_until`) | yes | 6 | no | N |
| `*.presentationHeader`, `*.proof` | no | – | no | N |

- (c) 32/32 proofs distinct → **PASS**; (d) **d3 anonymity set 1/1/1 of 6 → LEAK**

### 4.4 Scenario B — `B-unlinkable-stable`

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `parent.disclosed[guardian_key]` | yes | 1 | yes | **Y** |
| `sub.disclosed[delegator_key]` | yes | 1 | yes | **Y** |
| `parent.disclosed[mandate_scope]`, `sub.disclosed[sub_scope]` | yes | 4 | yes | partial |
| `parent.header`, `sub.header`, `*.valid_until`, `*.type`, issuer key, indexes, lengths | yes | 6 | no | N |
| `*.presentationHeader`, `*.proof` | no | – | no | N |

- (c) 32/32 distinct → **PASS**; (d) d3 anonymity set 6/6/6 of 6 → no linkage
- The two hard correlators are the *same key material* under two names — which is
  exactly what makes hop binding possible.

### 4.5 Scenario B — `B-unlinkable-fresh`

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `parent.disclosed[mandate_scope]`, `sub.disclosed[sub_scope]` | yes | 4 | yes | partial |
| `parent.header`, `sub.header`, `*.valid_until`, `*.type`, issuer key, indexes, lengths | yes | 6 | no | N |
| `sub.delegatorPublicKey`, `*.presentationHeader`, `*.proof` | no | – | no | N |

- (c) 32/32 distinct → **PASS**; (d) d3 anonymity set 6/6/6 of 6 → no linkage
- No k = 1 correlator — and no attenuation either (see f2 below).

### 4.6 (e) Cross-hop unlinkability

| pairing | result | detail |
|---|---|---|
| `A-naive` × `B-auditable` | **FAIL** | 7 hard cross-hop correlators, each present in *every* presentation on both sides: the parent credential id (as `credential_id=` in hop 1 and inside `parent.header` in hop 2), the revocation handle, and the exact `valid_until` |
| `A-hardened` × `B-unlinkable-stable` | **PASS** | only cohort-wide atoms shared (issuer key, header, `type`, bucketed expiry); `mandate_scope` narrows to 4/6 |
| `A-hardened` × `B-unlinkable-fresh` | **PASS** | same |

### 4.7 (f) Attenuation — active escalation attempts

| chain profile | attack | accepted? | result |
|---|---|---|---|
| all three | f1 rewrite the disclosed `sub_scope` value | no | PASS — *hop 2 proof failed to verify* |
| all three | f3 substitute a different signed attribute at the scope index | no | PASS — *hop 2 proof failed to verify* |
| all three | f4 baseline: honest presentation at the delegated scope | yes | PASS |
| `auditable` | f2 sub-carer self-issues a broader sub-mandate under its own key | no | PASS — *delegator key != guardian key* |
| `unlinkableStable` | f2 (same) | no | PASS — *delegator key != guardian key* |
| **`unlinkableFresh`** | **f2 (same)** | **YES** | **FAIL — escalation succeeded** |
| — | T1 guardian shares the parent signature | **YES** | **FAIL — sub-carer presents the full parent mandate** |
| — | T2 static pre-derived parent proof | no (strict verifier) | PASS against a nonce-checking verifier; accepted by a lax one, and proof bytes identical across verifiers |

**(f) overall: FAIL** — one escalation succeeded (`unlinkableFresh` / f2), plus the
T1 transport failure which applies regardless of profile.

### 4.8 (g) Cascading revocation

| chain profile | ok before revocation | still accepted after | result |
|---|---|---|---|
| `auditable` | yes | no | **PASS** — *parent mandate is revoked* |
| `unlinkableStable` | yes | **YES** | **FAIL** |
| `unlinkableFresh` | yes | **YES** | **FAIL** |

Context, single hop: `A-naive` correctly rejects a revoked mandate; `A-hardened`
**accepts** it, because it ships no status handle.

---

## 5. Limitations — what this harness does NOT establish

Read this section before quoting any verdict above.

1. **It does not prove unlinkability.** "No obvious correlator found" means this
   checker's tests did not fire on this corpus. Testing finds leaks; it cannot
   establish their absence.
2. **It finds structural correlators only.** Exact-match comparison over payload
   fields, plus path-agnostic atom matching for cross-hop. It does **not** cover
   subtle statistical correlation, traffic analysis, timing, ordering, message
   sizes as a side channel, browser/device fingerprinting, IP-level linkage, or
   any behavioural correlation. In a real deployment those are likely to dominate.
3. **Cross-hop matching ignores fragments shorter than 8 characters**, so a
   low-entropy cross-hop correlator would be missed there (the per-scenario field
   tables cover that case within a scenario).
4. **The functional checks are not security proofs.** (f) attenuation and (g)
   cascading revocation ran four and two concrete attacks respectively. A passing
   functional check means "these attacks failed", not "no attack exists". In
   particular we do **not** prove attenuation soundness for multi-hop delegation.
5. **Issuer–verifier collusion is only partially modelled.** The issuer
   contributed its signatures, all signed messages including withheld ones, all
   headers, and the credential→dependent map, and we ran a trial-verification
   attack with them. We did **not** model a malicious issuer that *tags*
   credentials at issuance (e.g. per-holder ciphersuite parameters, deliberately
   skewed attribute values, unique message counts, or a covert channel in the
   header) — a tagging issuer defeats all of this trivially and is a policy /
   governance problem, not a protocol one.
6. **Cohort size 6 is a toy.** Anonymity-set numbers are illustrative of the
   mechanism, not of a real deployment's privacy.
7. **The unlinkability↔auditability tension is not addressed.** A guardian's
   actions may need to be auditable for accountability while unlinkable to RPs.
   Nothing here tests whether an accountable-but-unlinkable construction exists.
8. **Gap to the full W3C cryptosuite.** We use the BBS scheme directly, not
   `bbs-2023` from *W3C Data Integrity BBS Cryptosuites v1.0*. JSON-LD
   canonicalisation, mandatory pointers, `baseProof`/`derivedProof` encoding and
   `@context` handling are all untested — and the cryptosuite's
   *mandatory-disclosed* statements are constant across derived proofs by
   construction, i.e. exactly the class of leak this harness hunts. Re-running
   these checks against the cryptosuite is the highest-value next step.
9. **We do not verify the library's correctness.** We assume
   `@digitalbazaar/bbs-signatures` correctly implements the IETF draft, and we
   assume the underlying BBS scheme's proof unlinkability. Neither was audited here.
10. **Scope realism.** In the motivating school-enrolment case the verifier
    learns the child's identity anyway, out of band. P1 is only meaningful for
    relying parties that genuinely do not need to know *which* dependent — a
    scoping point the protocol text should make explicitly.

---

## 6. Questions to escalate to a cryptographer

1. **Delegation without a linking key.** Is there a construction, using only
   standardised primitives, that lets a verifier check "hop 2 was authorised by
   the holder of hop 1" *without* either hop disclosing a value that is stable
   across presentations? Do BBS blind signatures, proof-of-equality of committed
   values, or the per-verifier-linkability / pseudonym BBS drafts close this, or
   is delegated anonymous credentials (a different, heavier construction) the
   honest answer?
2. **Multi-hop attenuation soundness.** Our functional check shows the sub-carer
   cannot widen a *bound* chain. Is attenuation actually *sound* — can a
   colluding guardian and sub-carer produce a chain the verifier accepts at a
   scope the issuer never granted? Under what assumptions is scope containment
   enforceable when the parent credential is not fully disclosed?
3. **Cross-hop collusion.** Under full issuer + multi-verifier collusion across
   both hops, is `B-unlinkable-fresh`-style hiding actually unlinkable, or does
   the issuer's knowledge of the parent signature give an oracle we did not
   construct? Our trial-verification attack found none — is there a better one?
4. **The `header` as a covert/necessary channel.** The BBS `header` must be
   reproduced by the verifier, so it is public and constant per credential. Is
   cohort-wide domain separation (our `A-hardened` choice) sound, or does it
   create issues elsewhere — replay across credentials, cross-protocol confusion,
   weakened domain separation? What is the minimum safe header content?
5. **Revocation privacy vs. cascading revocation.** Is there a privacy-preserving
   status mechanism compatible with BBS derived proofs where the verifier learns
   "the parent is not revoked" without learning *which* parent? Do unlinkable
   revocation lists / accumulator-based schemes actually compose here, and do
   they survive the multi-hop case?
6. **Short-lived credentials as a revocation substitute.** If we drop status
   handles entirely and rely on short validity plus re-issuance, what is the
   privacy cost of the re-issuance channel itself (the issuer sees a request
   rate per dependent), and what epoch length keeps the cohort large enough to
   matter?
7. **Accountable-but-unlinkable.** Is there a sound construction giving audit
   capability to an authorised auditor while remaining unlinkable to relying
   parties, or is this an inherent tension that must be stated as a design limit?
8. **Minimum viable subset.** Given the above, which subset of P1–P4 is soundly
   achievable *today* with BBS + VCDM 2.0 + an EUDI mandate attestation, and what
   must v1 explicitly scope out as future work?

---

## 7. What this means for the design, in one paragraph

Single-hop P1 looks achievable with standardised primitives, but only if the
composition is disciplined in ways that are easy to get wrong: nothing
per-credential in the BBS `header`, no credential id, no per-credential status
handle, expiry bucketed to a cohort-wide epoch — and revocation consequently
degraded to short validity. Multi-hop is a different matter. In this harness no
composition delivered unlinkability, attenuation and cascading revocation
simultaneously; each was obtainable only at the cost of another, and the
delegation transport problem (only the guardian holds the parent signature) bites
before any of that. On the evidence here, **v1 should ship single-hop and name
multi-hop delegation as open work** pending question 1 above.
