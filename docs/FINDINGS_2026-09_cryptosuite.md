# FINDINGS — P1 re-run against the full W3C `bbs-2023` cryptosuite (2026-09)

This closes the gap named in [FINDINGS_2026-08 §5.8](FINDINGS_2026-08.md): the
first run tested the raw IETF BBS scheme, not the W3C Data Integrity cryptosuite
that a real deployment would use. Here the **same checks** run against genuine
`bbs-2023` base and derived proofs over VCDM 2.0 JSON-LD credentials.

It is still a **falsification attempt**. "No obvious correlator found" is not a
proof of anything.

| | |
|---|---|
| **Spec consulted** | W3C *Data Integrity BBS Cryptosuites v1.0*, Candidate Recommendation Draft, **10 September 2026** |
| **Feature exercised** | `bbs-2023` **baseline** only (derived-proof CBOR tag `d9 5d 03`, which matches the baseline tag in that draft). Anonymous holder binding and pseudonyms are **not** implemented by the library and **not** tested. |
| **Cryptosuite** | `@digitalbazaar/bbs-2023-cryptosuite` **2.0.1** (released 2024-08-26) |
| **Stack** | `@digitalbazaar/data-integrity` 2.5.0 · `@digitalbazaar/vc` 7.3.0 · `@digitalbazaar/di-sd-primitives` 3.3.0 · `@digitalbazaar/bls12-381-multikey` 2.2.0 · `jsonld` 9.0.0 · `rdf-canonize` 5.0.0 — all pinned |
| **BBS underneath** | `@digitalbazaar/bbs-signatures` **3.1.0**, the same version as the raw run, so the BBS maths is identical and the comparison is clean |
| **Population** | 6 dependents (target `dep:Y` + 5 decoys), 4 relying parties; target presents 6× (4 RPs, 2 repeat visits), decoys 3× each — the same plan as the raw run |
| **Verification** | every one of the 84 presentations verified with `@digitalbazaar/vc` `verifyCredential` before analysis (21/21 per policy) |
| **Runtime** | 195 s for the full cryptosuite run (Monte Carlo included) on a laptop |
| **Raw output** | [`harness/sample-output/cryptosuite-output.txt`](../harness/sample-output/cryptosuite-output.txt) and [`.json`](../harness/sample-output/cryptosuite-output.json) — both from the same run |
| **Reproduce** | `cd harness && npm install && npm run cryptosuite` |

**What the checker sees.** For each presentation, the derived credential exactly
as a verifier receives it (`@context`, `id`, claims, `proof` object), **plus** the
contents of `proof.proofValue` decoded, which every verifier must parse to
verify anyway: `bbsProof`, `labelMap`, `mandatoryIndexes`, `selectiveIndexes`,
`presentationHeader`. It also sees the canonical N-Quads the verifier
reconstructs, including the mandatory statements and their hash. Rows prefixed
`decoded.` in the tables are only visible after that parsing step. This matters:
compared as an opaque string, `proofValue` is unique on every presentation (it
embeds the randomised BBS proof), and a checker that stopped there would have
reported nothing.

---

## 1. Headline

**The cryptosuite layer adds its own correlators, and every requested
`mandatoryPointers` policy is falsified.** No per-credential value needs to be
mandatory for this to happen.

The leak does not come from what the issuer *chooses* to make mandatory. It
comes from two mechanisms that apply regardless:

1. **Node `id`s on a selected path are always revealed.** The selection
   algorithm copies the `id` of every object along a disclosed JSON pointer
   (`di-sd-primitives/lib/select.js:122`). A credential with a per-credential
   `id` leaks it on every presentation, even with **zero** mandatory pointers.
   `C-minimal` was falsified by exactly this (k = 1, deterministic).
2. **The HMAC blank-node shuffle is a per-credential tag.** `bbs-2023` relabels
   blank nodes by ranking them under a per-credential HMAC key. The resulting
   `labelMap` and the `selectiveIndexes`/`mandatoryIndexes` that depend on it
   are identical on every presentation of one credential and differ between
   credentials. With the nested credential shape of `C-hardened`, where every
   disclosed *value* is cohort-wide, the target was exactly linkable in
   **26 of 30** freshly issued cohorts (87%; 27/30 and 24/30 in two earlier
   runs). Under issuer collusion the issuer, which holds the HMAC key, pinned
   **every** presentation to `dep:Y` by name.

A **mitigation candidate** that follows from probe (k) survived all checks: a
credential with **exactly one blank node** (flat subject, epoch-scoped
credential `id`), 0/30 cohorts linkable. It has real costs (§5), and it was not
one of the three policies originally requested.

The randomised BBS proof itself held again: 21/21 distinct proofs in every
policy, no base-proof material (signature, header, HMAC key) reappeared in any
presentation, and no withheld claim value surfaced.

---

## 2. VERDICT per pointer policy

| Policy | `mandatoryPointers` | Verdict |
|---|---|---|
| **C-naive** | `/issuer`, `/validUntil`, `/credentialStatus` | **FALSIFIED via the auto-revealed credential `id`, the status entry (`credentialStatus.id`, `statusListIndex`), exact `validUntil`, and `mandatoryHash`** (all k = 1, deterministic). Issuer collusion: anonymity set 1/6. |
| **C-minimal** | *(none — the cryptosuite minimum)* | **FALSIFIED via the auto-revealed credential `id`** (k = 1, deterministic), with no mandatory pointer at all. The HMAC tag adds more (`labelMap` k = 2, `selectiveIndexes` k = 2). Issuer collusion: 1/6, including from the proof-internal parts alone. |
| **C-hardened** | `/issuer`, epoch-bucketed `/validUntil`; no `id`, no status | **FALSIFIED via the HMAC blank-node label tag.** In the committed run `labelMap`, `selectiveIndexes`, `mandatoryIndexes`, `mandatoryHash` and the blank-node ranks each reached k = 1. Over **30 fresh cohorts** the target was exactly linkable in **26/30 (87%)**. Issuer collusion: 1/6 on every presentation. Every disclosed *value* in this policy is cohort-wide. |
| *C-hardened+flat* (mitigation candidate, not requested) | `/issuer`, epoch-bucketed `/validUntil`; 1 blank node, epoch-scoped `id` | **No obvious correlator found in this harness — passes the basic empirical check. This is NOT a soundness proof.** 0/30 cohorts linkable; best remaining field is the scope (4/6, as in the raw run). Issuer collusion: 4/6 (scope only). |

**Cross-hop (e), optional Scenario B probe.** The guardian's own presentation
(scope) was compared with the parent-mandate proof inside a sub-carer chain
(scope + `guardianKey`, as in B-unlinkable-stable):

| Credential shape | Result | |
|---|---|---|
| nested (`C-hardened`) | **FAIL** | linkable across hops in **15/20** cohorts (75%); single atom `Guardian@b2` reached k = 1 in the committed cohort |
| flat, one blank node | PASS | 0/20 |

The raw run reported **PASS** for this pairing ([FINDINGS_2026-08 §4.6](FINDINGS_2026-08.md)).
The cryptosuite turns it into a FAIL for the nested shape. A blank node's HMAC
rank is fixed for the whole credential, so it matches across hops **even though
the two hops disclose different fields**. (f) and (g) were not re-run; they
concern delegation structure, not the cryptosuite.

---

## 3. What the cryptosuite changes, mechanism by mechanism

### (h) Mandatory-disclosed statements

- **C-naive:** all 9 mandatory N-Quads have k = 1, because every one has a
  per-credential IRI as its subject: the credential `id` (5 quads) or the status
  entry's `id` (4 quads). So `mandatoryHash` is a k = 1 tag too.
- **C-hardened:** all 4 mandatory N-Quads carry only **cohort-wide values**
  (types, issuer, epoch expiry), yet each has k = 1. Their subject is the
  credential's root **blank node**, whose HMAC-assigned label (`_:bN`) differs
  per credential. **Making every mandatory value cohort-wide is not enough.**
  The blank-node label inside the mandatory statements carries the tag.
- **C-hardened+flat:** with one blank node its label is always `_:b0`, and all
  4 mandatory N-Quads fall to k = 6.

### (i) Proof object

Clean in every policy: `type`, `cryptosuite`, `proofPurpose` and
`verificationMethod` are cohort-wide (single issuer key). There is **no
`created`** (the library deletes it at signing, `bbs-2023-cryptosuite/lib/sign.js`)
and no proof `id`. That is an implementation choice, so the profile should
still forbid them (§5). `proofValueByteLength` varies only with the verifier's
nonce length, which is a verifier artefact.

### (j) Document structure

Cohort-wide in every policy: `@context`, document shape, number of revealed
statements, `bbsProofByteLength`. **This is only because every credential in
the cohort has an identical schema.** The BBS proof length encodes the number of
undisclosed messages, so optional fields would break it (spec §6.2.1).

### (k) HMAC label replacement

The HMAC outputs themselves never appear. Their *ranking* does, and it repeats
exactly on every presentation of one credential (unit-tested). Monte Carlo over
30 issuances of **identical claims**, where only the library-drawn HMAC key
differs:

| credential shape | N blank nodes | m revealed | distinct tags / 30 | theory N!/(N−m)! | spec §6.2.2 C(N,m) | bits |
|---|---|---|---|---|---|---|
| S1 nested + per-credential `id` (naive/minimal) | 3 | 2 | 6 | 6 | 3 | 2.58 |
| S2 nested, no `id` (hardened) | 4 | 3 | 17 | 24 | 4 | 4.58 |
| S3 flat, no `id` | 2 | 2 | 2 | 2 | 1 | 1.00 |
| S4 flat + epoch-scoped `id` | 1 | 1 | 1 | 1 | 1 | 0 |

17 distinct values in 30 draws is what a uniform distribution over 24 values
predicts (expected ≈ 17.3). A space of 4 values could never produce it.

**Ordering side channel.** Two credentials differing **only** in a hidden
sibling inside a multi-valued property (`scope: ["school_enrolment", X]`,
disclosing the first) produced **identical revealed documents** but
deterministically different `selectiveIndexes`: `[0,2,6]` for X =
`aaa_hidden_scope` and `[0,2,5]` for X = `zzz_hidden_scope`. The index of a
revealed statement leaks how undisclosed values sort relative to it.

### (d) Issuer collusion reverses

In the raw run the issuer, holding every signature, **gained nothing** against
the hardened profile: its anonymity set was 6/6. Under `bbs-2023` the issuer
holds each credential's HMAC key (it generated it). It can re-derive every
credential it issued with the profile's pointers and match the non-random parts
of any presentation. For naive, minimal and hardened: **anonymity set 1/6 on all
six target presentations, each pinned to `dep:Y` by name.** Only the one-blank-node
shape resists: 6/6 on proof-internal parts, 4/6 overall (scope).

---

## 4. Tables

k = number of distinct dependents in the corpus sharing the target's value (k = 1
is exact linkage; k = 6 is no narrowing). "–" = varies per presentation.

### 4.1 C-naive — `mandatoryPointers: /issuer, /validUntil, /credentialStatus`

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `id` *(never selected — auto-revealed)* | yes | 1 | yes | **Y** |
| `validUntil` | yes | 1 | yes | **Y** |
| `credentialStatus.id` | yes | 1 | yes | **Y** |
| `credentialStatus.statusListIndex` | yes | 1 | yes | **Y** |
| `decoded.mandatoryNQuads` | yes | 1 | yes | **Y** |
| `decoded.mandatoryHash` | yes | 1 | yes | **Y** |
| `decoded.labelMap` | yes | 3 | yes | partial |
| `decoded.selectiveIndexes` | yes | 3 | yes | partial |
| `decoded.bnodeRank.Mandate` | yes | 3 | yes | partial |
| `decoded.bnodeRank.Guardian` | yes | 4 | yes | partial |
| `credentialSubject.mandate.scope` | yes | 4 | yes | partial |
| `issuer`, `@context`, `type`, `credentialStatus.{type,statusPurpose,statusListCredential}`, `credentialSubject.type`, `credentialSubject.mandate.type` | yes | 6 | no | N |
| `proof.{type,cryptosuite,proofPurpose,verificationMethod}`, `decoded.cborTag` | yes | 6 | no | N |
| `decoded.{mandatoryIndexes,mandatoryNQuadCount,revealedNQuadCount,labelMapSize,documentShape,bbsProofByteLength}` | yes | 6 | no | N |
| `proof.proofValue`, `decoded.bbsProof`, `decoded.presentationHeader`, `decoded.proofValueByteLength` | no | – | no | N |

(c) 21/21 distinct · clustering: `id` alone gives precision 1.00 / recall 1.00 ·
conjunction: exact linkage · d1 no · d2 no · **d3 1/6** · d3b (proof parts only) 3/6 ·
revocation enforced (status disclosed).

### 4.2 C-minimal — `mandatoryPointers: []`

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `id` *(never selected — auto-revealed)* | yes | 1 | yes | **Y** |
| `decoded.labelMap` | yes | 2 | yes | partial |
| `decoded.selectiveIndexes` | yes | 2 | yes | partial |
| `decoded.bnodeRank.Mandate` | yes | 2 | yes | partial |
| `decoded.bnodeRank.Guardian` | yes | 3 | yes | partial |
| `credentialSubject.mandate.scope` | yes | 4 | yes | partial |
| `issuer`, `@context`, `type`, subject/mandate `type`, all `proof.*` except `proofValue` | yes | 6 | no | N |
| `decoded.{mandatoryHash,mandatoryNQuads,mandatoryIndexes,…counts,shape,cborTag}` | yes | 6 | no | N |
| `proof.proofValue`, `decoded.{bbsProof,presentationHeader,proofValueByteLength}` | no | – | no | N |

(c) 21/21 · clustering: `id` 1.00/1.00 · conjunction: exact · d1 no · d2 no ·
**d3 1/6** · **d3b 1/6** · revoked credential **still accepted** (status entry exists but is not disclosed).

### 4.3 C-hardened — `mandatoryPointers: /issuer, /validUntil` (epoch-bucketed), no `id`, no status

| field | constant? | k | correlatable? | leak |
|---|---|---|---|---|
| `decoded.labelMap` | yes | 1 | yes | **Y** |
| `decoded.selectiveIndexes` | yes | 1 | yes | **Y** |
| `decoded.mandatoryIndexes` | yes | 1 | yes | **Y** |
| `decoded.mandatoryNQuads` | yes | 1 | yes | **Y** |
| `decoded.mandatoryHash` | yes | 1 | yes | **Y** |
| `decoded.bnodeRank.Mandate` | yes | 1 | yes | **Y** |
| `decoded.bnodeRank.GuardianshipMandateCredential+VerifiableCredential` | yes | 1 | yes | **Y** |
| `decoded.bnodeRank.Guardian` | yes | 2 | yes | partial |
| `credentialSubject.mandate.scope` | yes | 4 | yes | partial |
| `issuer`, `validUntil` (epoch), `@context`, `type`, subject/mandate `type`, `proof.*` except `proofValue` | yes | 6 | no | N |
| `decoded.{mandatoryNQuadCount,revealedNQuadCount,labelMapSize,documentShape,bbsProofByteLength,cborTag}` | yes | 6 | no | N |
| `proof.proofValue`, `decoded.{bbsProof,presentationHeader,proofValueByteLength}` | no | – | no | N |

(c) 21/21 · clustering: `decoded.labelMap` 1.00/1.00 · conjunction: exact ·
**cohort Monte Carlo 26/30** · d1 no · d2 no · **d3 1/6** · **d3b 1/6** · revoked
credential accepted (no status entry by design). The k = 1 rows vary run to run;
the Monte Carlo figure is the stable one.

### 4.4 C-hardened+flat (mitigation candidate)

Every row is k = 6 (no narrowing) **except** `credentialSubject.scope` (k = 4,
partial, the same as the raw run) and the per-presentation random fields.
`labelMap`, both index lists, `mandatoryHash`, the mandatory N-Quads and the
blank-node rank are all cohort-wide. The epoch-scoped `id` is revealed but shared
by the whole cohort (k = 6).

(c) 21/21 · clustering best field: scope, 0.40/1.00 · conjunction: no exact
linkage (4 dependents in the group) · cohort Monte Carlo **0/30** · d3 4/6 · d3b 6/6.

---

## 5. Implications for the Kinship-Caps profile

The main result is that **a `mandatoryPointers` policy alone cannot deliver P1
under `bbs-2023`**. Credential *shape* matters as much. The profile therefore
has to constrain the issuer's credential design as well as its pointers.

**MUST**

1. **At most one blank node in the entire credential.** In practice: a flat
   `credentialSubject` with no nested objects, and a root that is not a second
   blank node. Rationale: §3(k). N!/(N−m)! must equal 1, and the only way to
   guarantee that is N = 1.
2. **No per-credential or per-subject node `id` anywhere on a disclosable
   path.** That covers the root credential `id`, `credentialSubject.id` (a
   holder DID) and nested ids. They are revealed whether or not any pointer
   selects them. If a root `id` is needed to satisfy rule 1, it must be
   **cohort-scoped** (e.g. per issuance epoch) — see the costs below.
3. **Mandatory pointers resolve only to cohort-wide values:** `/issuer` and a
   `/validUntil` bucketed to the issuance epoch. `type` and `@context` are
   revealed anyway.
4. **Fixed schema, all fields always present,** so the number of signed
   statements (visible through the BBS proof length and the index lists) is
   identical across the cohort (spec §6.2.1).
5. **Single-valued properties only for anything a holder may partially
   disclose.** One scope per credential, not a scope array (§3, ordering side
   channel).

**MUST NOT**

- mandatory `/credentialStatus` with a per-credential index, `/id`, `/validFrom`,
  an exact `/validUntil`, or any pointer under `/credentialSubject` whose value
  varies per subject;
- `proof.created`, `proof.id`, `proof.expires` or any other per-credential proof
  option. The tested library already omits `created`; other implementations may
  not (spec §6.2.4).

**Costs the profile must state honestly**

- A cohort-scoped credential `id` violates the usual expectation that an `id`
  identifies one credential. RDF stores that merge graphs would merge every
  mandate of an epoch into one node. The alternative, a flat subject with no
  `id` (S3), leaves **1 bit** per credential (2 equiprobable tags).
- As in the raw run, **revocation degrades to short validity.** A disclosed
  per-credential status entry is a k = 1 correlator (C-naive), and an undisclosed
  one is useless (C-minimal accepted a revoked credential).
- The flat shape was **not falsified in this harness, and that is all.** See §6.

---

## 6. Comparison with the raw-scheme run (FINDINGS_2026-08)

| | raw scheme (2026-08) | `bbs-2023` (this run) |
|---|---|---|
| BBS proof randomisation | PASS | PASS (same `bbs-signatures` 3.1.0 underneath) |
| Per-credential BBS `header` | **leaked in clear** (naive) | **gone as a field.** The header is now `proofHash ‖ mandatoryHash`, recomputed by the verifier. Its per-credential content moved into the mandatory statements (values *and* blank-node labels) |
| Credential `id` | leaked only when we chose to disclose it | **leaks automatically** whenever it exists (selection includes node ids) |
| HMAC blank-node label tag | n/a | **new:** per-credential constant, log2(N!/(N−m)!) bits |
| Index lists | cohort-wide (fixed schema positions) | **new:** per-credential (depend on the HMAC ranking) and leak the ordering of hidden values |
| Hardened profile, verifiers only | not falsified | **FALSIFIED** (26/30 cohorts) |
| Hardened profile, issuer collusion | issuer anonymity set 6/6 | **issuer anonymity set 1/6** |
| Cross-hop (e), hardened × stable | PASS | **FAIL** (15/20 cohorts) for the nested shape; PASS for the flat shape |
| Proof timestamp (`created`) | n/a | absent (the library strips it) |
| Scope | partial, k = 4 | partial, k = 4 (unchanged) |
| Revocation trade-off | disclose status → linkable; omit → unrevocable | identical |

**Net effect:** the cryptosuite removed one leak (the header broadcast) and
introduced three (auto-revealed ids, the HMAC tag, the ordering channel). One of
them, the HMAC tag, cannot be fixed with pointer choices, only with credential
shape.

---

## 7. Relationship to the spec

All three leak classes are **acknowledged qualitatively** in the 10 Sep 2026 CR
Draft: §6.2.1 (index values of revealed statements, total message count),
§6.2.2 (the HMAC shuffle "can leave a fingerprint"), §6.2.3 (node identifiers)
and §6.2.4 (proof options and mandatory reveal). This run is an **empirical
confirmation and quantification**, not a discovery of something the spec
ignores.

**One quantitative discrepancy is worth raising.** §6.2.2 states that "given *n*
blank nodes and *k* disclosed indexes in the worst case this would be a reduction
in the anonymity set size by a factor of *C(n, k)*." We measured the number of
distinct tags as **n!/(n−m)!** (ordered injections, m = revealed blank nodes),
not C(n, m):

- n = 2, m = 2: the formula gives **1** (no fingerprint); we measured **2** equiprobable tags.
- n = 4, m = 3: the formula gives **4**; we measured **17 distinct in 30 draws**, consistent only with ~24.

The reason: `labelMap` reveals *which* canonical node maps to *which* HMAC rank,
not merely which subset of ranks is revealed. If "k disclosed indexes" in the
spec means the number of disclosed *statements* rather than blank nodes, then
C(n, k) is not defined for the common case k > n. Under either reading the
stated worst case understates what we measured. **Caveat:** this rests on one
implementation (§8.1), and the spec's intended reading of *k* should be
confirmed with its editors before the claim is published as fact.

---

## 8. Limitations

Everything in [FINDINGS_2026-08 §5](FINDINGS_2026-08.md) still applies: structural
correlators only, no timing, traffic or behavioural analysis, a 6-member toy
cohort, functional checks are not proofs, no tagging-issuer model. In addition:

1. **One implementation, and an older one.** `@digitalbazaar/bbs-2023-cryptosuite`
   2.0.1 was released 2024-08-26 and predates the CR drafts published since.
   We checked that its derived-proof tag matches the current baseline tag. We
   did **not** reconcile its label-shuffle and index algorithms line by line
   against the 10 Sep 2026 draft. A conforming implementation of a later draft
   could behave differently.
2. **Baseline feature only.** Anonymous holder binding (`d9 5d 05`) and
   pseudonyms (`d9 5d 07`, `d9 5d 09`) are untested. Pseudonyms in particular are
   designed around per-verifier linkability and need their own run.
3. **Not seedable.** The library draws each credential's HMAC key internally.
   Single-cohort k values for HMAC-derived rows change between runs. The stable
   figures are the Monte Carlo ones, and those are small samples: 26/30 has a
   95% interval of roughly 70–96%; 0/30 bounds the linkage rate below ~12%, not
   at zero.
4. **Network-side channels are out of scope.** The document loader is offline.
   In a real deployment a verifier dereferencing the issuer's `@context`, the
   `verificationMethod` controller document or a status list is itself a
   potential tracking channel (towards the host of those URLs). Untested.
5. **JSON-LD-level attacks** (context substitution, `@protected` bypasses,
   term-redefinition tricks by a malicious verifier or issuer) are untested.
6. **Uniform cohort.** All credentials share one schema. Real populations with
   optional fields would additionally leak via message count and index
   positions (§3j). We did not measure how much.
7. **Scenario B is partial.** Only cross-hop (e) was re-run, for two credential
   shapes. Attenuation (f), cascading revocation (g) and the delegation
   transports are unchanged by the cryptosuite and were not repeated.
8. **The mitigation is evidence, not a recommendation from a cryptographer.**
   "One blank node" removes the channel we measured. It does not show there is
   no other one.

---

## 9. Questions to add to the cryptographer / W3C escalation list

1. **§6.2.2 bound.** Is C(n, k) intended to bound the `labelMap` fingerprint? Our
   measurement is n!/(n−m)!, and for n = m = 2 the formula predicts no reduction
   where we see one bit.
2. **Can the label map be per-presentation?** Is there a construction within
   standard BBS (no new cryptography) in which the revealed blank-node labels
   are re-randomised per presentation while the verifier can still recompute
   `mandatoryHash`? If not, is "at most one blank node" the only mitigation, and
   should the spec say so normatively for unlinkability use cases?
3. **Selective-index ordering.** Should the spec recommend a canonical placement
   or padding of revealed messages so that `selectiveIndexes` cannot rank hidden
   values against revealed ones?
4. **Auto-revealed node ids.** Should §6.2.3 state explicitly that `id`s on any
   selected path are disclosed regardless of mandatory pointers? That is not
   obvious to someone designing a pointer policy.
5. **Issuer collusion under `bbs-2023`.** The issuer knows every HMAC key.
   Beyond credential-shape constraints, is there a sound way to keep the
   holder's label shuffle secret from the issuer, or is issuer-side linkage
   inherent to the baseline feature, with pseudonyms / holder binding as the
   only answer?
