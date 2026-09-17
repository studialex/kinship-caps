# open-core-p1-harness

A small, reproducible harness that tries to **falsify** one privacy claim from the
Kinship-Caps guardianship-delegation design:

> **P1 — repeat-presentation unlinkability.** When a guardian presents a mandate
> ("I am authorised to act for dependent Y, scope = Z") to multiple verifiers,
> those verifiers — even colluding with each other and with the issuer — must not
> be able to link Y's presentations to each other.

This is a **falsification attempt, not a proof**. A green result here means
"this harness found no structural correlator", nothing stronger. See
[`docs/FINDINGS_2026-08.md`](../docs/FINDINGS_2026-08.md) for the results, the verdicts, and the explicit limits.

## Run it

From this directory (`harness/`):

```bash
npm install && npm test
```

`npm test` runs the unit tests for the harness itself and then the full
falsification run. To run only the linkability check:

```bash
npm run linkability
```

Machine-readable output:

```bash
npm run linkability:json
```

Runtime is roughly 50–70 s on a laptop (~350 BLS12-381 pairings-based operations
in pure JS). Node ≥ 20, no native build step, one dependency.

Committed sample output: [`sample-output/run-output.txt`](sample-output/run-output.txt)
and [`sample-output/run-output.json`](sample-output/run-output.json).

**The results of this harness are documented in
[`../docs/FINDINGS_2026-08.md`](../docs/FINDINGS_2026-08.md)** — that file is the
canonical write-up (verdicts, leak tables, limitations, open questions).

## The primitive (chosen, not assumed)

| | |
|---|---|
| Library | [`@digitalbazaar/bbs-signatures`](https://github.com/digitalbazaar/bbs-signatures) **3.1.0** (pinned) |
| Spec | IETF `draft-irtf-cfrg-bbs-signatures-06` (the draft the library's internals are named after) |
| Ciphersuite | `BLS12-381-SHA-256` |
| Maintained? | latest release published 2026-06-02; maintained by Digital Bazaar, who also author the W3C Data Integrity BBS cryptosuite |
| Capabilities verified before committing | multi-attribute `sign`, `deriveProof` over a **subset** of messages, `verifyProof`, and randomised (non-deterministic) derived proofs |

**Why this one.** It is the lowest-level maintained JS implementation that
exposes `deriveProof`/`verifyProof` directly, which is exactly what the harness
needs: the checker must see *the raw presentation payload*, not a JSON-LD
document that a cryptosuite has already normalised.

**Gap to the full W3C cryptosuite (stated explicitly).** We use the BBS scheme
directly, not `bbs-2023` from *W3C Data Integrity BBS Cryptosuites v1.0*. So this
harness does **not** exercise JSON-LD canonicalisation, the mandatory-pointers
mechanism, `baseProof`/`derivedProof` encoding, or `@context` handling. That
matters, because the cryptosuite adds its own structures — in particular
*mandatory-disclosed* statements, which are constant across every derived proof
of a credential by construction. Those are exactly the kind of thing this harness
is designed to catch, and they are **out of scope here**. Re-running the same
checks against `@digitalbazaar/bbs-2023-cryptosuite` is the obvious next step.

We implement **no cryptography**. `src/bbs.js` is a thin forwarding wrapper; every
cryptographic operation is a call into the library.

## What the harness does

1. **Mock issuer** signs a guardianship mandate with attributes
   `type, dependent_id, mandate_scope, valid_until, guardian_key, issuer_key_id,
   revocation_handle, credential_id`.
2. **Cohort.** The same issuer issues mandates to **six** dependents (target
   `dep:Y` plus five decoys with overlapping scopes). Decoys are load-bearing:
   without them you cannot tell a value that is *constant* from a value that is
   *identifying*.
3. **Presentations.** The target presents **six** times — to four different
   relying parties, and twice each to two of them. Decoys present three times each.
4. **The checker** (`src/harness.js`) receives only the payloads and reports, per
   field: constant? · anonymity set *k* · correlatable? · leak.

### Composition profiles

The BBS maths is identical in every profile. What differs is *our* composition
around it — that is the thing actually under test.

| Profile | What it does |
|---|---|
| `A-naive` | a normal VC envelope (credential id, `credentialStatus`, issuer kid, holder DID) wrapped around a BBS proof; BBS `header` domain-separated **per credential** |
| `A-hardened` | cohort-wide `header`, no per-credential envelope fields, expiry bucketed to the issuance epoch |
| `B-auditable` | two-hop chain that discloses the delegation pointer and the parent's status handle |
| `B-unlinkable-stable` | parent ids/status removed, but the guardian's key is still disclosed so the verifier can bind the hops |
| `B-unlinkable-fresh` | hop binding removed entirely; the sub-mandate is re-issued under a throwaway delegator key per presentation |

### Checks

| | Check |
|---|---|
| (a) | field-by-field comparison across all presentations |
| (b) | flag any value constant across the target's presentations **and** unique to the target (`k = 1`) |
| (c) | sanity: every derived proof must differ — duplicate proof bytes are a hard fail |
| (d) | collusion: hand the adversary the issuer's signatures, all signed messages (including withheld ones) and headers, then re-test — including a **trial-verification attack** that measures the issuer's anonymity set |
| (e) | cross-hop: can a guardian presentation be tied to a sub-carer presentation? (path-agnostic, so it catches the same secret surfacing as `guardian_key` on one side and `delegator_key` on the other) |
| (f) | attenuation: four active scope-escalation attempts per chain profile |
| (g) | cascading revocation: revoke the parent, re-present as the sub-carer |
| + | a generic clustering adversary with **no field allowlist**, scored against ground truth (precision/recall) |

Plus two **delegation transport** attacks — how hop 2 obtains a hop-1 proof at
all, given that only the guardian holds the parent signature:

- **T1** guardian shares the parent signature → attenuation destroyed
- **T2** guardian pre-derives a static parent proof → replayable and linkable
- **T3** guardian derives a fresh parent proof per presentation (requires the
  guardian online) — this is what the scenario runs use

## Layout

```
src/bbs.js         thin wrapper over the BBS library (no crypto of our own)
src/schema.js      credential attributes, scope lattice, composition profiles
src/issuer.js      mock issuer, status list, header strategies
src/holder.js      guardian + sub-carer; builds presentation payloads
src/verifier.js    relying party: proof, nonce, scope, status checks
src/world.js       cohort, relying parties, presentation plan
src/scenarios.js   Scenario A / Scenario B corpora
src/harness.js     the checker: (a)(b)(c)(d) + clustering adversary
src/crosshop.js    (e) cross-hop analysis
src/attacks.js     (f) escalation, (g) cascading revocation, T1/T2 transports
src/report.js      table rendering
src/run.js         entry point
test/              tests for the harness itself + BBS library assumptions
```

## Reproducibility

All identifiers, pseudonyms, keys and nonces come from a seeded PRNG
(`src/rng.js`), so the cohort and every leak table are byte-identical between
runs. **BBS proof randomness is deliberately not seeded** — check (c) asserts
that derived proofs differ every time, which is only meaningful with the
library's real entropy. Proof bytes therefore differ between runs; the report
prints flags and derived metrics, not raw proof bytes.

## Licence

Apache-2.0. See [LICENSE](../LICENSE) at the repository root.
