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
in pure JS). Node ≥ 20, no native build step.

Committed sample output: [`sample-output/run-output.txt`](sample-output/run-output.txt)
and [`sample-output/run-output.json`](sample-output/run-output.json).

### The same checks against the full W3C `bbs-2023` cryptosuite

```bash
npm run cryptosuite
```

Issues real VCDM 2.0 JSON-LD credentials with `bbs-2023` base proofs, derives
real `bbs-2023` disclosure proofs, verifies every one with `@digitalbazaar/vc`,
and runs checks (a)–(d), the clustering and conjunction adversaries, and the
cryptosuite-specific probes (h)–(k) per `mandatoryPointers` policy, plus an
optional cross-hop (e) probe. Runtime roughly 3–4 minutes: it includes cohort-
level Monte Carlo runs. The run exits non-zero only if an honest presentation
fails to verify (harness malfunction), never because it found a leak.

To run the unit tests, the raw run and the cryptosuite run in one go:

```bash
npm run test:all
```

Committed sample output: [`sample-output/cryptosuite-output.txt`](sample-output/cryptosuite-output.txt)
and [`sample-output/cryptosuite-output.json`](sample-output/cryptosuite-output.json)
(both from the same run). Write-up:
[`../docs/FINDINGS_2026-09_cryptosuite.md`](../docs/FINDINGS_2026-09_cryptosuite.md).

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

**Gap to the full W3C cryptosuite — now covered, for the baseline feature.**
The original run (`npm test` / `npm run linkability`) uses the BBS scheme
directly. Since 2026-09 the same checks also run against `bbs-2023` from
*W3C Data Integrity BBS Cryptosuites v1.0* (`npm run cryptosuite`, code in
`src/cryptosuite/`). That run does exercise JSON-LD canonicalisation (RDFC-1.0),
the mandatory-pointers mechanism, `baseProof`/`derivedProof` encoding, HMAC
blank-node label replacement and `@context` handling, and the checker sees the
derived credential exactly as a verifier receives it (plus the decoded contents
of `proofValue`, which any verifier can parse).

What is still **not** covered: the spec's *anonymous holder binding* and
*pseudonym* feature options (the library implements the baseline feature only),
status-list credentials themselves, JSON-LD-level attacks on `@context`, and any
other `bbs-2023` implementation. See
[`../docs/FINDINGS_2026-09_cryptosuite.md`](../docs/FINDINGS_2026-09_cryptosuite.md) §6.

| cryptosuite stack (pinned) | version | released |
|---|---|---|
| `@digitalbazaar/bbs-2023-cryptosuite` | 2.0.1 | 2024-08-26 |
| `@digitalbazaar/data-integrity` | 2.5.0 | 2024-09-06 |
| `@digitalbazaar/vc` | 7.3.0 | 2026-02-05 |
| `@digitalbazaar/di-sd-primitives` | 3.3.0 | 2026-04-27 |
| `@digitalbazaar/bls12-381-multikey` | 2.2.0 | 2026-05-25 |
| `@digitalbazaar/bbs-signatures` (underneath, same as the raw run) | 3.1.0 | 2026-06-02 |

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
src/run.js         entry point (raw scheme)
src/cryptosuite/   the bbs-2023 re-run:
  env.js           offline document loader, issuer key, sign/disclose/verify suites
  mandate.js       the mandate as a VCDM 2.0 credential; mandatoryPointers policies
  scenario.js      Scenario A cohort: issue, derive, verify
  decode.js        adversary view: decoded proofValue, verifier-side N-Quads
  probes.js        (h)(i)(j)(k), collusion, Monte Carlo, ordering, cross-hop (e)
  run.js           entry point (cryptosuite)
test/              tests for the harness itself + BBS / bbs-2023 library assumptions
```

## Reproducibility

All identifiers, pseudonyms, keys and nonces come from a seeded PRNG
(`src/rng.js`), so the cohort and every leak table are byte-identical between
runs. **BBS proof randomness is deliberately not seeded** — check (c) asserts
that derived proofs differ every time, which is only meaningful with the
library's real entropy. Proof bytes therefore differ between runs; the report
prints flags and derived metrics, not raw proof bytes.

**The cryptosuite run is less reproducible, unavoidably.** `bbs-2023` draws a
fresh HMAC key inside the library at every issuance, and it cannot be seeded.
Every value derived from it (`labelMap`, the index lists, `mandatoryHash`)
changes between runs, so single-cohort k values for those rows vary. Stable
numbers come from the Monte Carlo sections, which re-issue whole cohorts many
times. Deterministic leaks (auto-revealed `id`, exact dates, status entries) are
identical across runs.

## Licence

Apache-2.0. See [LICENSE](../LICENSE) at the repository root.
