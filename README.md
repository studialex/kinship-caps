# Kinship-Caps

**Unlinkable guardianship delegation for the EUDI wallet** — protocol profile, BBS falsification harness, and measured findings.

## The gap

eIDAS 2.0 already recognises "a natural person representing another natural person" (Art. 3, Art. 5a(5)(f); recital 55; Annex VI item 9 — *Powers and mandates to represent natural or legal persons*). But the EUDI Architecture and Reference Framework has **not yet technically specified** representation — it is an open EDICG discussion topic ("Topic I"). So today a parent, guardian or carer has no standardised, privacy-preserving way to prove and exercise authority over a **dependent's** data in the EU wallet ecosystem — and naive designs would let every verifier (or an issuer–verifier collusion) **track the dependent** across presentations.

## The approach: compose, don't invent

Kinship-Caps is an open FOSS protocol profile + reference library that **composes existing standards only**:

- **W3C Verifiable Credentials Data Model 2.0** (W3C Recommendation, 2025-05-15)
- the **EUDI EAA / mandate-attestation model** (profiled to interoperate with whatever EDICG Topic I converges on)
- the **W3C Data Integrity BBS Cryptosuite** (Candidate Recommendation Draft) — selective disclosure + unlinkable derived proofs

**No new cryptography is designed here.** The claimed novelty is the composition for the guardianship case: revocable + scope-limited + **unlinkable-on-repeat-presentation** delegation over a dependent's credentials.

## Status & measured results (2026-08)

We tried to **falsify** our own core privacy claim before building. An empirical harness (see [`docs/FINDINGS_2026-08.md`](docs/FINDINGS_2026-08.md)) generated repeated presentations of a BBS-signed guardianship mandate and hunted for correlators, including under simulated issuer–verifier collusion. Headline:

- **The BBS layer did not leak. Our composition plumbing did** — credential ids, status handles, exact expiry dates, and (worst) a per-credential domain separator in the BBS `header`.
- A **hardened single-hop profile passed** the empirical check (at the cost of revocation degraded to short validity + re-issuance).
- **Multi-hop delegation (guardian → temporary sub-carer) was falsified**: an unlinkability ↔ attenuation ↔ cascading-revocation trilemma, plus a delegation-transport problem.

**Consequence: v1 targets single-hop; multi-hop is documented open research** (8 precise open questions in FINDINGS §6).

> A passing check is **not** a soundness proof. Testing finds leaks; it cannot prove their absence. See the explicit limitations in FINDINGS §5.

## Repository contents

| Path | What |
|---|---|
| [`docs/SOUNDNESS_MEMO.md`](docs/SOUNDNESS_MEMO.md) | Properties memo for cryptographic review: claims P1–P4, threat model, construction, open questions |
| [`docs/FINDINGS_2026-08.md`](docs/FINDINGS_2026-08.md) | Falsification-harness results: field-by-field tables, attack transcripts, limitations, questions for cryptographers |
| [`harness/`](harness/) | the falsification harness itself — Node.js, `@digitalbazaar/bbs-signatures`, reproducible; `npm install && npm test` |

## Review & feedback invited

This is a public-interest, fully open effort; the result is intended as input to the EDICG **Topic I** discussion and the wider W3C VC / BBS community. If you are a cryptographer or identity engineer: the questions we most need answered are in **FINDINGS §6** (hop-binding without a stable disclosed correlator; minimum safe BBS header content; revocation privacy under cascading revocation; accountable-but-unlinkable auditing). Issues and PRs welcome — including "you're holding BBS wrong."

## Lineage

This project supersedes an earlier direction ([human-context-standard](https://github.com/studialex/human-context-standard)) that proposed *new* context standards; a mid-2026 prior-art review retired that approach in favour of extending existing standards. Killing our own weak ideas on evidence is the method.

## License

[Apache-2.0](LICENSE). Copyright (c) 2026 Oleksiy Marchenko.
