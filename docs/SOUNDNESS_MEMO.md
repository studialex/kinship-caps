# Kinship-Caps — Properties Memo for Cryptographic Review (v0.2)

> **Status (2026-08 → 2026-09).** The empirical falsification harness described in [`FINDINGS_2026-08.md`](FINDINGS_2026-08.md) (code in [`../harness/`](../harness/), `@digitalbazaar/bbs-signatures` 3.1.0, IETF `draft-irtf-cfrg-bbs-signatures-06`) has been run. Headline: **the BBS layer did not leak; our composition plumbing did.** Single-hop P1 passed the basic empirical check in a hardened profile (no per-credential header, no credential id, no status handle, bucketed expiry — at the cost of revocation degraded to short validity). **Multi-hop delegation was falsified:** an unlinkability ↔ attenuation ↔ cascading-revocation trilemma — no tested composition achieved all three — plus a delegation-transport problem (sharing the parent signature = full scope escalation; pre-derived proofs = replay + linkability; fresh proofs = guardian must be online). Design consequence: **v1 ships single-hop; multi-hop is named open work.** The questions in §5 below are superseded by the sharper eight in FINDINGS §6 — please answer those against the measured results.

**Purpose.** A short, self-contained brief so an applied cryptographer or identity engineer can sanity-check the **soundness of the privacy/security composition** behind Kinship-Caps in roughly one to two hours of reading. It states what we claim, how we intend to obtain it from existing primitives, and the specific open questions. **This is not a request for a new-cryptosystem audit** — by design we *compose* standardised primitives and invent no new cryptography.

**Scope guard.** This is **not** about differential privacy or data masking/anonymisation. The object of review is the **unlinkability / scope / revocation composition** of a guardianship-delegation credential in the EUDI / W3C-VC ecosystem.

---

## 1. One-paragraph context

eIDAS 2.0 recognises "a natural person representing another natural person" and treats powers/mandates as electronic attestations of attributes, but the EUDI ARF has **not yet** technically specified it (open EDICG discussion "Topic I", Iteration 5, 26 Aug–21 Oct 2026). Kinship-Caps is an **open FOSS protocol profile + reference library** for a guardian/carer to prove and exercise **revocable, scope-limited, privacy-unlinkable** authority over a *dependent's* (minor / person with diminished capacity) data and credentials — built on **W3C VCDM 2.0 + the EUDI EAA/mandate-attestation model**, using **BBS** for the unlinkability layer. Novelty is claimed in the *composition for this use case*, not in primitives.

## 2. The construction under review (compose, don't invent)

- **Credential model:** W3C Verifiable Credentials Data Model 2.0 (W3C Recommendation, 2025-05-15).
- **Carrier:** an EUDI **mandate/representation attestation** (EAA-shaped), profiled to interoperate with whatever Topic I converges on.
- **Unlinkability primitive:** **BBS** via the W3C *Data Integrity BBS Cryptosuites v1.0* (Candidate Recommendation Draft) — selective disclosure + **unlinkable derived proofs** (zero-knowledge proof of knowledge of a signature).
- **Delegation/attenuation:** object-capability pattern (attenuated, possibly multi-hop) — cited as a *design pattern* (ZCAP-LD is a W3C-CCG draft, not a normative dependency).
- **Revocation:** short-lived and/or revocable attestations; revocation-status checks intended to be privacy-preserving (cf. related work below).

## 3. Properties we CLAIM (to be checked, not assumed)

- **P1 — Repeat-presentation unlinkability.** A guardian presenting "I am authorised to act for dependent Y" to multiple relying parties (or the same RP repeatedly) must **not** let those parties (or a verifier+issuer collusion) link Y's transactions across contexts. I.e. the delegation proof must not reintroduce the mdoc/SD-JWT reused-signature fingerprint that BBS derived proofs avoid.
- **P2 — Scope limitation / attenuation.** The proof discloses **only** the specific authority exercised (e.g. "may submit school enrolment") and nothing more; attenuation cannot be escalated by the holder.
- **P3 — Revocability.** All parties entitled by law to revoke can do so; revoked authority cannot be exercised; revocation-status checking does not itself become a linkability channel.
- **P4 — Dependent binding without over-exposure.** The proof binds to the correct dependent Y for verification, without exposing Y's full identity to RPs that don't need it.

## 4. Threat model to assume

- Honest-but-curious **relying parties** that may **collude** with each other and/or with the **issuer/attestation provider**.
- Goal of the adversary: **track the dependent Y** across presentations, or learn authority beyond what was disclosed.
- Out of scope: device compromise, coercion of the guardian, and legal-process disclosure (handled elsewhere / by policy).

## 5. Open questions (original set — see FINDINGS §6 for the sharpened, post-measurement version)

1. **Does P1 hold under composition?** BBS gives per-presentation unlinkability for a *single* credential. A guardianship proof may combine (a) the dependent's PID/attribute(s), (b) the mandate attestation, and (c) a delegation/attenuation statement. Does combining these break unlinkability (a stable correlator in the mandate, the dependent's identifier, the revocation handle)?
2. **Unlinkability vs. auditability.** A guardian's actions may need to be **auditable for accountability**, yet **unlinkable for privacy**. Is there a sound construction giving accountable-but-unlinkable (e.g. audit only to an authorised auditor, not to RPs)? Or is this an inherent tension that must be a stated design limit?
3. **Revocation privacy (P3).** Can revocation status be checked without an RP/issuer learning *which* dependent or *which* mandate is being checked? Is a privacy-preserving status mechanism compatible with BBS derived proofs here?
4. **Multi-hop / cascading attenuation.** If delegation is chained (guardian → temporary carer), do P1–P3 still hold, and what breaks first? *(Measured answer: see FINDINGS §3 — the trilemma.)*
5. **Minimum viable subset.** Which subset of P1–P4 is **soundly achievable today with standardised primitives** (BBS cryptosuite + VCDM 2.0), and which parts are genuinely open research that v1 should scope *out*?

## 6. What we explicitly do NOT claim

- No new cryptographic primitive or assumption.
- Not differential privacy; not anonymity of the *guardian* where law requires accountability.
- Not a new standard — a profile/reference implementation that should interoperate with EDICG Topic I.

## 7. The single yes/no we need

> *"Is there a defensible, soundly-achievable subset of P1–P4 — composing only standardised primitives (BBS cryptosuite + VCDM 2.0 + an EUDI mandate attestation) — that delivers unlinkable, scoped, revocable guardianship delegation; and if so, what is the smallest such subset and what must be deferred?"*

Our current, measured answer: single-hop with short validity (see FINDINGS §7). We would like it confirmed or broken.

## 8. References

- W3C *Data Integrity BBS Cryptosuites v1.0* — Candidate Recommendation Draft (selective disclosure + unlinkable derived proofs).
- W3C *Verifiable Credentials Data Model 2.0* — Recommendation, 2025-05-15.
- EUDI ARF (v3.0.0 at time of writing); EDICG **Topic I "Natural person representing another natural person"** (Iteration 5, 26 Aug–21 Oct 2026, open).
- "Cryptographers' Feedback on the EU Digital Identity's ARF" (June 2024) — documents the mdoc/SD-JWT linkability the unlinkability layer must avoid.
- MDPI *Electronics* 14(14):2795 (2025) — "Unlinkable Revocation Lists for Qualified Electronic Attestations: A Blockchain-Based Framework" (revocation privacy for EUDI).
- D. Slamanig, "Privacy-Preserving Authentication: Theory vs. Practice", arXiv:2501.07209 (survey of anonymous credentials incl. unlinkable revocation).
- IETF `draft-irtf-cfrg-bbs-per-verifier-linkability` (BBS pseudonyms) — relevant to question 2 (accountable-to-one-verifier, unlinkable to others).
- Delegatable anonymous credentials from mercurial signatures — Crites & Lysyanskaya (CT-RSA 2019); practical DAC from equivalence-class signatures (PoPETs 2023); ePrint 2024/1216 — relevant to question 4: multi-hop without a stable disclosed correlator is solvable in the literature, but not yet with any standardised primitive.

---
*v0.2 (2026-09). Frames questions for reviewers; does not assert the properties are proven. Issues and PRs welcome.*
