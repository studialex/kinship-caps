# Open Core — Properties Memo for Cryptographic Review (v0.1)

> **UPDATE 2026-08-05 — empirical falsification harness has now been run** (results: `Open_Core_SelfTest_FINDINGS_2026-08.md`, harness `open-core-p1-harness`, @digitalbazaar/bbs-signatures 3.1.0 / IETF draft-06). Headline: **the BBS layer did not leak; our composition plumbing did.** Single-hop P1 passed the basic empirical check in a hardened profile (no per-credential header, no credential id, no status handle, bucketed expiry — at the cost of revocation degraded to short validity). **Multi-hop delegation was FALSIFIED: an unlinkability↔attenuation↔cascading-revocation trilemma** — no tested composition achieved all three; plus a delegation-transport problem (sharing the parent signature = full scope escalation; pre-derived proofs = replay+linkability; fresh proofs = guardian must be online). Design consequence: **v1 ships single-hop; multi-hop is named open work.** The reviewer questions in §5 are superseded by the sharper 8 questions in FINDINGS §6 — please answer those against the measured results.

**Purpose.** A short, self-contained brief so an applied cryptographer can sanity-check the **soundness of the privacy/security composition** behind Open Core in ~1–2 hours of reading. It states what we claim, how we intend to get it from existing primitives, and the specific open questions we want answered. **We are not asking for a new-cryptosystem audit** — by design we *compose* standardised primitives and invent no new cryptography.

**What this review is NOT about (scope guard).** This is **not** differential privacy and **not** the Family OS "adversarial semantic masking / DP-KG" idea — those are a separate workstream and are explicitly out of scope here (per the project's decoupling rule). The object of review is the **unlinkability / scope / revocation composition** of a guardianship-delegation credential in the EUDI / W3C-VC ecosystem.

---

## 1. One-paragraph context

eIDAS 2.0 recognises "a natural person representing another natural person" and treats powers/mandates as electronic attestations of attributes, but the EUDI ARF has **not yet** technically specified it (open EDICG discussion "Topic I", Iteration 5, 26 Aug–21 Oct 2026). Open Core is an **open FOSS protocol profile + reference library** for a guardian/carer to prove and exercise **revocable, scope-limited, privacy-unlinkable** authority over a *dependent's* (minor / person with diminished capacity) data and credentials — built on **W3C VCDM 2.0 + the EUDI EAA/mandate-attestation model**, using **BBS+** for the unlinkability layer. Novelty is claimed in the *composition for this use case*, not in primitives.

## 2. The construction under review (compose, don't invent)

- **Credential model:** W3C Verifiable Credentials Data Model 2.0 (W3C Recommendation, 2025-05-15).
- **Carrier:** an EUDI **mandate/representation attestation** (EAA-shaped), profiled to interoperate with whatever Topic I converges on.
- **Unlinkability primitive:** **BBS** via the W3C *Data Integrity BBS Cryptosuites v1.0* (Candidate Recommendation) — selective disclosure + **unlinkable derived proofs** (zero-knowledge proof of knowledge of a signature).
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
- Out of scope: device compromise, coercion of the guardian, and legal-process disclosure (these are handled elsewhere / by policy).

## 5. Open questions FOR THE REVIEWER (the actual soundness asks)

1. **Does P1 hold under composition?** BBS gives per-presentation unlinkability for a *single* credential. A guardianship proof may combine (a) the dependent's PID/attribute(s), (b) the mandate attestation, and (c) a delegation/attenuation statement. **Does combining these break unlinkability** (e.g. via a stable correlator in the mandate, the dependent's identifier, or the revocation handle)?
2. **Unlinkability vs. auditability.** A guardian's actions may need to be **auditable for accountability**, yet **unlinkable for privacy**. Is there a sound construction that gives accountable-but-unlinkable (e.g. audit only to an authorised auditor, not to RPs)? Or is this an inherent tension that must be a stated design limit?
3. **Revocation privacy (P3).** Can revocation status be checked without an RP/issuer learning *which* dependent or *which* mandate is being checked? (Related work: unlinkable revocation lists — see refs.) Is a privacy-preserving status mechanism compatible with BBS derived proofs here?
4. **Multi-hop / cascading attenuation.** If delegation is chained (guardian → temporary carer), do P1–P3 still hold, and what breaks first?
5. **Minimum viable subset.** Which subset of P1–P4 is **soundly achievable today with standardised primitives** (BBS CR + VCDM 2.0), and which parts are genuinely open research that v1 should scope *out* and name as future work?

## 6. What we explicitly do NOT claim

- No new cryptographic primitive or assumption.
- Not differential privacy; not anonymity of the *guardian* where law requires accountability.
- Not a new standard — a profile/reference implementation that should interoperate with EDICG Topic I.

## 7. The single yes/no we need from the review

> *"Is there a defensible, soundly-achievable subset of P1–P4 — composing only standardised primitives (BBS Cryptosuite + VCDM 2.0 + an EUDI mandate attestation) — that delivers unlinkable, scoped, revocable guardianship delegation; and if so, what is the smallest such subset and what must be deferred?"*

A clear answer here is the project's **moat test**: a yes (with a named achievable subset) justifies building and funding; a no (or "only with new crypto") sends us back to narrow the claim.

## 8. References (verify before citing in any proposal)

- W3C *Data Integrity BBS Cryptosuites v1.0* — Candidate Recommendation (selective disclosure + unlinkable derived proofs).
- W3C *Verifiable Credentials Data Model 2.0* — Recommendation, 2025-05-15.
- EUDI ARF v2.9.0; EDICG **Topic I "Natural person representing another natural person"** (Iteration 5, 26 Aug–21 Oct 2026, Open).
- "Cryptographers' Feedback on the EU Digital Identity's ARF" (Jun 2024) — documents the mdoc/SD-JWT linkability the unlinkability layer must avoid.
- MDPI *Electronics* 14(14):2795 (2025) — "Unlinkable Revocation Lists for Qualified Electronic Attestations: A Blockchain-Based Framework" (related work on revocation privacy for EUDI). *(Corrected 2026-07-02: this is the revocation paper — it is NOT arXiv:2501.07209.)*
- arXiv:2501.07209 — Daniel Slamanig, "Privacy-Preserving Authentication: Theory vs. Practice" (survey of anonymous credentials incl. unlinkable revocation; EUDIW context) — cite separately, verified 2026-07-02.

## 9. Reviewer logistics (keep it fast)

- **Ask:** ~1–2 hours to read §2–§7 and answer §7 (+ §5 where possible).
- **Format:** a short written opinion is enough; no formal proof required at this stage.
- **Routes (by speed/credibility):** (a) free community feedback in the W3C VC / BBS Community Group or an SSI/IETF list; (b) a short paid consult with an applied cryptographer; (c) a named academic (e.g. a TU/e cryptographer) for grant-grade credibility, run in parallel since scheduling is slower.

---
*v0 properties memo. Drafted from the project files (Scoping Note v0.5 §§3–5, GUARDIANSHIP_CONTEXT decoupling rule). It frames questions for a cryptographer; it does not assert the properties are proven. Correct the "DP-soundness" mislabel wherever it appears — the object of review is the unlinkability/scope/revocation composition, not differential privacy.*
