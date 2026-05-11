# Compliance signal inventory

> Sub-agent research output, 2026-05-11. Source-of-truth for what the
> dashboard should surface above-the-fold, what belongs in the detail
> drill-down, and what to explicitly skip. Drive renderer + collector
> design from this document.

## Anchor frameworks

- **OpenSSF Scorecard** (v5, 19 checks) — the lingua franca every buyer
  questionnaire references.
- **SLSA 1.0** — Build L1-L3 (Source track still draft). Target green
  state: Build L3 + Source L2.
- **NIST SSDF (SP 800-218)** — the 12 practice IDs with publicly
  verifiable signals; skip the org-internal practices.
- **CISA SBOM Minimum Elements** — table stakes for any federal-adjacent
  buyer (and most BigLaw clients).
- **PEP 740 + sigstore + PyPI Trusted Publishers** — the strongest single
  signal we can extract.
- **Cyber Resilience Act** — pre-emptively surface what a 2027
  conformity-assessment will need.
- **Legal-industry overlays** — ABA Formal Opinion 477R, state-bar
  ethics opinions, EDRM data-privacy guidance.

## Top 5 anti-patterns the dashboard MUST avoid

1. **Raw test coverage percentage as a top-line metric.** Coverage trend
   yes; coverage absolute above the fold no.
2. **"Signed commits" as a binary green check.** Without policy
   enforcement, signed-commit ratio is decorative.
3. **SBOM presence without dependency edges.** A component list with no
   `dependencies[]` graph is a manifest, not an SBOM. Downgrade these
   visibly.
4. **A composite "compliance score" out of 100.** Use the OpenSSF
   Scorecard aggregate; never invent a competing number.
5. **Maintainer-identity signals (country, employer, real name).**
   Encourages discrimination, generates false positives on
   pseudonymous-but-trusted maintainers, adds zero supply-chain
   integrity. Skip entirely.

Honorable mention: GitHub stars are a popularity metric, not a trust
metric. `event-stream` / `colors.js` / `ua-parser-js` were all
high-star at the moment of compromise.

## Above-the-fold (5 signals, ordered)

1. **PyPI Trusted Publisher + workflow_ref pin** — proves OIDC-bound
   build-to-publish chain to a specific workflow at a specific commit.
2. **OpenSSF Scorecard aggregate score**, with the five "must"
   sub-checks visible on hover: Branch-Protection, Code-Review,
   Pinned-Dependencies, Signed-Releases, Token-Permissions.
3. **Unfixed OSV vulnerabilities, broken out by severity and age.** Age
   matters more than count.
4. **Maintained-in-last-90-days + median time-to-merge for security
   PRs.** Combined liveness signal.
5. **SBOM present with non-empty dependency graph, CycloneDX or SPDX,
   less than 30 days old vs. latest release.**

## Per-framework signal tables

### OpenSSF Scorecard (19 checks)

Must: Binary-Artifacts, Branch-Protection, CI-Tests, Code-Review,
Dangerous-Workflow, Dependency-Update-Tool, License, Maintained,
Packaging, Pinned-Dependencies, SBOM, Security-Policy, Signed-Releases,
Token-Permissions, Vulnerabilities.

Nice: CII-Best-Practices, Contributors, Fuzzing, SAST.

Skip: none outright. Display CII-Best-Practices, Contributors, and
Fuzzing collapsed/secondary because they generate false negatives on
legitimate small libraries.

### SLSA fields

- `slsa.build_level` — sigstore bundle `predicateType` → must
- `slsa.builder.id` — provenance `builder.id` → must
- `slsa.invocation.configSource` — provenance
  `invocation.configSource.uri` → must
- `slsa.source.signed_commit_ratio` — GH `commits` API
  `verification.verified` → nice (Source track still draft)
- `slsa.hermetic` — provenance `metadata.completeness` → nice

### NIST SSDF (publicly evidenceable subset)

PO.1.1 (SECURITY.md exists), PO.3.2 (CI references SAST/dep-scan),
PO.5.1 (build runs in CI), PS.1.1 (branch protection + signed commits),
PS.2.1 (sigstore bundle), PS.3.1 (tagged releases retained), PS.3.2
(SBOM per release), PW.4.1 (pinned deps with provenance), PW.7.1 (code
review), PW.8.2 (CI test pass + trend), RV.1.1 (Dependabot/Renovate),
RV.1.3 (vulnerability disclosure program).

Skip PO.2.x (org training), PO.4.x (metrics governance), PW.1-3 (design
practices) — not evidenceable from public artifacts.

### CISA SBOM minimum elements

- `sbom.component.supplier` — CycloneDX `supplier.name` (must)
- `sbom.component.name` — CycloneDX `name` (must)
- `sbom.component.version` — CycloneDX `version` (must)
- `sbom.component.purl` — CycloneDX `purl` (must) — the machine-usable
  ID; CPE is theater for OSS
- `sbom.dependencies[]` — CycloneDX `dependencies` graph (must) — most
  faked field
- `sbom.metadata.authors` — CycloneDX `metadata.authors` (must)
- `sbom.metadata.timestamp` — CycloneDX `metadata.timestamp` (must)
- `sbom.format` — static (must)
- `sbom.component.hashes` — CycloneDX `hashes[]` (nice)
- `sbom.component.licenses` — CycloneDX `licenses[].license.id` (must)

### PEP 740 + sigstore + Trusted Publishers (extraction from
`https://pypi.org/pypi/<pkg>/json`)

- `pypi.has_attestations` — `releases[ver][file].provenance` non-null
  (must)
- `pypi.attestation_url` — `urls[].provenance` (must)
- `pypi.publisher.issuer` — sigstore bundle cert ext OIDC issuer (must)
- `pypi.publisher.workflow_ref` — cert ext `1.3.6.1.4.1.57264.1.9`
  (must) — **highest-density signal in the entire report**
- `pypi.publisher.source_repo` — cert ext `1.3.6.1.4.1.57264.1.5` (must)
- `pypi.trusted_publisher` — inferred from OIDC-issued cert vs.
  user-token upload (must)
- `pypi.signature.algo` — bundle `verificationMaterial` (nice)
- `pypi.rekor.log_index` — bundle `messageSignature.logIndex` (must)
- `pypi.predicate_type` — bundle `dsseEnvelope.payload.predicateType`
  (must)
- `pypi.attestations_per_file` — `releases[ver][*].provenance` array
  (nice)

### CRA pre-emptive signals

- `cra.vuln_handling_doc` — `SECURITY.md` parse (must, Annex I Part II §1)
- `cra.disclosure_policy` — `SECURITY.md` keyword scan (must, Annex I
  Part II §5)
- `cra.sbom_published` — reuse CISA section (must, Annex I Part II §1)
- `cra.median_patch_days` — GHSA `published_at` vs. fix commit (nice)
- `cra.overdue_advisories` — GHSA + repo issue cross-ref (must)
- `cra.steward` — `pyproject.toml` `maintainers` (nice)
- `cra.update_mechanism` — README/SECURITY parse (nice)

Do NOT invent a "CRA compliance score." Enforcement guidance lands
2027.

### Legal-industry overlay

- `legal.has_telemetry` — static scan for network calls in
  `__init__.py`, opt-out env vars (must — privilege leakage, ABA 477R)
- `legal.license_spdx` — copyleft is a hard block for many firms
  shipping work product (must)
- `legal.reproducible_build` — SLSA L3 provenance + builder (nice —
  discovery defensibility)
- `legal.history_retained` — repo commit history depth (must — EDRM
  chain-of-custody)
- `legal.fips_capable` — static doc claim (nice — federal-court-adjacent
  buyers)
- `legal.eccn_claim` — static claim only (nice — crypto libs)

SKIP: `legal.data_residency` (meaningless for a library),
`legal.maintainer_country` / `legal.ofac_screening` (encourages bias,
unreliable), `legal.infra_privacy` (library doesn't have one).

## Renderer implication: the four-bucket card layout

Given the inventory above, the index page's per-package card should
have exactly four buckets (not more), corresponding to the four
questions a buyer asks in order:

1. **Identity** — what is this, what version, signed by what.
2. **Integrity** — build provenance + signature chain + SBOM with edges.
3. **Hygiene** — Scorecard aggregate + vuln count + maintained signal.
4. **Velocity** — release cadence + median PR age + time-to-publish.

Anything that doesn't fit one of these four buckets needs explicit
justification or it goes in the methodology page, not the dashboard.

---

*Source: research sub-agent transcript at
`/tmp/claude-1000/-home-mjbommar-projects-273v/24ff5dad-7dde-40c2-8e94-40a470c096a2/tasks/afbd6f182858f17e0.output`*
