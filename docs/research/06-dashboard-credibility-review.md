# Dashboard credibility review

> External Opus reviewer, 2026-05-11, regulated-buyer perspective.
> Reviewed the live dashboard, methodology, license audit + policy
> YAML, and the JSON snapshot. Pulls no punches; the goal is to find
> what would erode trust with a compliance officer on first read.

## The dashboard's strongest move

> "The single load-bearing design decision is the **dual commitment to
> a public `api/v1/snapshot.json` as source-of-truth plus a methodology
> page that names anti-patterns rather than feature-listing virtues**.
> Most vendor compliance pages tell you what they include; this one
> tells you what they refuses to include, which is a much harder claim
> to fake. The fact that the JSON is plausibly auditor-grade is what
> makes the visible self-contradictions on the index (R1, R2, R3, R13,
> R24) so damaging — the underlying data model would support a more
> honest presentation than the current HTML actually delivers. The
> dashboard's strength is the substrate; the weakness is that the
> HTML layer is currently *over-claiming relative to the JSON it sits
> on*."

## Findings (25 total)

| ID | Dimension | URL | Finding (compressed) | Priority |
|---|---|---|---|---|
| R1 | Anti-pattern self-violation | `/` | The index header literally says "Composite trust" and renders `aria-label="Composite score"` — exactly the pattern the methodology forbids. 16/100 vs 16/16 doesn't save it; it's still a rolled-up trust number. | **P0** |
| R2 | Anti-pattern self-violation | `/` | "16/16 Signed releases" pill is binary-green-without-policy-enforcement — the second anti-pattern the methodology forbids, applied to releases. No pairing with attestation state. | **P0** |
| R3 | Self-contradiction | `/` vs `/supply-chain.html` | Index says "16/16 Signed releases — Pass." Supply-chain page says "0/16 PEP 740 attestations." Not reconciled anywhere. **The single most damaging credibility issue today.** | **P0** |
| R4 | Trust signal | `/api/v1/snapshot.json` | No dashboard self-attestation. The dashboard signs packages but doesn't sign its own snapshot. No SHA, no Rekor entry, no verification recipe. | **P0** |
| R6 | Methodology clarity | `/methodology.html` | Pill state thresholds not defined. What makes Security amber vs red? What makes License Warn? Green is unfalsifiable without rules. | **P0** |
| R7 | Implausibility | `/security.html` | 16/16 green across 6 scanners (gitleaks, bandit, vulture, pip-audit, cargo-audit, cargo-deny) without a suppressions ledger is implausibly clean at scale. | **P0** |
| R8 | Missing dimension | `/methodology.html`, `/security.html` | OpenSSF Scorecard cited as anchor framework but no per-check results shown. "Cite the framework, don't show the data" reads as evasion. | **P0** |
| R13 | Internal asymmetry | per-package pages | Per-package detail pages show "0/0 green" + "No signal" pills while the org rollup claims 16/16. The asymmetry destroys trust in both pipelines. | **P0** |
| R24 | Hidden disclosure | `/` | Branch protection is universally off across the org but the index hides this. A buyer scanning the rollup sees green/green/green and never learns the state. | **P0** |
| R5 | Anti-pattern boundary | `/governance.html` | `verified_commit_ratio_90d` is a ratio of identity claims — adjacent to the maintainer-identity anti-pattern. Methodology never draws the line between "ratios OK" and "names not OK." | P1 |
| R9 | Missing dimension | `/supply-chain.html` | No SLSA Build level claimed per package. Methodology cites SLSA but no package asserts a level. | P1 |
| R10 | Missing dimension | `/supply-chain.html` | No CISA SBOM Minimum Elements gap analysis (author, supplier, name, version, unique ID, relationships, timestamp). | P1 |
| R11 | Missing dimension | `/security.html` | No CVE feed source named. "0 Open advisories" — but scanned against what database, at what cursor? | P1 |
| R12 | IA / abandonment risk | `/diary.html` | Diary in top nav at equal weight to Security/Supply-chain/etc but the page is empty. Reads as abandoned feature. | P1 |
| R14 | IA / discoverability | `/` | "Methodology" is rightmost nav item, visually de-emphasized. For an auditor view, it's the second-most-important page after the rollup. | P1 |
| R16 | Trust signal | `/license-policy.html` | License detection method not named. Doesn't say "SPDX via crates.io + uv pip compile + ScanCode for parser gaps." | P1 |
| R17 | Trust signal | `/license-policy.html` | Single-reviewer attestation (`reviewers: [mjbommar]`) is sole-signer pattern, not acknowledged. | P1 |
| R18 | Missing dimension | `/methodology.html` | NIST SSDF cited but no SSDF practice-ID → dashboard-signal matrix. SSDF reference reads as decorative. | P1 |
| R23 | Trust signal | `/api/v1/snapshot.json` | No `$schema` URL, no published JSON Schema, no `digest` field. Cannot machine-validate or detect tampering. | P1 |
| R25 | Versioning | `/methodology.html` | "Methodology version 1.0" with no breaking-change semantics committed. When does this become 2.0? What can change without a major bump? | P1 |
| R15 | Provenance | `/` | LoC headline (274,030) has no tool/exclusion provenance footnote. Reads as vanity number. | P2 |
| R19 | Missing dimension | `/methodology.html` | CRA cited but no Annex II / Article 13 traceability. EU-jurisdiction reviewer dismisses CRA citation. | P2 |
| R20 | Accessibility | `/` | `aria-label` on link-pill creates duplication with inner `<span class="wd">`. Screen reader announces "Build Pass open evidence Pass." | P2 |
| R21 | Accessibility / CSP | `/` | Inline `style="position:absolute;left:-9999px"` blocks strict `style-src 'self'` CSP. | P2 |
| R22 | Accessibility | `/` | Mobile responsiveness good overall, but the LoC strip's 4 numbers overflow below 480px. | P2 |

## Top 5 changes if shipping v1.1 tomorrow

1. **Kill "Composite trust" label and rolled-up 16/16 hero number on the index** (R1). Reconciles dashboard with its own anti-pattern list.
2. **Reconcile "16/16 Signed releases" with "0/16 PEP 740 attestations"** (R2 + R3). Pair them or downgrade to "Trusted Publisher present" + separate "Attestation verified."
3. **Add a "Branch protection" column to the index** (R24). Universal-off is fine for alpha if disclosed at the rollup; hiding it feels evasive.
4. **Publish per-pill threshold definitions on methodology.html** (R6). Green/amber/red/gray rules per signal.
5. **Sign `snapshot.json` and surface the snapshot digest** (R4 + R23). Dashboard claims downstream packages are signed; the dashboard itself should be too.

## Watch out for

> "The biggest drift risk is **pill inflation** — over the next two
> quarters, as more signals come online and per-package detail pages
> get backfilled, the temptation will be to add new green pills faster
> than new amber/red ones. The current 16/16-across-the-board state is
> statistically implausible at any non-trivial scanner depth, and
> unless suppressions are surfaced explicitly, the dashboard will
> gradually accumulate invisible scope reductions to keep the green
> count up."
>
> "The second drift risk is **methodology-version silent edits.** The
> first time someone 'clarifies' the green threshold for a signal
> without bumping the version, the dashboard loses the property that
> makes it credible in the first place — that an external reviewer
> can pin a snapshot to a methodology version and reproduce the
> assessment. Lock methodology to semver with a CI rule that fails if
> `policy_version`, pill thresholds, or signal definitions change
> without a CHANGELOG entry and a version bump."

---

*Source: research sub-agent transcript at
`/tmp/claude-1000/-home-mjbommar-projects-273v/24ff5dad-7dde-40c2-8e94-40a470c096a2/tasks/a8fc28a84eb8e670f.output`*
