# kaos-* process audit

> External Opus reviewer, 2026-05-11, supply-chain compliance perspective.
> Focuses on the ACTUAL development process the dashboard reports on,
> not on the dashboard's presentation of it. Pulls no punches; finds
> what a procurement reviewer who clicks `Verify` will raise.

## 2026-05-12 remediation note

This document is preserved as the May 11 audit record. Several findings
changed during the May 12 public-PR hardening pass:

- **F1 remediated operationally.** `main` branch protection is now
  enabled across the public KAOS repos and `kaos-compliance`, with
  required status checks, CODEOWNER review, stale-review dismissal,
  last-push approval, linear history, admin enforcement, and no
  force-pushes.
- **F18 partially remediated.** Scorecard workflows are installed and
  SHA-pinned, but `kaos-compliance` still does not ingest per-check
  Scorecard output into the dashboard. That ingestion remains tracked
  as `R8` in `docs/research/08-followup.md`.
- **F20 remediated operationally.** Dependabot configuration is now
  present for the public repos; stale pre-hardening tag-based Actions
  PRs were closed so SHA-aware Dependabot PRs can replace them.
- **F10 corrected.** `kaos-x64-16core` is a GitHub-hosted larger runner,
  not an org-owned persistent self-hosted runner. The remaining runner
  policy is cost/egress/cache risk for public PRs, not persistence risk
  on 273V hardware.

The dashboard should not silently rewrite the historical audit table.
Current state should be verified through the live dashboard and the
admin-only audit commands in `docs/RUNBOOK.md`.

## What's already impressive

- **PEP 740 attestations live on 16/16 packages** with verified Rekor
  log indices recorded in the snapshot. The supply-chain page's
  `Verify` link genuinely reproduces. Most Python orgs in early 2026
  don't have this.
- **NOTICE + LICENSE both present in every sdist and every wheel**
  (`license_files_in_wheel: ['LICENSE', 'NOTICE']` on all 16).
  LICENSE-AUDIT.md walks each weak-copyleft case with reasoning —
  rigorous hygiene.
- **The dashboard's anti-patterns section** (no composite scores, no
  signed-commits-without-protection green pill, no maintainer
  identity tracking) is the right calibration. Hold this line.
- **CI matrix discipline**: free-threaded Python 3.14t, gated 3.15-dev,
  macOS arm64, Windows x64, min-deps job — more thorough than most
  commercial Python SDKs ship with.
- **The snapshot.json is publicly addressable and machine-readable**
  (`/api/v1/snapshot.json`, `schema_version` field, `heartbeat`
  timestamps). Reviewers can write their own evaluators against it
  without scraping. Rare and should not regress.

## Findings (20 total)

| ID | Bucket | Finding | Effort | Priority |
|---|---|---|---|---|
| F1 | Branch hygiene | `main` branch protection is **disabled on 16/16 repos**. Force-push, direct-to-main, bypassed reviews all possible today. | S | **P0** |
| F2 | Branch hygiene | CODEOWNERS routes 100% of paths to a single account, `@mjbommar`. `unique_committers_90d == 1` across all 16. Bus factor 1; "required reviewer" rule (when enabled) is self-review. | M | **P0** |
| F3 | Branch hygiene | DCO sign-off rate is **5.1%–88%, median ~58%**; six packages below 50% (kaos-ml-core 27%, kaos-office 8.7%, kaos-source 14.5%, kaos-web 5.1%, kaos-pdf, kaos-nlp-transformers). | S | **P0** |
| F6 | Release pipeline | `identity.pypi_version` and `identity.pypi_url` are **null on every package** despite the snapshot containing the data under `supply_chain.pypi_version`. `tag_at_head` is true on only 2 of 16. Collector bug + real release-drift. | S | **P0** |
| F8 | Release pipeline | SBOMs are emitted to `kaos-compliance/data/sbom/` only; the **published PyPI sdist/wheel does not contain the SBOM**, no GitHub Release asset for it. Buyer asserts the SBOM is a third-party artifact, not vendor-attested. | M | **P0** |
| F18 | Other (SLSA / Scorecard) | **No published OpenSSF Scorecard run** anywhere. Methodology cites Scorecard but no workflow installs it. The dashboard's "verifiable claims" promise is self-inflicted-gapped. | S | **P0** |
| F20 | CRA / dep hygiene | **No Dependabot or Renovate configuration** in any repo. Security cron detects CVEs but no workflow fixes them. Direct CRA "regular updates" gap. | S | **P0** |
| F4 | Branch hygiene | Verified-commit ratio is 2.9%–43.8%, median ~17%. Methodology already concedes this is decorative without F1. | S | P1 |
| F7 | Release pipeline | Tag → PyPI latency varies 53s–1322s (median 53s, outlier 22min on kaos-nlp-core). Suggests human-in-loop or matrix waits, breaks SLSA L3 hermeticity claim. | M | P1 |
| F9 | Release pipeline | SBOMs are **edgeless component lists** — methodology explicitly says "a component list without edges is a manifest, not an SBOM." Snapshot exposes `components_count` + `license_breakdown` but no `dependencies[]` graph. | M | P1 |
| F10 | Release pipeline | `kaos-ml-core/release.yml` uses `runs-on: ubuntu-latest` while the other 15 use the self-hosted `kaos-x64-16core`. Inconsistent publishing trust boundary. | S | P1 |
| F13 | Cross-package consistency | Release-pipeline shape drifts (137 vs 184 vs 282 vs 307 lines). `permissions:` blocks, `environment:` names, `attestations: true` flag positions not byte-identical. Hand-edited; not under change control. | L | P1 |
| F15 | Disclosure | SECURITY.md states a 90-day window but **no historical vulnerability response cadence** surfaced (no advisories closed, no MTTR). Policy exists, evidence of practice does not. Common cause of CRA first-audit rejection. | M | P1 |
| F17 | Disclosure | No GOVERNANCE.md anywhere. No documented maintainer succession, escalation path, or key-rotation policy. Procurement-bar item for any enterprise 1.0. | S | P1 |
| F19 | SLSA | **No SLSA build-level claim published.** PEP 740 + Trusted Publishing puts the team at Build L2 effectively; not surfaced. L3 achievable. | M | P1 |
| F5 | Branch hygiene | Conventional-commits rate 38.7%–88.9%; six packages below 75%. Auto-changelogs / SemVer enforcement unreliable on those. | S | P2 |
| F11 | Cross-package consistency | `ruff-pre-commit` pinned at v0.15.7 in kaos-citations + kaos-source, v0.15.12 in the other 14. Hook drift is silent and ungoverned. | S | P2 |
| F12 | Cross-package consistency | SECURITY.md title casing drifts (`# Security policy` vs `# Security Policy`); file sizes range 53–243 lines; "Supported versions" tables not synchronized. | S | P2 |
| F14 | Cross-package consistency | Several `.pre-commit-config.yaml` files contain two `- repo: local` stanzas instead of one — concatenated by hand. | S | P2 |
| F16 | Disclosure | No VEX (Vulnerability Exploitability eXchange) documents. CVE-level diff between SBOM and OSV will assume all findings are unaddressed. | L | P2 |

## Top 3 paired remediations

1. **F1 + F2 paired** — Turn on branch protection on `main` across all 16 + eliminate the single-owner CODEOWNERS pattern. This single pairing converts F3 (DCO), F4 (verified commits), F5 (conventional commits) from advisory metrics into enforced policy. Without a second maintainer, every other control is theatre: "required PR review" is self-review, bus factor 1 is a procurement disqualifier at any enterprise of meaningful size.
2. **F8 + F18 paired** — Ship SBOMs as PyPI release assets + install OpenSSF Scorecard. Together these convert the dashboard from "273V's self-report" to "independently reproducible against industry-standard tooling." That's the difference between a buyer trusting your dashboard and a buyer running their own scan and matching your numbers.
3. **F20** — Install Dependabot/Renovate org-wide. Without automated transitive-vulnerability remediation, the "Security every 4h" cron *detects* CVEs but no workflow *fixes* them.

---

*Source: research sub-agent transcript at
`/tmp/claude-1000/-home-mjbommar-projects-273v/24ff5dad-7dde-40c2-8e94-40a470c096a2/tasks/a0f9db0a88920fc0e.output`*
