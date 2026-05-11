# Follow-up roadmap — cross-org and architectural gaps

> Tracks audit findings (`docs/research/06-*.md`, `docs/research/07-*.md`)
> that aren't addressable inside the `kaos-compliance` repo alone, or
> that need a multi-day rewrite the polish PR couldn't carry. Each entry
> names the finding, the gap class, and the next concrete step.
>
> This file is the single index for follow-up work. New audits should
> append; closed gaps should be moved into `CHANGELOG.md` with the PR
> that closed them.

## Convention

- **Cross-org operational** — the fix lives in a `273v/kaos-*` repo,
  not in `kaos-compliance`. The dashboard observes the state; it does
  not enforce it. These are tracked as issues on
  [`273v/kaos-compliance`](https://github.com/273v/kaos-compliance/issues)
  with the `cross-org` label.
- **Architectural** — a fix that requires a multi-day rewrite of the
  collector or renderer. Scoped here with an explicit next-step.

## Process-audit follow-ups

| ID | Class | Status | Next step |
|---|---|---|---|
| F3 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F3: DCO sign-off rate <50% on six kaos-* repos'`. Surface a per-repo amber pill on `governance.html` once `F1` (branch protection) lands, since DCO without enforcement is decorative. Methodology amendment in `docs/METHODOLOGY.md §Anti-patterns` already names this. |
| F4 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F4: Verified-commit ratio decorative without F1'`. Pair surfacing waits on `F1`. |
| F5 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F5: Conventional-commits rate <75% on six kaos-* repos'`. Renderer already surfaces the rate on `governance.html` per-row; no dashboard change. |
| F7 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F7: Tag → PyPI publish latency outlier on kaos-nlp-core'`. The dashboard already surfaces `time_to_pypi_seconds_median` on `governance.html`; the outlier indicates a human-in-loop step in the release pipeline. Action lives in the affected repo, not here. |
| F9 | Architectural | roadmap | The SBOM collector emits component lists without an edge graph (CycloneDX `dependencies[]`). Building that graph requires walking each component's transitive resolutions; the existing parsers (`uv.lock`, `Cargo.lock`) carry parent/child information that we currently discard. Plan: extend `collector/sbom.py` to track and emit `dependencies[]` in CycloneDX 1.5 (`components[i].dependsOn[]` is not the right field — the top-level `dependencies[]` array is). Estimated 1-2 days; gated behind a test fixture that round-trips `uv.lock` → graph → CycloneDX. Methodology already calls this out as an anti-pattern; the dashboard's License + Deps pills downgrade to yellow if the graph is missing. |
| F10 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F10: kaos-ml-core release.yml uses ubuntu-latest, peers use self-hosted'`. Affects publishing trust boundary; SLSA Build-Level claim downgrades on that one repo (see R9 / F19 below). |
| F11 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F11: ruff-pre-commit version drift across kaos-*'`. The dashboard does not currently observe pre-commit-hook versions; this is a follow-up signal under the supply-chain page. |
| F12 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F12: SECURITY.md drift (casing + length) across kaos-*'`. Renderer already surfaces `SECURITY.md present` on `governance.html` per-repo; consistency is a separate signal not yet collected. |
| F13 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F13: release.yml byte-drift across kaos-*'`. Workflow-shape consistency is a CRA-Annex-I §5 signal; not yet collected. Plan: hash every `.github/workflows/release.yml` at sweep time, expose `governance.release_workflow_sha`, render a "release-workflow consistency" tile. |
| F14 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F14: pre-commit config has two - repo: local stanzas'`. Hand-edit artifact; fix in each affected repo. |
| F15 | Cross-org | tracked | Issue `gh issue create --label cross-org --title 'F15: SECURITY.md cites 90-day window but no MTTR/closed-advisory history'`. The dashboard already exposes `advisories_open` (zero everywhere); a follow-up tile should surface advisory close rate + MTTR once GHSA history collection lands. CRA first-audit risk; tracked but not blocking the polish PR. |
| F16 | Architectural | roadmap | VEX (Vulnerability Exploitability eXchange) documents: each SBOM should carry a sibling `*.vex.json` indicating which OSV/GHSA findings are not applicable to a given package release. Plan: extend `collector/sbom.py` to emit CycloneDX VEX 1.4 alongside each SBOM, populated from a hand-curated allowlist (`policy/vex-allowlist.yaml`) at first; later automated against OSV API queries. Estimated 2-3 days; gated behind first real CVE landing on the org. |
| F19 | Renderer (landed) | n/a | SLSA Build-Level claim per package — surfaced on `supply-chain.html` and the per-package detail page when `attestations.pep740_present` AND `attestations.publisher_kind == 'GitHub'`. See R9 below for the methodology link. |

## Dashboard-audit follow-ups

| ID | Class | Status | Next step |
|---|---|---|---|
| R8 | Architectural | roadmap (tied to F18) | OpenSSF Scorecard per-check results. F18 wires the Scorecard workflow in `kaos-compliance` itself; the dashboard then ingests `results.json` and renders a per-check table on `security.html`. The methodology page already lists which Scorecard checks the dashboard maps to; the data is the gap, not the documentation. Reproduce locally with `scorecard --repo=273v/kaos-compliance --format=json`. Plan: extend `collector/governance.py` to ingest the Scorecard SARIF/JSON output and emit a `scorecard.checks[]` block; renderer surfaces the table behind a /security.html#scorecard anchor. |
| R9 | Renderer (landed) | n/a | SLSA Build-Level surfaced per package on `supply-chain.html` derived from attestation + publisher state. See also F19. |
| R10 | Renderer (landed) | n/a | CISA SBOM Minimum Elements gap analysis surfaced on `supply-chain.html` per package. The seven elements are walked against the live SBOM and flagged green/yellow/red individually so a buyer can see exactly which element is missing. |
| R12 | Renderer (landed) | n/a | Diary empty-state copy reworked; the page now explains the diary contract instead of reading as an abandoned feature. The cron is wired up; days without LLM availability render the commit aggregation as authoritative. |

## Anti-patterns explicitly NOT implemented

These were suggested but conflict with `docs/METHODOLOGY.md §Anti-patterns we explicitly avoid` and are deliberately not surfaced on the dashboard:

- A single "trust score" or composite rollup pill. The methodology
  forbids this; the polish PR removed the last remaining instance
  (R1, already landed in `main`).
- "Signed commits" as a binary green pill. We surface the verified
  ratio paired with branch-protection state on `governance.html`;
  binary-green-without-policy-enforcement is explicitly forbidden.
- Maintainer identity (country, employer, real name). Tracked as
  CODEOWNERS path + commit-share only; no identity signals.
- GitHub stars / fork counts. Popularity metric, not a trust metric.
- Raw coverage percentage as a top-line. Trend yes; absolute no.

If a future audit recommends one of these, push back in the audit
response. They are load-bearing constraints, not negotiable cosmetics.

---

*This document is the polish-PR bookkeeping for `feat/dashboard-polish-bundle`.*
*Last updated: 2026-05-11.*
