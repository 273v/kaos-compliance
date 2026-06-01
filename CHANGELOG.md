# Changelog

All notable changes to `kaos-compliance` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### CI / infra

- Corrected `main` branch-protection required status checks. They pinned
  pre-rename contexts (`Lint`, `Pre-commit hooks`, `Test (Linux / Python
  3.13|3.14)`, `Build distribution`) that no longer report, so every PR was
  permanently blocked on phantom checks. Now require the real, always-on
  PR gates: `quality`, `test`, `build` (`strict` preserved). Security jobs
  (`gitleaks`, `bandit`) still run on every PR but are intentionally not
  required, to avoid a conditionally-skipped check blocking forever.

### Methodology — 1.2.0 (new headline signal: real test count)

The headline **Tests** tile was a misnomer: it summed CI matrix legs
(one per `(os, python)` cell ≈ 90), which a reviewer reads as "the org
has 90 tests." It now shows the **real test-function cardinality** across
every package — ~tens of thousands — and the matrix-leg number is
relabelled **CI test legs** to name what it actually measures (testing
breadth).

- New collector field `code_metrics.{python,rust}.tests_count`: counts
  Python `def test_*` / `async def test_*` in pytest-collected files
  (`tests/` dir or `test_*.py` / `*_test.py`) and Rust `#[test]` /
  `#[tokio::test]` / `#[rstest]` / `#[test_case]` attributes (inline
  across `.rs`). Counted statically from the sibling clones — the
  dashboard never executes a suite — so a parametrized row counts **once**;
  this is a deliberate, honest lower bound on test *cases*. `None` (never
  zero) when a clone is not inspectable.
- Renderer aggregates it into `org.tests_count_total` (the **Tests**
  headline); `org.tests_total` (CI matrix legs) is now labelled **CI test
  legs**. Both link to their methodology rows (`#sig-tests-count`,
  `#sig-tests-total`).
- Methodology bumped 1.1.1 → **1.2.0** (minor: new signal under R25).
  Snapshot `schema_version` stays **1.0** — the new field is additive and
  non-breaking, and that field bumps on breaking changes only.
- Regression tests: `tests/test_code_metrics.py` (Python + Rust counting,
  parametrize-counted-once, missing-clone → `None`).


## [0.0.2] — 2026-05-23

### Methodology — 1.1.1 (audit-04 §23-H bookkeeping)

Per the methodology's own versioning rule (R25 / `docs/METHODOLOGY.md:347-353`),
the renderer's `METHODOLOGY_VERSION = "1.1.1"` (`render/__init__.py:10`)
must have a matching CHANGELOG entry and a matching footer line in the
methodology document. This entry plus the corresponding
`docs/METHODOLOGY.md` footer change close the gap audit-04/kaos-compliance.md
§23-H flagged:

- 1.1.1 is a **patch bump** under the R25 matrix — restoring honest cadence
  prose (paused hourly light cron, `stale_threshold_hours = 26` constant)
  and the corresponding 26-hour freshness boundary. No signal definitions
  or thresholds changed. The pill colors, snapshot schema, and per-signal
  evidence boundaries are unchanged.
- This is the missing CHANGELOG entry the audit called out; methodology
  doc footer is updated in the same patch.

### Methodology

- Public PR and CI/CD hardening policy detail in the methodology,
  including the evidence boundary between public workflow-file checks
  and admin-only repository settings.
- Runbook audit commands for repo settings that the dashboard should
  not render as public green claims until GitHub exposes a
  third-party-reproducible evidence path.
- `kaos-compliance`-specific policy and CI guards so external fork PR
  code is not an accepted or executed contribution path for the
  dashboard publisher.

### Added

- **Live public dashboard** at
  <https://273v.github.io/kaos-compliance/>, regenerated on cron via
  GitHub Actions plus a local-cron fallback.
- **Six rendered pages**: org rollup (`index.html`), per-package
  detail (17 of these), `methodology.html`, `security.html`,
  `supply-chain.html`, `governance.html`, `diary.html`. Each page is
  inline-CSS, no-JS, no external assets, mobile-responsive, dark-mode
  aware, and print-friendly.
- **Machine-readable endpoints**: `/api/v1/snapshot.json` (the
  source-of-truth snapshot), `/api/v1/sbom/<pkg>-<version>.cdx.json`
  (17 per-package CycloneDX 1.5 SBOMs, ~80 components each),
  `/heartbeat.json` (small file watchdogs can poll for cron silence).
- **Initial scaffold + research**: layout, LICENSE/NOTICE,
  pyproject.toml, METHODOLOGY.md, SECURITY.md, CONTRIBUTING.md, and 5
  research docs anchored to OpenSSF Scorecard, SLSA, NIST SSDF, CISA
  SBOM minimums, PEP 740 / sigstore / Trusted Publishers, the Cyber
  Resilience Act, and the legal-industry overlay (ABA Formal Opinion
  477R, EDRM data-privacy guidance).
- **Collector pipeline** (`collector/`):
  - `_retry.py` — retry + backoff for `gh` and PyPI, with rate-limit
    distinction and 4-attempt default.
  - `snapshot.py` — top-level orchestrator. Identity / CI matrix /
    Security workflow / open PRs / freshness, plus the heartbeat
    block that mitigates the "freshness lying" failure mode.
  - `pypi.py` — typed PyPI extraction with live-verified JSON paths.
  - `sbom.py` — CycloneDX 1.5 lockfile parser + emitter
    (uv.lock + Cargo.lock).
  - `supply_chain.py` — PEP 740 attestation extraction (publisher
    kind, source repo, workflow ref, Rekor log index), wheel
    platform matrix, license breakdown aggregation, SBOM emission.
  - `governance.py` — DCO sign-off rate, conventional-commits rate,
    verified commit ratio, branch protection state, CODEOWNERS
    coverage, SECURITY.md presence with disclosure window parse,
    release cadence, time-to-PyPI median. Anti-pattern guardrails
    enforced (no maintainer-identity signals, no composite scores).
  - `diary.py` — LLM-generated daily narrative across all kaos-* repos
    via kaos-llm-client or the Anthropic SDK. Gracefully skips when
    no API key is present.
- **Renderer pipeline** (`render/`):
  - `__main__.py` — snapshot → view-model adapter (per-pill state
    classification, per-pill evidence links, four-state semantics
    where gray ≠ green), Jinja templating, JSON republish.
  - Per-pill links: every Build / Tests / Security / Signing /
    License / Deps pill in the org grid is an anchor to the
    underlying evidence (workflow run, PyPI release page, CycloneDX
    SBOM artifact).
- **CI + cron**:
  - `.github/workflows/sweep.yml` — three cron schedules
    (1h light, 4h security, 24h full), 30-min timeout, deploy gated
    on success, forensic artifact upload gated on always.
  - `.github/workflows/ci.yml` — lint + pre-commit + pytest on
    Python 3.13 and 3.14.
  - `scripts/local-cron.sh` + `scripts/install-cron.sh` — local
    fallback with `--force-with-lease` to avoid racing the GHA push.
- **First live numbers** (2026-05-11 sweep, 17 modules):
  - 16/17 packages ship PEP 740 attestations.
  - 17/17 packages have a populated CycloneDX SBOM.
  - 0 red pills anywhere (no failing CI/Security, no strong-copyleft
    transitive deps).
  - 69 green / 29 yellow / 4 gray pill states across the org grid.

[0.0.2]: https://github.com/273v/kaos-compliance/releases/tag/v0.0.2
