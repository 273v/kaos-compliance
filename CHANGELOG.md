# Changelog

All notable changes to `kaos-compliance` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/273v/kaos-compliance/compare/...HEAD

[Unreleased]: https://github.com/273v/kaos-compliance/compare/...HEAD
