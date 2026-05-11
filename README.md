# kaos-compliance

**Continuous compliance and supply-chain dashboard for the KAOS open-source
ecosystem.**

| | |
|---|---|
| **Live dashboard** | <https://273v.github.io/kaos-compliance/> |
| **Methodology** | <https://273v.github.io/kaos-compliance/methodology.html> |
| **Machine-readable snapshot** | <https://273v.github.io/kaos-compliance/api/v1/snapshot.json> |
| **Heartbeat (cron watchdog)** | <https://273v.github.io/kaos-compliance/heartbeat.json> |

[![Methodology](https://img.shields.io/badge/methodology-public-blue)](docs/METHODOLOGY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

## What is this

A static dashboard that gives compliance and information security
reviewers a fast, evidence-backed answer to:

> Can our team depend on the 273v/kaos-* packages today?

The dashboard surfaces continuously-refreshed signals across every
public KAOS package, anchored to industry-standard frameworks:

- **[OpenSSF Scorecard](https://scorecard.dev)** — 19-check baseline.
- **[SLSA](https://slsa.dev)** — build provenance.
- **[NIST SSDF (SP 800-218)](https://csrc.nist.gov/Projects/ssdf)** —
  publicly-evidenceable subset.
- **[CISA SBOM Minimum Elements](https://www.cisa.gov/sbom)** — supply-chain.
- **[PEP 740](https://peps.python.org/pep-0740/) + [sigstore](https://www.sigstore.dev/)** —
  PyPI attestation chain.
- **[Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)** —
  EU 2027 conformity-assessment readiness.

Every claim links to a public evidence source (GitHub Actions run, PyPI
metadata, sigstore Rekor log, or a file in this repo).

## What this is not

- Not a substitute for an independent security audit or a SOC 2 / ISO 27001
  attestation.
- Not a vanity score. We do not invent a composite "compliance score out
  of 100" — that pattern incentivizes gaming cheap signals at the cost of
  expensive ones. We report the OpenSSF Scorecard aggregate and surface
  the underlying signals; buyers compose their own bar.
- Not a marketing surface. The dashboard makes maintainers slightly
  uncomfortable and procurement slightly happier; if it does the reverse,
  it has become marketing.

## How it works

1. A collector script runs on a cron schedule (1h light, 4h security
   scan refresh, 24h full sweep + SBOM rebuild + LLM diary).
2. The collector queries public sources only: GitHub REST API for repos,
   PyPI JSON + simple-index for package metadata, sigstore Rekor for
   attestation chains, and the local sibling repo clones for filesystem
   signals (uv.lock, Cargo.lock, CHANGELOG.md).
3. The collected JSON snapshot is the source of truth. The dashboard is
   one render of it; the JSON is also published at
   `data/snapshots/latest.json` for compliance ingest.
4. A renderer turns the snapshot into static HTML and commits it to the
   `gh-pages` branch.
5. The LLM diary uses `kaos-llm-client` to produce a daily narrative
   summary from `git log` across all 16 packages.

Full methodology at [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Repo layout

```
collector/        — fetches signals from GitHub, PyPI, local repos
render/           — Jinja templates + render script
data/
  snapshots/      — historical JSON snapshots (rolling 90 days)
  sbom/           — per-package CycloneDX 1.5 SBOMs
  diary/          — daily LLM-generated narrative summaries
docs/
  METHODOLOGY.md  — what claims this dashboard makes and how to verify
  EVIDENCE.md     — how a third party can independently reproduce every claim
  DATA-MODEL.md   — JSON schema for snapshot.json
  research/       — design-grade research artifacts
tests/            — pytest suite covering the collector
.github/
  workflows/
    sweep.yml     — cron-driven collection + rendering
    ci.yml        — lints + tests the collector
```

## Running locally

```bash
uv sync --group dev
uv run python -m collector.snapshot --output data/snapshots/local.json
uv run python -m render --snapshot data/snapshots/local.json --output _site/
```

Tests:

```bash
uv run pytest tests/ -q --no-cov
```

## Reporting issues

If you find a discrepancy between what the dashboard claims and what the
underlying evidence supports, please open an issue or contact
<security@273ventures.com>.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
