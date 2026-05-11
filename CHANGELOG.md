# Changelog

All notable changes to `kaos-compliance` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial scaffold: layout, LICENSE/NOTICE, README, pyproject.toml,
  research-grade design docs anchored to OpenSSF Scorecard / SLSA /
  NIST SSDF / CISA SBOM minimums / PEP 740 / CRA / legal-industry
  overlays.
- PyPI extraction module (`collector/pypi.py`) — typed model for
  artifact, release, and attestation metadata, with live-verified JSON
  paths against `kaos-graph` 0.1.0a3 (PEP 740 attestations confirmed).

[Unreleased]: https://github.com/273v/kaos-compliance/compare/...HEAD
