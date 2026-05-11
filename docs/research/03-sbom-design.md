# SBOM Extraction Module — Design

Module: `kaos-compliance.sbom`. Input: a `kaos-*` package directory containing
`uv.lock` (required) and optionally `Cargo.lock`. Output: a CycloneDX 1.5 JSON
SBOM that satisfies CISA Minimum Elements for an SBOM (NTIA 2021 / CISA 2024).

## Format choice: CycloneDX 1.5 over SPDX 2.3

We emit CycloneDX 1.5. The honest trade-off:

- **SPDX 2.3** is the de-facto standard for legal-review pipelines (FOSSology,
  ScanCode, most outside-counsel workflows). Many enterprise procurement teams
  ask for SPDX by name. Its license model (`licenseDeclared` /
  `licenseConcluded` / `LicenseRef-*`) is richer than CycloneDX's.
- **CycloneDX 1.5** has materially better OSS tooling for *generation* and
  *vulnerability correlation*: `cyclonedx-python`, `cyclonedx-bom`, Dependency-
  Track, Trivy, Grype, Syft all consume it natively. The JSON schema is
  ergonomic and round-trips cleanly through `json` without a third-party lib.
- Buyers who require SPDX can run `cyclonedx-cli convert --output-format spdxjson`
  losslessly for our subset (package, version, hash, license, supplier, PURL).

For an internal compliance dashboard whose primary jobs are (a) feed a
vulnerability scanner and (b) answer "what's in our wheel," CycloneDX wins. We
will publish an SPDX export path in v2.

## CISA Minimum Elements: data sources and gaps

| CISA Field          | Source (in order tried)                                          | Gap / Notes |
|---------------------|------------------------------------------------------------------|-------------|
| Supplier name       | PyPI `info.author` -> PyPI uploader -> home_page domain -> "Unknown / community" | PyPI `author` is free-text; we keep it verbatim and also emit `externalReferences.distribution` to PyPI |
| Component name      | `[[package]].name` in `uv.lock` / `Cargo.lock`                   | Exact |
| Version             | `[[package]].version`                                            | Exact |
| Unique identifier   | Synthesized PURL: `pkg:pypi/<name>@<version>` or `pkg:cargo/<name>@<version>`; plus SHA-256 from wheel/sdist | We always emit PURL + at least one `hashes[].alg=SHA-256` |
| Dependency relationship | `[[package]].dependencies` array in both lockfiles            | CycloneDX `dependencies[]` graph; markers (`marker = "..."`) are stripped — we list the union |
| Author of SBOM data | `metadata.tools[]` (this module) and `metadata.authors[]` (CI actor) | Exact |
| Timestamp           | `metadata.timestamp` ISO-8601 Zulu                               | Exact |

**Honest gaps:**

1. **Supplier** for ~half of PyPI projects resolves only to a free-text name
   (e.g., `"The pip developers <distutils-sig@python.org>"`). We don't get a
   legal entity. We mark these `supplier.name` as-is and let the dashboard
   surface them for human review.
2. **License** is *declared*, not *concluded*. We do not scan source for actual
   license texts (that is FOSSology's job). The dashboard should call this
   "declared license" everywhere.
3. **Cargo crates** lack a uniform license-metadata API. We read `license` /
   `license-file` from the crate's `Cargo.toml` when present in the registry
   cache, else flag as unknown.
4. **Vendored or path-source deps** (`source = { editable = "." }` or
   `git+https://...`) have no registry metadata; we record the VCS URL as the
   PURL qualifier and leave license empty.

## License normalization

Target: SPDX expression valid against **SPDX License List 3.24** (June 2024).

- Prefer existing SPDX expressions; pass through unchanged if they parse.
- Common variants are folded to canonical IDs via a 40+ entry map
  (`_LICENSE_ALIASES` in `lockfile_parser.py`): e.g.,
  `Apache 2.0`, `Apache License, Version 2.0`, `ASL 2.0`, `ASL2.0`,
  `Apache-2`, `LICENSE: Apache` all → `Apache-2.0`.
- "MIT License" / "Expat" → `MIT`. "BSD" alone → `BSD-3-Clause` (most common;
  flagged for review). "PSF-2.0" / "Python Software Foundation License" →
  `Python-2.0`.
- Free-form `"OSI Approved :: ..."` Trove classifiers are parsed by stripping
  the prefix and re-running the alias map.
- Anything we can't map becomes `LicenseRef-unknown-<sha1(text)[:8]>` and is
  flagged.

## Supplier attribution fallback chain

1. PyPI JSON `info.author` (if non-empty and not literally `"UNKNOWN"`).
2. PyPI JSON `info.maintainer` or last sdist `uploaded_by`.
3. The hostname of `info.home_page` or `info.project_urls.Homepage`
   (e.g., `github.com/pydantic` → `Supplier: pydantic`).
4. Literal string `"Unknown / community"`. The dashboard treats this as a
   compliance signal.

## Allowlist policy

A component is **clean** if its SPDX expression is purely permissive:
`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `0BSD`,
`Python-2.0`, `MPL-2.0` (file-scoped, acceptable), `Unlicense`.

A component is **compliance-concern** if its expression contains *any* of:

- `GPL-2.0*`, `GPL-3.0*`, `AGPL-3.0*` (copyleft viral on our codebase)
- `LGPL-*` *without* the `-or-later` linking-exception or when dynamic linking
  is not guaranteed (we conservatively flag all LGPL for human review)
- Anything containing `NonCommercial`, `Non-Commercial`, `CC-BY-NC*`,
  `CC-BY-ND*` (no derivatives blocks integration)
- `SSPL-1.0`, `BUSL-1.1`, `Elastic-2.0` (source-available, not OSS)
- `LicenseRef-unknown-*` or the literal `"unknown"`

The CycloneDX output sets `properties[name=kaos:license-class]` to
`permissive | weak-copyleft | strong-copyleft | source-available | unknown`.
The compliance dashboard's gate fails the build if any `strong-copyleft`,
`source-available`, or `unknown` component appears without an explicit
allowlist override keyed by `purl`.
