"""
pypi_extract_spec
=================

Extraction specification for the kaos-compliance dashboard collector.

This module defines the data model and the JSON paths the collector reads
from PyPI's public APIs. No HTTP calls are performed here -- ``fetch_release``
is a signature-only contract documented for downstream implementers.

PyPI endpoints relied on
------------------------

1. Project JSON (latest release):
       GET https://pypi.org/pypi/<project>/json
   Project JSON (pinned release):
       GET https://pypi.org/pypi/<project>/<version>/json
   Public, stable, undocumented-but-de-facto API exposed by Warehouse.
   Docs: https://warehouse.pypa.io/api-reference/json.html
   Supports claims about: project metadata (name, summary, classifiers,
   license_expression, license_files, requires_python, requires_dist),
   per-file digests (sha256/md5/blake2b_256), filename, packagetype
   ("sdist"|"bdist_wheel"), size, upload_time_iso_8601, yanked flag.
   Does NOT consistently populate the ``provenance`` field on each
   ``urls[]`` entry -- as of 2026-05-11 it is ``None`` even for projects
   that publish PEP 740 attestations (verified on ``sigstore`` 4.2.0).

2. Simple index, JSON content type (PEP 691, extended by PEP 700/714/740):
       GET https://pypi.org/simple/<project>/
       Accept: application/vnd.pypi.simple.v1+json
   Docs: https://peps.python.org/pep-0691/  (JSON simple index)
         https://peps.python.org/pep-0700/  (api-version, size, upload-time)
         https://peps.python.org/pep-0714/  (core-metadata key rename)
         https://peps.python.org/pep-0740/  (provenance URL per file)
   This is the AUTHORITATIVE source for the ``provenance`` URL of each
   artifact. Each ``files[]`` entry exposes: filename, url, hashes (dict),
   size, upload-time, requires-python, yanked, core-metadata, provenance.

3. Integrity (PEP 740 attestation bundle):
       GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance
       Accept: application/vnd.pypi.integrity.v1+json
   Docs: https://docs.pypi.org/api/integrity/
         https://peps.python.org/pep-0740/
   Returns ``{version, attestation_bundles: [{publisher, attestations}]}``.
   ``publisher.kind`` identifies the Trusted Publisher (GitHub, GitLab,
   Google, ActiveState). ``publisher.repository`` + ``publisher.workflow``
   anchor the build to a specific workflow file. Each ``attestation`` is a
   sigstore DSSE envelope (``envelope``) plus ``verification_material``
   (the Rekor transparency-log inclusion proof and signing-cert chain).

4. Sigstore Rekor transparency log (out-of-band verification):
       GET https://rekor.sigstore.dev/api/v1/log/entries/<uuid>
   Docs: https://docs.sigstore.dev/logging/overview/
         https://github.com/sigstore/rekor/blob/main/openapi.yaml
   The Rekor entry UUID is embedded in ``verification_material`` of each
   PEP 740 attestation; fetching it independently is how a third-party
   compliance auditor confirms the attestation was logged publicly.

Live verification performed 2026-05-11
--------------------------------------
- ``GET /pypi/sigstore/json``     -> top keys present as documented.
- ``GET /pypi/kaos-graph/json``   -> identical schema; cp313-abi3 wheels.
- ``GET /simple/sigstore/``       -> ``files[].provenance`` populated, e.g.
  ``https://pypi.org/integrity/sigstore/4.2.0/sigstore-4.2.0.tar.gz/provenance``.
- ``GET /simple/kaos-graph/``     -> ``files[].provenance`` populated.
- ``GET /integrity/.../provenance`` -> both bundles returned publisher
  ``kind=GitHub``; sigstore=``sigstore/sigstore-python:release.yml``,
  kaos-graph=``273v/kaos-graph:release.yml`` (environment=``pypi``).

Drift between docs and live behavior
------------------------------------
- ``urls[].provenance`` in the legacy JSON API is documented but observed
  ``None`` even when a provenance URL is reachable via /simple/ -- so the
  collector MUST consult the JSON simple index for this field.
- ``urls[].has_sig`` is still emitted but refers to legacy detached GPG
  ``.asc`` signatures; PyPI removed GPG-upload support in 2023, so the
  field is effectively always ``False`` for post-2023 releases and MUST
  NOT be conflated with sigstore/PEP 740.
- ``info.license`` is the freeform legacy field; ``info.license_expression``
  (PEP 639, SPDX) and ``info.license_files`` (list of filenames inside the
  dist) are the modern, machine-readable fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Per-artifact (one wheel or sdist file) record.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PyPIArtifact:
    """One uploaded file (wheel or sdist) for a given release.

    JSON path notation
    ------------------
    ``JSON:``    /pypi/<pkg>/<ver>/json -> urls[i].<field>
    ``SIMPLE:``  /simple/<pkg>/ (JSON) -> files[i].<field>  (filtered to ver)
    """

    # Filename, e.g. "kaos_graph-0.1.0a3-cp313-abi3-manylinux_2_17_x86_64.whl".
    # JSON:   urls[i].filename
    # SIMPLE: files[i].filename
    filename: str

    # Fully-qualified download URL on files.pythonhosted.org.
    # JSON:   urls[i].url
    # SIMPLE: files[i].url
    url: str

    # Size in bytes (PEP 700 added this to simple-index).
    # JSON:   urls[i].size
    # SIMPLE: files[i].size
    size_bytes: int

    # Content digests. PyPI guarantees sha256; md5 and blake2b_256 are
    # legacy/extra and may go away. Compliance MUST pin on sha256.
    # JSON:   urls[i].digests.sha256 / .md5 / .blake2b_256
    # SIMPLE: files[i].hashes.sha256   (md5/blake2b NOT in simple index)
    sha256: str
    blake2b: Optional[str] = None
    md5: Optional[str] = None

    # PEP 425 compatibility tags parsed from the wheel filename.
    # For sdists these are all None. Source of truth is the FILENAME, not
    # any JSON field -- PyPI does not break the tag out separately.
    # JSON:   parse(urls[i].filename)
    # SIMPLE: parse(files[i].filename)
    python_tag: Optional[str] = None      # e.g. "cp313", "py3"
    abi_tag: Optional[str] = None         # e.g. "abi3", "cp313", "none"
    platform_tag: Optional[str] = None    # e.g. "manylinux_2_17_x86_64"

    # Per-file requires-python (overrides project-level if present).
    # JSON:   urls[i].requires_python
    # SIMPLE: files[i].requires-python
    requires_python: Optional[str] = None

    # ISO 8601 UTC upload timestamp.
    # JSON:   urls[i].upload_time_iso_8601    (e.g. "2026-05-11T01:52:51.166205Z")
    # SIMPLE: files[i].upload-time            (PEP 700, same value)
    upload_time_iso8601: Optional[str] = None

    # PEP 740 attestation presence. Authoritative source is the simple
    # index: a non-null ``provenance`` URL means a bundle is published.
    # JSON:   urls[i].provenance   (UNRELIABLE: often null on live PyPI)
    # SIMPLE: files[i].provenance  (AUTHORITATIVE)
    has_pep740_attestation: bool = False

    # True iff fetching the provenance URL yields at least one bundle
    # whose ``attestations[].verification_material`` contains a sigstore
    # transparency-log entry. PEP 740 is the wire format; sigstore is the
    # underlying signing tech, so in practice has_sigstore == has_pep740
    # for current PyPI uploads. We track both so the dashboard does not
    # have to re-derive the distinction later.
    has_sigstore_signature: bool = False

    # The provenance bundle URL itself, for the dashboard to deep-link.
    # SIMPLE: files[i].provenance
    attestation_data_url: Optional[str] = None

    # Yank status. A yanked file is still downloadable but resolvers skip
    # it; ``yanked_reason`` is human prose set by the uploader.
    # JSON:   urls[i].yanked / urls[i].yanked_reason
    # SIMPLE: files[i].yanked  (bool OR string -- string means yanked+reason)
    yanked: bool = False
    yanked_reason: Optional[str] = None

    # "bdist_wheel" or "sdist". Wheels can be inspected for abi3/musllinux;
    # sdists cannot.
    # JSON:   urls[i].packagetype
    # SIMPLE: derive from filename (".whl" vs ".tar.gz")
    packagetype: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-release aggregate (all artifacts for one version of one project).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PyPIRelease:
    """All compliance-relevant facts about one (project, version) pair."""

    # JSON: info.name + info.version
    project: str
    version: str

    # JSON: info.project_url (canonical pypi.org page)
    project_url: str

    # JSON: info.summary
    summary: Optional[str] = None

    # PEP 639 SPDX expression, e.g. "Apache-2.0 OR MIT".
    # JSON: info.license_expression  (preferred)
    # JSON: info.license             (legacy freeform; fallback only)
    license_expression: Optional[str] = None

    # PEP 639 license filenames embedded in the dist, e.g. ["LICENSE"].
    # JSON: info.license_files
    license_files: tuple[str, ...] = ()

    # JSON: info.classifiers  (Trove)
    classifiers: tuple[str, ...] = ()

    # JSON: info.requires_python  (e.g. ">=3.10")
    requires_python: Optional[str] = None

    # PEP 508 dependency specifiers as PyPI returns them. The collector
    # is expected to parse these with ``packaging.requirements.Requirement``;
    # we keep the raw strings here so the dashboard can show what PyPI said.
    # JSON: info.requires_dist
    declared_dependencies: tuple[str, ...] = ()

    # The full list of files for this version. Order matches /simple/.
    artifacts: tuple[PyPIArtifact, ...] = ()

    # Computed: set of (python_tag, abi_tag, platform_tag) covered by wheels.
    # Source: parse each PyPIArtifact.filename. sdists contribute nothing.
    wheel_platform_matrix: tuple[tuple[str, str, str], ...] = ()

    # Computed: True iff any wheel filename matches r"-cp\d+-abi3-".
    # Stable-ABI wheels are a strong signal of a deliberate, audited build
    # rather than per-interpreter churn -- they are what kaos-graph ships.
    is_abi3: bool = False

    # Computed: True iff any wheel has a musllinux_* platform tag.
    has_musllinux_wheel: bool = False

    # Computed: True iff any artifact has packagetype == "sdist".
    has_sdist: bool = False

    # Computed: True iff ANY artifact has has_pep740_attestation or
    # has_sigstore_signature. This is the load-bearing trust signal.
    signed_release: bool = False

    # Parsed from the FIRST attestation_bundles[0].publisher object on any
    # signed artifact. Shape per PEP 740:
    #   {"kind": "GitHub"|"GitLab"|"Google"|"ActiveState",
    #    "repository": "<owner>/<repo>",        (GitHub/GitLab)
    #    "workflow": "<file>.yml",              (GitHub)
    #    "environment": "<env-name>" | null}
    # We store the dict rather than collapse to a string -- the dashboard
    # renders kind+repo+workflow separately.
    # SOURCE: /integrity/<pkg>/<ver>/<file>/provenance -> attestation_bundles[0].publisher
    uploader_trusted_publisher: Optional[dict] = field(default=None)


# ---------------------------------------------------------------------------
# Fetch contract (signature only; the collector implements this).
# ---------------------------------------------------------------------------
def fetch_release(pkg: str, version: Optional[str] = None) -> PyPIRelease:
    """Return a fully-populated ``PyPIRelease`` for ``pkg`` at ``version``.

    Call path (the implementation MUST follow this order):

    1. If ``version`` is None:
           GET https://pypi.org/pypi/<pkg>/json
       Read ``info.version`` from the response; this becomes the version.
       Otherwise:
           GET https://pypi.org/pypi/<pkg>/<version>/json
       Either way, populate ``PyPIRelease`` scalar fields from ``info``
       and ``PyPIArtifact`` rows from ``urls[]`` (digests, size, filename,
       upload_time_iso_8601, yanked, packagetype, requires_python).

    2. GET https://pypi.org/simple/<pkg>/
       with ``Accept: application/vnd.pypi.simple.v1+json``.
       For each artifact already collected in step 1, look up the matching
       ``files[]`` entry by filename and:
         - copy ``provenance`` into ``attestation_data_url``
         - set ``has_pep740_attestation = provenance is not None``
       This is mandatory because ``urls[].provenance`` in the JSON API is
       not reliably populated (verified empirically 2026-05-11).

    3. For each artifact with ``attestation_data_url`` set, optionally:
           GET <attestation_data_url>
           Accept: application/vnd.pypi.integrity.v1+json
       Set ``has_sigstore_signature = True`` if any
       ``attestation_bundles[].attestations[].verification_material``
       contains a transparency-log entry. Capture
       ``attestation_bundles[0].publisher`` into
       ``PyPIRelease.uploader_trusted_publisher``.

    4. Parse each wheel filename per PEP 425 to populate
       ``python_tag``, ``abi_tag``, ``platform_tag``, and the derived
       ``wheel_platform_matrix``, ``is_abi3``, ``has_musllinux_wheel``.

    The function MUST NOT raise on a missing provenance URL -- absence
    is itself a compliance signal and is recorded as ``signed_release=False``.
    """
    raise NotImplementedError  # collector implements; this module is the spec


# ---------------------------------------------------------------------------
# Gaps: what PyPI's public JSON does NOT expose.
# ---------------------------------------------------------------------------
# The dashboard's METHODOLOGY page MUST disclose these limits so users do
# not over-read what a green checkmark means.
#
# 1. No uploader identity beyond the Trusted Publisher claim. PyPI does
#    not reveal which human account ran ``twine upload``, the upload IP,
#    or the user-agent. For Trusted-Publisher releases the workflow run
#    is identified, but for legacy token uploads we get nothing.
#
# 2. No reproducible-build status. PyPI does not verify that the wheel
#    on disk matches a rebuild from the sdist. ``is_abi3`` and the
#    presence of an sdist are proxies, not proofs.
#
# 3. No SBOM. PyPI accepts but does not surface CycloneDX/SPDX SBOMs
#    embedded in a dist. The dashboard must download and inspect the
#    wheel itself to find ``*.spdx.json`` / ``bom.json`` under ``*.dist-info/``.
#
# 4. No vulnerability data inline. ``vulnerabilities`` exists at the top
#    of the JSON response but is populated from OSV and is best-effort;
#    absence of entries does NOT mean the release is unaffected.
#
# 5. No malware-scan results. PyPI runs internal scanners (e.g.,
#    pypi-scan, Inspector) but does not expose per-release scan verdicts
#    over the JSON API. Yanks may follow a scan but the reason is free text.
#
# 6. No per-Trusted-Publisher-claim audit log. The ``publisher`` block in
#    the PEP 740 bundle tells you which repo+workflow signed THIS file,
#    but the history of which publishers were configured for the project
#    over time is not exposed.
#
# 7. No download-counts at per-release granularity. ``info.downloads`` is
#    a stub (``-1`` values); real numbers require the BigQuery dataset or
#    pypistats.org, which are separate services.
#
# 8. No deletion history. If a maintainer deletes a release entirely
#    (not just yanks), it vanishes from /pypi/.../json with no tombstone.
#    The dashboard must keep its own historical snapshots to detect this.
#
# 9. ``info.dynamic`` (PEP 643) lists which core-metadata fields were
#    marked dynamic in pyproject.toml, but PyPI does not tell you what
#    those fields RESOLVED to at build time -- you only learn that some
#    field was non-static.
#
# 10. ``has_sig`` is a vestigial GPG-signature flag and is effectively
#     always False after PyPI removed GPG-upload support in 2023. It is
#     NOT a sigstore/PEP 740 indicator and must be ignored.
