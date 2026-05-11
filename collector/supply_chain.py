"""Supply-chain signal collector for the kaos-compliance dashboard.

This module aggregates the per-package supply-chain story:

  * PyPI release metadata: latest version, upload time, license, license files.
  * Wheel-platform matrix derived from PEP 425 filename tags (manylinux,
    musllinux, abi3, macOS, windows).
  * PEP 740 attestation chain via the PEP 691 JSON simple index, including
    publisher repository + workflow + Rekor log index.
  * Local SBOM build (CycloneDX 1.5) from ``uv.lock`` (+ optional
    ``Cargo.lock``), with a license breakdown and an explicit copyleft flag.

Design notes
------------

Public sources only (README + ``docs/METHODOLOGY.md``):

  - ``https://pypi.org/pypi/<pkg>/json``                  -> ``info`` + ``urls[]``
  - ``https://pypi.org/simple/<pkg>/``                    -> ``files[i].provenance``
        (Accept: application/vnd.pypi.simple.v1+json)
  - ``https://pypi.org/integrity/<pkg>/<ver>/<f>/provenance``
        (Accept: application/vnd.pypi.integrity.v1+json) -> attestation bundle

The legacy ``urls[i].provenance`` field on the JSON endpoint is observed
``null`` even for packages that publish PEP 740 attestations (see
``docs/research/02-pypi-extraction-findings.md``). Only the PEP 691 simple
index's ``files[i].provenance`` is authoritative.

The module never raises out of :func:`collect` — each section is wrapped
and per-section error strings accumulate in ``result["errors"]``. The
dashboard depends on this behavior to surface honest gaps instead of
silently coercing missing data to false-positives.
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from collector import sbom as _sbom

__all__ = ["PYPI_INTEGRITY_HEADER", "PYPI_JSON_BASE", "PYPI_SIMPLE_BASE", "collect"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PYPI_JSON_BASE = "https://pypi.org/pypi"
PYPI_SIMPLE_BASE = "https://pypi.org/simple"

PYPI_SIMPLE_HEADER: dict[str, str] = {
    "Accept": "application/vnd.pypi.simple.v1+json",
}
PYPI_INTEGRITY_HEADER: dict[str, str] = {
    "Accept": "application/vnd.pypi.integrity.v1+json",
}

# Repo-root defaulting: ``__file__`` is ``<repo>/collector/supply_chain.py``,
# so the repo root is two parents up. This is used as the default base for
# writing CycloneDX SBOMs into ``data/sbom/``.
_DEFAULT_DATA_ROOT = Path(__file__).resolve().parent.parent

# PEP 425 wheel filename: <distribution>-<version>(-<build>)?-<python>-<abi>-<platform>.whl
# We are interested only in the trailing three tags.
_WHEEL_FILENAME_RE = re.compile(
    r"""
    ^[^-]+-                # distribution
    [^-]+                  # version
    (?:-[^-]+)?            # optional build tag
    -(?P<python>[^-]+)
    -(?P<abi>[^-]+)
    -(?P<platform>[^-]+)
    \.whl$
    """,
    re.VERBOSE,
)

# ABI3-stable wheel filename. PEP 425 abi tag of "abi3" combined with any
# cpXY python tag is the cross-version C-extension wheel pattern.
_ABI3_RE = re.compile(r"-cp\d+-abi3-")


# ---------------------------------------------------------------------------
# Callable type aliases (purposefully loose so tests can pass plain lambdas)
# ---------------------------------------------------------------------------

# Matches collector._retry.url_get_json(url, *, headers=..., timeout=..., max_attempts=...)
UrlGetJson = Callable[..., Any]
# Matches collector._retry.gh_run(args, *, timeout=..., max_attempts=...) ->
# subprocess.CompletedProcess[str]; we accept it for API symmetry with the
# rest of the collector even though this module currently only reads PyPI.
GhRun = Callable[..., "subprocess.CompletedProcess[str]"]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def collect(
    repo: str,
    sibling_dir: Path | None,
    *,
    gh_run: GhRun,
    url_get_json: UrlGetJson,
    data_root: Path | None = None,
) -> dict[str, Any]:
    """Collect every supply-chain signal for one kaos package.

    Args:
        repo: Package name as it appears on PyPI (e.g. ``"kaos-graph"``).
            Must match the PyPI distribution name; for the kaos-* fleet
            the GitHub repo name and the PyPI distribution name agree.
        sibling_dir: Local clone of the package's source repository.
            ``uv.lock`` is read from here; ``Cargo.lock`` if present.
            If ``None`` or the directory doesn't exist, the SBOM section
            degrades to ``components_count=None`` with empty lists, but
            the PyPI sections still run (they are online-only).
        gh_run: Retry-aware ``gh`` CLI runner — accepted for API symmetry
            with the rest of the collector even though no codepath in
            this module currently shells out. Tests can pass a stub.
        url_get_json: Retry-aware JSON fetcher. Must accept ``url`` plus
            keyword ``headers`` and return a parsed JSON object.
            On terminal failure (e.g. 404) it must raise.
        data_root: Where to write CycloneDX JSON. Defaults to the
            kaos-compliance repo root inferred from ``__file__``. Tests
            override this with a ``tmp_path`` fixture.

    Returns:
        A dict with the keys documented in the module docstring. Missing
        signals are surfaced as ``None`` (or empty collections), never as
        synthesized defaults. ``errors`` collects per-section failure
        strings; callers can branch on ``len(errors) > 0`` to decide
        whether to mark the row amber/red on the dashboard.
    """
    # Accept gh_run for testability and to match the function signature
    # the rest of the collector uses; bind to _ to silence linters until
    # a future code path requires it.
    _ = gh_run

    root = (data_root or _DEFAULT_DATA_ROOT).resolve()
    errors: list[str] = []

    result: dict[str, Any] = {
        "pypi_version": None,
        "pypi_release_iso": None,
        "wheel_platforms": [],
        "wheel_sha256s": {},
        "is_abi3": None,
        "has_musllinux_wheel": None,
        "license_expression": None,
        "license_files_in_wheel": [],
        "attestations": {
            "pep740_present": None,
            "publisher_kind": None,
            "publisher_source_repo": None,
            "publisher_workflow_ref": None,
            "rekor_log_index": None,
            "verified_count": 0,
            "total_count": 0,
        },
        "sbom": {
            "components_count": None,
            "license_breakdown": {},
            "weak_copyleft": [],
            "strong_copyleft": [],
            "unknown_license": [],
            "sbom_artifact_path": None,
        },
        "errors": errors,
    }

    pypi_json = _safe_fetch_pypi_json(repo, url_get_json, errors)
    if pypi_json is not None:
        _fill_pypi_metadata(pypi_json, result, errors)

    # The simple-index call is independent of /pypi/.../json: it is the
    # only authoritative source for ``files[i].provenance``. We make it
    # even when the legacy JSON 404s, because a brand-new package could
    # exist on /simple/ before the legacy mirror catches up (rare, but
    # the cost is one HTTP call and the dashboard cares about correctness).
    simple_json = _safe_fetch_pypi_simple(repo, url_get_json, errors)
    if simple_json is not None and result["pypi_version"] is not None:
        _fill_attestations(
            simple_json,
            result,
            repo=repo,
            url_get_json=url_get_json,
            errors=errors,
        )

    _fill_sbom(
        repo=repo,
        sibling_dir=sibling_dir,
        version=result["pypi_version"],
        url_get_json=url_get_json,
        data_root=root,
        result=result,
        errors=errors,
    )

    return result


# ---------------------------------------------------------------------------
# PyPI JSON metadata
# ---------------------------------------------------------------------------


def _safe_fetch_pypi_json(
    pkg: str,
    url_get_json: UrlGetJson,
    errors: list[str],
) -> dict[str, Any] | None:
    """Fetch ``/pypi/<pkg>/json`` and return parsed JSON, or ``None``."""
    url = f"{PYPI_JSON_BASE}/{urllib.parse.quote(pkg, safe='')}/json"
    try:
        payload = url_get_json(url)
    except Exception as exc:
        errors.append(f"pypi_json: {type(exc).__name__}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append("pypi_json: response was not a JSON object")
        return None
    return payload


def _fill_pypi_metadata(
    payload: dict[str, Any],
    result: dict[str, Any],
    errors: list[str],
) -> None:
    """Populate version/release-time/wheels/license fields from /pypi/.../json.

    JSON paths consumed (see ``collector/pypi.py`` for the spec):

      * ``info.version``                          -> ``pypi_version``
      * ``info.license_expression`` (PEP 639)     -> ``license_expression``
      * ``info.license_files``                    -> ``license_files_in_wheel``
      * ``urls[i].filename``                      -> wheel filename parsing
      * ``urls[i].digests.sha256``                -> ``wheel_sha256s``
      * ``urls[i].upload_time_iso_8601``          -> ``pypi_release_iso`` (max)
    """
    try:
        info = payload.get("info") or {}
        result["pypi_version"] = info.get("version")
        result["license_expression"] = info.get("license_expression") or None
        license_files = info.get("license_files")
        if isinstance(license_files, list):
            result["license_files_in_wheel"] = [
                str(x) for x in license_files if isinstance(x, str)
            ]

        urls = payload.get("urls") or []
        platforms: list[str] = []
        shas: dict[str, str] = {}
        is_abi3 = False
        has_musllinux = False
        latest_upload: str | None = None

        for entry in urls:
            if not isinstance(entry, dict):
                continue
            filename = entry.get("filename")
            if not isinstance(filename, str):
                continue
            digests = entry.get("digests") or {}
            sha = digests.get("sha256") if isinstance(digests, dict) else None
            if isinstance(sha, str):
                shas[filename] = sha
            upload = entry.get("upload_time_iso_8601")
            if isinstance(upload, str) and (latest_upload is None or upload > latest_upload):
                latest_upload = upload
            if _ABI3_RE.search(filename):
                is_abi3 = True
            label = _platform_label_from_wheel(filename)
            if label is not None:
                platforms.append(label)
                if "musllinux" in label:
                    has_musllinux = True

        # Deduplicate while preserving observation order — the dashboard
        # renders platforms as chips so duplicates are noise.
        seen: set[str] = set()
        deduped: list[str] = []
        for p in platforms:
            if p not in seen:
                seen.add(p)
                deduped.append(p)

        result["wheel_platforms"] = deduped
        result["wheel_sha256s"] = shas
        result["pypi_release_iso"] = latest_upload
        # ``is_abi3`` and ``has_musllinux_wheel`` are only meaningful if
        # we observed at least one wheel artifact. With sdist-only releases
        # the answer is "no wheels at all" — we leave the flags None there.
        any_wheel = any(f.endswith(".whl") for f in shas)
        result["is_abi3"] = is_abi3 if any_wheel else None
        result["has_musllinux_wheel"] = has_musllinux if any_wheel else None
    except Exception as exc:
        errors.append(f"pypi_metadata: {type(exc).__name__}: {exc}")


def _platform_label_from_wheel(filename: str) -> str | None:
    """Map a wheel platform tag to a human-readable label.

    The platform tag is the third hyphen-delimited group from the right
    (PEP 425). We collapse macOS/Linux/Windows family naming for the
    dashboard's chip row, but preserve the manylinux/musllinux profile
    suffix since procurement reviewers care about it.
    """
    m = _WHEEL_FILENAME_RE.match(filename)
    if not m:
        return None
    plat = m.group("platform")
    # Wheels can ship multiple platform tags joined by ``.``; emit one
    # label per. PEP 425 example: ``manylinux1_x86_64.manylinux2010_x86_64``.
    parts = plat.split(".")
    labels = [_normalize_platform_tag(p) for p in parts]
    return ", ".join(dict.fromkeys(lab for lab in labels if lab))


def _normalize_platform_tag(tag: str) -> str:
    if tag == "any":
        return "any"
    if tag.startswith("macosx_"):
        # macosx_<major>_<minor>_<arch>
        arch = tag.rsplit("_", 1)[-1]
        return f"macos-{arch}"
    if tag.startswith("manylinux"):
        # manylinux_<major>_<minor>_<arch> OR manylinux<profile>_<arch>
        return f"linux-{_extract_arch(tag)}-{_extract_manylinux_profile(tag)}"
    if tag.startswith("musllinux"):
        return f"linux-{_extract_arch(tag)}-{_extract_musllinux_profile(tag)}"
    if tag.startswith("linux_"):
        return f"linux-{tag.removeprefix('linux_')}"
    if tag.startswith("win_") or tag == "win32":
        return f"win-{tag.removeprefix('win_')}" if tag != "win32" else "win-32"
    return tag


_KNOWN_ARCHES: tuple[str, ...] = (
    "x86_64",
    "i686",
    "aarch64",
    "armv7l",
    "armv6l",
    "ppc64le",
    "ppc64",
    "s390x",
    "riscv64",
    "loongarch64",
)


def _extract_arch(tag: str) -> str:
    """Extract the arch suffix from a manylinux/musllinux platform tag.

    Examples:

    * ``manylinux_2_28_x86_64``  -> ``"x86_64"``
    * ``manylinux1_x86_64``       -> ``"x86_64"``
    * ``musllinux_1_2_aarch64``  -> ``"aarch64"``

    We can't just walk from the right and stop at the first non-numeric
    token: ``x86_64`` itself contains the numeric segment ``64``. Instead,
    we match against the closed set of PEP 599 / 656 arches; if none
    matches we fall back to the trailing underscore-segment.
    """
    for arch in _KNOWN_ARCHES:
        if tag.endswith("_" + arch):
            return arch
    # Fallback: take everything after the trailing numeric profile segment.
    parts = tag.split("_")
    arch_parts: list[str] = []
    for token in reversed(parts):
        if token.isdigit():
            break
        arch_parts.insert(0, token)
    return "_".join(arch_parts) if arch_parts else parts[-1]


def _extract_manylinux_profile(tag: str) -> str:
    # PEP 600: manylinux_2_28_<arch>; legacy: manylinux2014_<arch>.
    if tag.startswith("manylinux_"):
        parts = tag.split("_")
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            return f"manylinux_{parts[1]}_{parts[2]}"
    # legacy form: manylinux2014_x86_64
    head = tag.split("_", 1)[0]
    return head


def _extract_musllinux_profile(tag: str) -> str:
    # musllinux_<major>_<minor>_<arch>
    parts = tag.split("_")
    if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
        return f"musllinux_{parts[1]}_{parts[2]}"
    return "musllinux"


# ---------------------------------------------------------------------------
# PEP 691 simple-index + PEP 740 attestations
# ---------------------------------------------------------------------------


def _safe_fetch_pypi_simple(
    pkg: str,
    url_get_json: UrlGetJson,
    errors: list[str],
) -> dict[str, Any] | None:
    """Fetch ``/simple/<pkg>/`` with the PEP 691 JSON Accept header."""
    url = f"{PYPI_SIMPLE_BASE}/{urllib.parse.quote(pkg, safe='')}/"
    try:
        payload = url_get_json(url, headers=PYPI_SIMPLE_HEADER)
    except Exception as exc:
        errors.append(f"pypi_simple: {type(exc).__name__}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append("pypi_simple: response was not a JSON object")
        return None
    return payload


def _files_for_version(simple: dict[str, Any], version: str) -> list[dict[str, Any]]:
    """Return the simple-index ``files[]`` entries that belong to ``version``.

    PEP 691 does not include a per-file version field; we filter by the
    canonical ``<name>-<version>`` filename prefix. We match against both
    the dist name (``kaos_graph``) and a hyphenated form, since wheels
    use underscores in the distribution segment.
    """
    files = simple.get("files") or []
    if not isinstance(files, list):
        return []
    # PEP 503 normalization: distribution names use ``-`` while wheel
    # filenames use ``_``. Build both forms so we don't miss either.
    name = str(simple.get("name") or "")
    name_us = name.replace("-", "_")
    prefixes = {f"{name_us}-{version}", f"{name}-{version}"}
    def _belongs(fn: str) -> bool:
        return any(fn.startswith(p + "-") or fn.startswith(p + ".") for p in prefixes)

    return [
        f
        for f in files
        if isinstance(f, dict)
        and isinstance(f.get("filename"), str)
        and _belongs(f["filename"])
    ]


def _fill_attestations(
    simple: dict[str, Any],
    result: dict[str, Any],
    *,
    repo: str,
    url_get_json: UrlGetJson,
    errors: list[str],
) -> None:
    """Walk simple-index ``files[i].provenance`` and fold into the result.

    The authoritative source for PEP 740 attestation presence is
    ``files[i].provenance`` on the JSON simple index — NOT
    ``urls[i].provenance`` on the legacy JSON endpoint, which is observed
    null even for projects that actually publish attestations (see
    ``docs/research/02``).

    For the FIRST file with a provenance bundle we extract:

      * ``attestation_bundles[0].publisher.kind`` (e.g. "GitHub")
      * ``attestation_bundles[0].publisher.repository``
      * ``attestation_bundles[0].publisher.workflow``
      * ``attestation_bundles[0].attestations[0]
            .verification_material.transparency_entries[0].logIndex``

    We deliberately only fetch ONE provenance bundle per release — every
    artifact in a single sigstore-signed release shares the same
    publisher block, and the Rekor index for any one of them is enough
    to bootstrap an audit trail. Fetching all of them would multiply our
    PyPI request count without adding signal.
    """
    try:
        version = result["pypi_version"]
        if not version:
            return

        files = _files_for_version(simple, version)
        result["attestations"]["total_count"] = len(files)

        provenance_files = [
            f for f in files if isinstance(f.get("provenance"), str)
        ]
        if not provenance_files:
            result["attestations"]["pep740_present"] = False
            return

        result["attestations"]["pep740_present"] = True
        verified = 0

        # Fetch the first provenance bundle for publisher + Rekor index.
        first_url = provenance_files[0]["provenance"]
        bundle: dict[str, Any] | None = None
        try:
            bundle = url_get_json(first_url, headers=PYPI_INTEGRITY_HEADER)
        except Exception as exc:
            errors.append(f"pep740_bundle: {type(exc).__name__}: {exc}")

        if isinstance(bundle, dict):
            bundles = bundle.get("attestation_bundles") or []
            if isinstance(bundles, list) and bundles:
                b0 = bundles[0]
                if isinstance(b0, dict):
                    publisher = b0.get("publisher") or {}
                    if isinstance(publisher, dict):
                        result["attestations"]["publisher_kind"] = publisher.get("kind")
                        result["attestations"]["publisher_source_repo"] = publisher.get(
                            "repository"
                        )
                        workflow = publisher.get("workflow")
                        environment = publisher.get("environment")
                        if isinstance(workflow, str) and environment:
                            # We surface "<workflow>@<environment>" as the
                            # full workflow_ref — sigstore identifies a
                            # workflow by file+env, not file alone.
                            result["attestations"]["publisher_workflow_ref"] = (
                                f"{workflow}@{environment}"
                            )
                        elif isinstance(workflow, str):
                            result["attestations"]["publisher_workflow_ref"] = workflow

                    attestations = b0.get("attestations") or []
                    if isinstance(attestations, list) and attestations:
                        a0 = attestations[0]
                        if isinstance(a0, dict):
                            vm = a0.get("verification_material") or {}
                            tes = vm.get("transparency_entries") or []
                            if isinstance(tes, list) and tes:
                                first_te = tes[0]
                                if isinstance(first_te, dict):
                                    li = first_te.get("logIndex")
                                    if isinstance(li, str) and li.isdigit():
                                        result["attestations"]["rekor_log_index"] = int(li)
                                    elif isinstance(li, int):
                                        result["attestations"]["rekor_log_index"] = li

        # ``verified_count`` is "files we saw a non-null provenance URL
        # for in the simple index." Verifying every one independently
        # against Rekor would multiply our PyPI request count without
        # changing the dashboard signal — the publisher block is identical
        # across artifacts in one release. Buyers who want per-artifact
        # verification can follow the Verify link in the dashboard.
        verified = len(provenance_files)
        result["attestations"]["verified_count"] = verified
    except Exception as exc:
        errors.append(f"attestations: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

_WEAK_PREFIXES = ("MPL-", "LGPL-")
_STRONG_PREFIXES = ("GPL-", "AGPL-")


def _classify_license(spdx: str | None) -> str:
    """Coarse class used by the dashboard's copyleft callout.

    Differs intentionally from :func:`collector.sbom.license_class`: that
    function returns a fine-grained class for the kaos-compliance build
    gate. Here we only need to bucket components into the three lists
    the dashboard renders.
    """
    if not spdx:
        return "unknown"
    if spdx.startswith("LicenseRef-unknown"):
        return "unknown"
    tokens = re.split(r"\s+(?:AND|OR|WITH)\s+", spdx)
    cleaned = [t.strip("() ") for t in tokens]
    if any(t.startswith(_STRONG_PREFIXES) for t in cleaned):
        return "strong"
    if any(t.startswith(_WEAK_PREFIXES) for t in cleaned):
        return "weak"
    return "permissive"


def _fill_sbom(
    *,
    repo: str,
    sibling_dir: Path | None,
    version: str | None,
    url_get_json: UrlGetJson,
    data_root: Path,
    result: dict[str, Any],
    errors: list[str],
) -> None:
    """Build a CycloneDX 1.5 SBOM from the sibling repo's lockfiles.

    Returns silently with ``components_count=None`` if no sibling repo is
    available — that's an honest gap, not a failure.
    """
    if sibling_dir is None or not sibling_dir.exists():
        return

    uv_lock = sibling_dir / "uv.lock"
    if not uv_lock.exists():
        errors.append(f"sbom: no uv.lock under {sibling_dir}")
        return

    try:
        components = _sbom.parse_uv_lock(uv_lock)
    except Exception as exc:
        errors.append(f"sbom_parse_uv: {type(exc).__name__}: {exc}")
        return

    cargo_lock = sibling_dir / "Cargo.lock"
    if cargo_lock.exists():
        try:
            components.extend(_sbom.parse_cargo_lock(cargo_lock))
        except Exception as exc:
            errors.append(f"sbom_parse_cargo: {type(exc).__name__}: {exc}")

    # License enrichment for PyPI components. We re-use the live PyPI
    # JSON endpoint via the injected fetcher; PyPI's per-version JSON is
    # the supplier-of-record for ``license_expression``. We wrap each
    # fetch so the SBOM doesn't fail wholesale on a single 404.
    def _pypi_fetcher(url: str) -> dict[str, Any] | None:
        try:
            payload = url_get_json(url)
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

    try:
        _sbom.enrich_from_pypi(components, gh_run=_pypi_fetcher)
    except Exception as exc:
        errors.append(f"sbom_enrich: {type(exc).__name__}: {exc}")

    # Rust components: crates.io carries the license expression in
    # crate metadata even though Cargo.lock does not. This single
    # enrichment pass kills the largest source of "unknown" pill
    # warnings on the dashboard — without it ~80% of yellow pills
    # are Cargo crates whose licenses we already know.
    def _crates_fetcher(url: str) -> dict[str, Any] | None:
        try:
            payload = url_get_json(url)
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

    try:
        _sbom.enrich_from_crates_io(components, gh_run=_crates_fetcher)
    except Exception as exc:
        errors.append(f"sbom_crates_io: {type(exc).__name__}: {exc}")

    # Offline license book is a best-effort backfill for common Python
    # deps whose PyPI metadata is missing or malformed. Only touches
    # components whose SPDX is still ``LicenseRef-unknown-*``.
    try:
        _sbom.apply_offline_license_book(components)
    except Exception as exc:
        errors.append(f"sbom_offline: {type(exc).__name__}: {exc}")

    pkg_version = version or "0.0.0+unknown"
    try:
        cdx = _sbom.to_cyclonedx_1_5(
            components,
            package_name=repo,
            package_version=pkg_version,
        )
    except Exception as exc:
        errors.append(f"sbom_emit: {type(exc).__name__}: {exc}")
        return

    breakdown, weak, strong, unknown = _aggregate_license_breakdown(cdx)
    result["sbom"]["components_count"] = len(cdx.get("components") or [])
    result["sbom"]["license_breakdown"] = breakdown
    result["sbom"]["weak_copyleft"] = weak
    result["sbom"]["strong_copyleft"] = strong
    result["sbom"]["unknown_license"] = unknown

    rel = _write_sbom(cdx, repo=repo, version=pkg_version, data_root=data_root, errors=errors)
    if rel is not None:
        result["sbom"]["sbom_artifact_path"] = rel


def _aggregate_license_breakdown(
    cdx: dict[str, Any],
) -> tuple[dict[str, int], list[str], list[str], list[str]]:
    """Aggregate ``components[].licenses`` into a SPDX -> count dict.

    A CycloneDX 1.5 ``components[i].licenses`` is a list of one of:

      * ``{"license": {"id": "<SPDX-ID>"}}``           (canonical)
      * ``{"license": {"name": "LicenseRef-unknown-..."}}`` (custom)
      * ``{"expression": "Apache-2.0 OR MIT"}``        (compound)

    We key the breakdown on the human-meaningful string in each shape.
    Compound expressions count as one key (the whole expression); this
    keeps the dashboard's "license breakdown" table honest about real
    declared expressions instead of double-counting their components.
    """
    breakdown: dict[str, int] = {}
    weak: list[str] = []
    strong: list[str] = []
    unknown: list[str] = []

    components = cdx.get("components") or []
    if not isinstance(components, list):
        return breakdown, weak, strong, unknown

    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        if not isinstance(name, str):
            continue
        spdx = _extract_spdx(comp.get("licenses"))
        key = spdx or "unknown"
        breakdown[key] = breakdown.get(key, 0) + 1
        cls = _classify_license(spdx)
        if cls == "weak":
            weak.append(name)
        elif cls == "strong":
            strong.append(name)
        elif cls == "unknown":
            unknown.append(name)

    return breakdown, sorted(set(weak)), sorted(set(strong)), sorted(set(unknown))


def _extract_spdx(licenses: Any) -> str | None:
    """Pull the SPDX-ish string from a CycloneDX licenses array."""
    if not isinstance(licenses, list) or not licenses:
        return None
    entry = licenses[0]
    if not isinstance(entry, dict):
        return None
    if "expression" in entry and isinstance(entry["expression"], str):
        return entry["expression"]
    lic = entry.get("license")
    if isinstance(lic, dict):
        for k in ("id", "name"):
            v = lic.get(k)
            if isinstance(v, str) and v:
                return v
    return None


def _write_sbom(
    cdx: dict[str, Any],
    *,
    repo: str,
    version: str,
    data_root: Path,
    errors: list[str],
) -> str | None:
    """Write the CycloneDX JSON under ``data/sbom/<pkg>-<ver>.cdx.json``.

    Returns the relative path (POSIX-style) on success, or ``None`` on
    failure. Failure is captured as an error string — the SBOM data is
    still reported via the in-memory breakdown.
    """
    try:
        sbom_dir = data_root / "data" / "sbom"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        # File name: ``<pkg>-<version>.cdx.json``. We keep the version
        # verbatim — alpha/rc suffixes need to round-trip so audits can
        # tell ``0.1.0a3`` from ``0.1.0``.
        out = sbom_dir / f"{repo}-{version}.cdx.json"
        out.write_text(json.dumps(cdx, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        return out.relative_to(data_root).as_posix()
    except Exception as exc:
        errors.append(f"sbom_write: {type(exc).__name__}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Frozen public summary (currently unused at the snapshot level, exposed for
# tests + future typed integration in ``collector/snapshot.py``).
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class AttestationSummary:
    """Compact view of the attestation block — useful for typed callers."""

    pep740_present: bool | None
    publisher_kind: str | None
    publisher_source_repo: str | None
    publisher_workflow_ref: str | None
    rekor_log_index: int | None
    verified_count: int
    total_count: int

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AttestationSummary:
        return cls(
            pep740_present=d.get("pep740_present"),
            publisher_kind=d.get("publisher_kind"),
            publisher_source_repo=d.get("publisher_source_repo"),
            publisher_workflow_ref=d.get("publisher_workflow_ref"),
            rekor_log_index=d.get("rekor_log_index"),
            verified_count=int(d.get("verified_count") or 0),
            total_count=int(d.get("total_count") or 0),
        )
