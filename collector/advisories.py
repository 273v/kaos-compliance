"""Known-vulnerability lookup for every locked dependency (OSV.dev).

Every pin in a repo's ``uv.lock`` and ``Cargo.lock`` is checked against
`OSV.dev <https://osv.dev>`_, the aggregated feed that GitHub Advisories
(GHSA), PyPA (PYSEC) and RustSec all publish into. This is the same data
Dependabot alerts and ``pip-audit`` / ``cargo-audit`` read, collected
without a credential. The sweep's ``GITHUB_TOKEN`` cannot read another
repository's Dependabot alerts, and OSV needs no token.

Only third-party pins are queried. Editable, virtual and path packages
(the package itself, workspace members, vendored crates) carry
``is_root=True`` in :mod:`collector.sbom` and are skipped, because OSV
keys on registry name + version and a local path build is not that
registry artifact.

OSV often returns one issue under several IDs for the same package (a
PYSEC record and the GHSA record it aliases). Records whose IDs / aliases
overlap are merged into one advisory, reported under its GHSA ID.

Severity comes from the GHSA record (``database_specific.severity``:
CRITICAL / HIGH / MODERATE / LOW), fetched through the alias when only the
PYSEC record was returned. An advisory with no GHSA severity anywhere
(most RustSec entries) is counted as ``unknown`` rather than guessed.
Withdrawn advisories are dropped.

RustSec ``unmaintained`` and ``notice`` entries are informational: they
flag a crate's upkeep, not a vulnerability, and Dependabot / cargo-audit
treat them as warnings. They are reported under ``notices`` and do not
count toward ``counts``. ``unsound`` entries (memory-safety bugs) are
counted like any other advisory.

Failure policy matches the rest of the collector: if the lookup fails
after retries, ``scanned_components`` stays ``None`` and the error is
recorded, so the renderer shows gray (no signal) instead of a false
"0 advisories".
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from collector import sbom as _sbom

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
# OSV caps a querybatch request at 1000 queries.
_BATCH_SIZE = 1000
SEVERITIES = ("critical", "high", "moderate", "low", "unknown")
# RustSec informational categories that describe upkeep, not a vulnerability.
NOTICE_CATEGORIES = frozenset({"unmaintained", "notice"})


def empty_result() -> dict[str, Any]:
    """The shape emitted when no lookup ran (gray, not zero)."""
    return {
        "source": "osv.dev",
        "scanned_components": None,
        "open": [],
        "notices": [],
        "counts": {**dict.fromkeys(SEVERITIES, 0), "total": 0},
        "errors": [],
    }


def _locked_components(repo_dir: Path) -> list[Any]:
    components: list[Any] = []
    uv_lock = repo_dir / "uv.lock"
    if uv_lock.is_file():
        components.extend(_sbom.parse_uv_lock(uv_lock))
    cargo_lock = repo_dir / "Cargo.lock"
    if cargo_lock.is_file():
        components.extend(_sbom.parse_cargo_lock(cargo_lock))
    seen: set[str] = set()
    out = []
    for c in components:
        if c.is_root or c.purl in seen:
            continue
        seen.add(c.purl)
        out.append(c)
    return out


def _severity(detail: dict[str, Any]) -> str:
    raw = str((detail.get("database_specific") or {}).get("severity") or "").lower()
    return raw if raw in SEVERITIES else "unknown"


def _informational(detail: dict[str, Any]) -> str | None:
    """RustSec's non-CVE categories (``unsound``, ``unmaintained``, ...)."""
    for affected in detail.get("affected") or []:
        info = (affected.get("database_specific") or {}).get("informational")
        if info:
            return str(info)
    return None


def _alias_groups(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group records that describe the same issue.

    OSV often returns one issue under several IDs for the same package
    (e.g. ``PYSEC-2026-177`` and ``GHSA-fhv5-28vv-h8m8``, which alias each
    other). Two records belong together when their ``{id} | aliases`` sets
    intersect.
    """
    groups: list[tuple[set[str], list[dict[str, Any]]]] = []
    for rec in records:
        keys = {rec.get("id", "")} | set(rec.get("aliases") or [])
        matched = [g for g in groups if g[0] & keys]
        merged_keys = set(keys)
        merged_recs = [rec]
        for g in matched:
            merged_keys |= g[0]
            merged_recs = g[1] + merged_recs
            groups.remove(g)
        groups.append((merged_keys, merged_recs))
    return [recs for _, recs in groups]


def _merged_row(
    group: list[dict[str, Any]],
    comp: Any,
    detail_for: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """One advisory row per issue: GHSA id preferred, highest known severity."""
    ghsa = [r for r in group if str(r.get("id", "")).startswith("GHSA-")]
    primary = (ghsa or group)[0]
    severities = [_severity(r) for r in group]
    known = [s for s in severities if s != "unknown"]
    if not known:
        # Only non-GHSA records came back (e.g. PYSEC). Their GHSA alias
        # carries the severity; fetch it rather than report "unknown".
        # Best-effort: an alias OSV does not carry (404) just leaves the
        # severity unknown; it must not fail the whole scan.
        for alias in sorted({a for r in group for a in r.get("aliases") or []}):
            if not alias.startswith("GHSA-"):
                continue
            try:
                sev = _severity(detail_for(alias))
            except Exception:
                continue
            if sev != "unknown":
                known.append(sev)
                break
    severity = min(known, key=SEVERITIES.index) if known else "unknown"
    ids = {str(r["id"]) for r in group if r.get("id")}
    alias_ids = {str(a) for r in group for a in r.get("aliases") or []}
    aliases = sorted((alias_ids | ids) - {primary["id"]})
    informational = next((i for i in (_informational(r) for r in group) if i), None)
    vid = primary["id"]
    return {
        "id": vid,
        "aliases": aliases,
        "package": comp.name,
        "version": comp.version,
        "ecosystem": comp.ecosystem,
        "severity": severity,
        "informational": informational,
        "summary": (primary.get("summary") or "")[:200],
        "url": f"https://osv.dev/vulnerability/{vid}",
    }


def collect(
    repo_dir: Path | None,
    *,
    url_post_json: Callable[..., Any],
    url_get_json: Callable[..., Any],
) -> dict[str, Any]:
    """Return open advisories for the repo's locked dependencies.

    Args:
        repo_dir: Local clone of the repo, or ``None`` when unavailable.
        url_post_json: POST-JSON callable (retrying), injected for tests.
        url_get_json: GET-JSON callable (retrying), injected for tests.
    """
    result = empty_result()
    if repo_dir is None:
        result["errors"].append("advisories: no local clone to read lockfiles from")
        return result
    try:
        components = _locked_components(repo_dir)
    except Exception as exc:
        result["errors"].append(f"advisories: lockfile parse failed: {exc}")
        return result

    hits: dict[str, list[str]] = {}
    try:
        for start in range(0, len(components), _BATCH_SIZE):
            chunk = components[start : start + _BATCH_SIZE]
            resp = url_post_json(
                OSV_QUERYBATCH_URL,
                {"queries": [{"package": {"purl": c.purl}} for c in chunk]},
            )
            for comp, res in zip(chunk, resp.get("results") or [], strict=False):
                ids = [v["id"] for v in (res or {}).get("vulns") or [] if v.get("id")]
                if ids:
                    hits[comp.purl] = ids
    except Exception as exc:
        result["errors"].append(f"advisories: OSV query failed: {exc}")
        return result

    details: dict[str, dict[str, Any]] = {}

    def detail_for(vid: str) -> dict[str, Any]:
        if vid not in details:
            details[vid] = url_get_json(OSV_VULN_URL.format(id=vid))
        return details[vid]

    open_rows: list[dict[str, Any]] = []
    try:
        for comp in components:
            live = [
                d
                for d in (detail_for(v) for v in hits.get(comp.purl, []))
                if not d.get("withdrawn")
            ]
            for group in _alias_groups(live):
                open_rows.append(_merged_row(group, comp, detail_for))
    except Exception as exc:
        result["errors"].append(f"advisories: OSV detail lookup failed: {exc}")
        return result

    notices = [r for r in open_rows if r["informational"] in NOTICE_CATEGORIES]
    vulns = [r for r in open_rows if r["informational"] not in NOTICE_CATEGORIES]
    counts = {**dict.fromkeys(SEVERITIES, 0), "total": len(vulns)}
    for row in vulns:
        counts[row["severity"]] += 1

    def order(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(rows, key=lambda r: (SEVERITIES.index(r["severity"]), r["id"]))

    result.update(
        {
            "scanned_components": len(components),
            "open": order(vulns),
            "notices": order(notices),
            "counts": counts,
        }
    )
    return result
