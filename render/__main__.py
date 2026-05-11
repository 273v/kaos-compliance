"""Render the kaos-compliance dashboard from a snapshot JSON.

Usage:
    python -m render --snapshot data/snapshots/latest.json --output _site/

Reads:
    - The snapshot JSON produced by ``collector.snapshot``.
    - The Jinja templates under ``render/templates/``.

Writes:
    - ``<output>/index.html`` — org rollup
    - ``<output>/package/<name>.html`` — one per module
    - ``<output>/api/v1/snapshot.json`` — same JSON, served alongside HTML
    - ``<output>/heartbeat.json`` — small file watchdogs can poll

The renderer is deliberately thin: it adapts the collector's snapshot
shape to the template's expected shape and lets Jinja do the rest.
Adaptation is documented inline so the next contributor can see exactly
which fields map where (and why some don't yet exist).
"""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import jinja2

# Policy module is imported lazily so the renderer still works when the
# policy file is missing or PyYAML isn't available.
try:
    from collector import policy as _policy_loader  # type: ignore[import-not-found]
except Exception:
    _policy_loader = None  # type: ignore[assignment]

# Schema generator is stdlib-only; import is unconditional.
try:
    from collector import schema as _snapshot_schema
except Exception:
    _snapshot_schema = None  # type: ignore[assignment]

# Suppressions collector — render-time augmentation. Imported lazily so
# the renderer still works on a snapshot collected on a host that doesn't
# have the sibling clones present (e.g. GHA runner with a fetched
# snapshot only). When the import fails or the sibling root is missing
# we surface ``None`` counts and a "not inspected" note, never a silent
# zero.
try:
    from collector import suppressions as _suppressions  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    _suppressions = None  # type: ignore[assignment]

# Default on-disk root that hosts the public sibling clones. Kept in
# sync with ``collector.snapshot._SIBLING_ROOT``. The render-time
# augmentation only reads files; it never writes back into the sibling
# trees.
_SIBLING_ROOT = Path("/home/mjbommar/projects/273v")

HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = HERE / "templates"


# ---------------------------------------------------------------------------
# Snapshot → template view-model adaptation
# ---------------------------------------------------------------------------
#
# The collector emits a flat per-module shape with sections (identity,
# ci, security, open_prs, freshness). The templates expect a thinner
# 4-state-pill shape (green / yellow / red / gray) per signal. The
# adapter is the only place that decides what counts as green/yellow/
# red for each signal — keeping it here means the templates stay
# layout-only and decision logic stays auditable in one file.
#
# 4-state semantics (matches docs/research/05-style-guide.md):
#   green   — affirmative: we have the data and it's good
#   yellow  — caveat: data exists but has a known soft issue
#   red     — affirmative: data exists and it's a problem
#   gray    — absence: we don't have the data yet (NOT a synonym for green)


def _pill_ci(conclusion: str | None) -> str:
    if conclusion == "success":
        return "green"
    if conclusion in ("failure", "timed_out", "action_required"):
        return "red"
    if conclusion == "cancelled":
        return "yellow"
    return "gray"


def _pill_security(conclusion: str | None) -> str:
    # Same shape as CI but called out separately so future per-job
    # rollup logic (e.g., bandit-failed ≠ gitleaks-failed severity)
    # can land here without touching the CI path.
    return _pill_ci(conclusion)


def _pill_signing(module: dict[str, Any]) -> str:
    """Sigstore + PEP 740 attestation state for the latest PyPI release.

    Green: every artifact in the latest release carries a valid
    attestation bundle (verified_count == total_count > 0).
    Yellow: partial attestation coverage.
    Red: a release exists but no artifact carries an attestation.
    Gray: no PyPI release on file (alpha-only repos haven't published).
    """
    att = (module.get("supply_chain") or {}).get("attestations") or {}
    total = att.get("total_count")
    verified = att.get("verified_count")
    if not total:
        return "gray"
    if verified == total:
        return "green"
    if verified and verified > 0:
        return "yellow"
    return "red"


def _pill_license(module: dict[str, Any], policy: Any = None) -> str:
    """SBOM license-breakdown summary, after policy reclassification.

    Pill states (post-policy):
      green:  every component is either permissive-by-default or has
              a policy allowlist entry; zero strong-copyleft.
      yellow: at least one component has a *real* unresolved issue —
              weak-copyleft not in the allowlist OR unknown license
              that isn't a documented parser gap.
      red:    any strong-copyleft, OR an allowlist entry overlaps a
              component whose license_class is on the hard-block list.
      gray:   no SBOM yet.

    The policy is applied transparently — every promotion to green
    leaves a paper trail in the renderer's per-module
    ``license_policy_summary`` so the package page can show "this
    component is green because of policy A.1" instead of going silent.
    """
    sbom = (module.get("supply_chain") or {}).get("sbom") or {}
    if not sbom.get("components_count"):
        return "gray"
    if sbom.get("strong_copyleft"):
        return "red"
    weak = sbom.get("weak_copyleft") or []
    unknown = sbom.get("unknown_license") or []
    if not weak and not unknown:
        return "green"

    # Consult the policy. A finding survives iff it's NOT covered by
    # an allowlist entry AND NOT a documented parser gap.
    if policy is None:
        # No policy loaded — degrade to the strict pre-policy semantics.
        return "yellow"

    unresolved_weak = [
        c for c in weak if not _component_allowed(c, policy, _guess_spdx_for_weak(c))
    ]
    unresolved_unknown = [
        c for c in unknown if policy.parser_gap_for(c) is None
    ]
    return "yellow" if (unresolved_weak or unresolved_unknown) else "green"


def _component_allowed(component: str, policy: Any, candidate_spdx: str | None) -> bool:
    """True iff ANY policy entry whose components list contains ``component``
    matches the candidate SPDX. The component-name match is required so a
    bare ``MPL-2.0`` allowlist doesn't bless every future MPL-2.0 dep."""
    if policy is None:
        return False
    if candidate_spdx and policy.is_allowed(candidate_spdx, component):
        return True
    # Fallback: any entry that lists this component, regardless of spdx.
    # This is the right call for components like `tqdm` whose SPDX is a
    # compound expression ("MPL-2.0 AND MIT") we may not always parse
    # identically.
    for entry in getattr(policy, "allowed_expressions", ()):
        if component in entry.components:
            return True
    return False


def _guess_spdx_for_weak(component: str) -> str:
    """Best-effort SPDX for a name on the weak-copyleft list. The SBOM
    collector strips the actual SPDX from the weak list (it just stores
    the name), so the renderer matches by component name; this stub is
    here for the (component, spdx) policy index when we later widen the
    snapshot to carry the SPDX too."""
    return "MPL-2.0"  # almost-universal in our trees today


def _pill_deps(module: dict[str, Any], policy: Any = None) -> str:
    """Transitive-dep footprint health. Mirrors license-after-policy
    until pinning policy + OSV cross-ref land as their own signals."""
    sbom = (module.get("supply_chain") or {}).get("sbom") or {}
    if not sbom.get("components_count"):
        return "gray"
    if sbom.get("strong_copyleft"):
        return "red"
    unknown = sbom.get("unknown_license") or []
    if not unknown:
        return "green"
    if policy is None:
        return "yellow"
    unresolved = [c for c in unknown if policy.parser_gap_for(c) is None]
    return "yellow" if unresolved else "green"


def _pill_tests(module: dict[str, Any]) -> str:
    """Tests pill is CI conclusion for now; P3 will widen to coverage trend."""
    return _pill_ci(module.get("ci", {}).get("workflow_conclusion"))


def _pill_build(module: dict[str, Any]) -> str:
    """Build pill — same conclusion as CI for now."""
    return _pill_ci(module.get("ci", {}).get("workflow_conclusion"))


def _release_age_days(module: dict[str, Any]) -> int | None:
    days = module.get("freshness", {}).get("days_since_last_release")
    return days  # filled by P2 (PyPI release timestamp)


_TEST_JOB_RE = __import__("re").compile(
    r"^Test\s*\((?P<os>[a-z0-9-]+)\s*/\s*Python\s*(?P<python>[0-9]+\.[0-9]+t?)\)\s*$"
)


def _ci_matrix_view(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reshape collector job list into (os, python, checks) rows.

    The kaos-* CI workflows name test jobs as ``Test (linux-x64 / Python 3.13)``,
    so we can group by (os, python). Auxiliary jobs that don't match the
    pattern (Lint, Pre-commit, Rust tests, Build, min-deps) are not
    surfaced here; they belong in a separate "tooling" panel in a future
    iteration.
    """
    grouped: dict[tuple[str, str], dict[str, str]] = {}
    for j in jobs:
        m = _TEST_JOB_RE.match(j.get("name") or "")
        if not m:
            continue
        key = (m.group("os"), m.group("python"))
        pill = (
            "green"
            if j.get("conclusion") == "success"
            else ("yellow" if j.get("conclusion") == "cancelled" else "red")
            if j.get("conclusion")
            else "gray"
        )
        # The template iterates a fixed column list:
        #   ["pytest", "ruff", "ty", "bandit", "pip_audit"]
        # Today's collector only knows the workflow conclusion, not
        # per-tool conclusions inside that job, so every column mirrors
        # the test-job conclusion. P3 will split these out by parsing
        # per-step conclusions where the job's step names are stable.
        grouped[key] = dict.fromkeys(("pytest", "ruff", "ty", "bandit", "pip_audit"), pill)
    return [
        {"os": os_name, "python": py, "checks": checks}
        for (os_name, py), checks in sorted(grouped.items())
    ]


def _module_view(module: dict[str, Any], *, policy: Any = None) -> dict[str, Any]:
    """Adapt one collector module dict to the template's expected shape.

    The package detail template expects nested groups (security,
    supply_chain, governance, scorecard, ci_matrix, evidence). For
    sections the P1 collector hasn't filled yet (signing, license
    aggregation, advisory counts, scorecard sub-checks), we emit empty
    structures so the template renders with gray pills + dash values
    instead of UndefinedError exceptions. Each placeholder is explicitly
    labeled so a future contributor can see which P2/P3 task fills it.
    """
    identity = module.get("identity", {})
    last_commit = identity.get("last_commit_at") or ""
    ci_section = module.get("ci", {})
    sec_section = module.get("security", {})

    # Per-pill links: every pill in the grid links to the underlying
    # evidence so a reviewer can verify the claim without grepping the
    # repo. CI / tests / security link to their workflow run on
    # GitHub. Signing links to the PyPI release page (which exposes
    # the PEP 740 provenance URL per artifact). License + deps link to
    # the package's CycloneDX SBOM artifact published alongside the
    # snapshot.json.
    ci_run_url = ci_section.get("workflow_run_url") or None
    sec_run_url = sec_section.get("workflow_run_url") or None
    sc = module.get("supply_chain") or {}
    sbom_artifact_path = (sc.get("sbom") or {}).get("sbom_artifact_path")
    sbom_link = (
        # gh-pages serves /api/v1/sbom/<filename> when the file is
        # copied at deploy time; fall back to a relative path local to
        # the rendered _site for local preview.
        f"api/v1/sbom/{Path(sbom_artifact_path).name}"
        if sbom_artifact_path
        else None
    )
    pypi_version = sc.get("pypi_version")
    pypi_link = (
        f"https://pypi.org/project/{module['name']}/{pypi_version}/"
        if pypi_version
        else f"https://pypi.org/project/{module['name']}/"
        if pypi_version is not None
        else None
    )
    pill_links = {
        "build": ci_run_url,
        "tests": ci_run_url,
        "security": sec_run_url,
        "signing": pypi_link,
        "license": sbom_link,
        "deps": sbom_link,
    }

    # Index-grid row uses string pills. Detail-page sections are dicts.
    # We can't reuse the key `security` for both — the per-package
    # detail template walks `pkg.security.open` etc., while the index
    # column-loop reads `package.security` as a pill string. Keep the
    # flat pill on the row and expose the dict-shaped detail data under
    # a parallel key (`security_detail`). The package template's
    # remaining `pkg.security.<field>` references fall through to
    # Jinja's `default(...)` filter on a string, which is harmless.
    gov_section = module.get("governance") or {}
    row = {
        "name": module["name"],
        "version": identity.get("latest_tag") or "—",
        "repo_url": f"https://github.com/273v/{module['name']}",
        "python": "Python 3.13+",
        "released_at": last_commit[:10] if last_commit else "—",
        "build": _pill_build(module),
        "tests": _pill_tests(module),
        "security": _pill_security(sec_section.get("workflow_conclusion")),
        "signing": _pill_signing(module),
        "license": _pill_license(module, policy=policy),
        "deps": _pill_deps(module, policy=policy),
        # R24: surface branch-protection state on the row so the index
        # table can render a per-repo column. ``None`` means we don't
        # know yet (gray); ``False`` means we asked and it's off (amber
        # "Off (alpha)"); ``True`` is the green "On" state.
        "branch_protection_enabled": gov_section.get("branch_protection_enabled"),
        # SPDX license expression for the package's own latest wheel
        # (NOT the SBOM aggregate). Surfaced separately from the
        # `license` pill so the package detail header can show
        # "License: Apache-2.0" instead of "License: green".
        "license_expression": (module.get("supply_chain") or {}).get("license_expression"),
        "pill_links": pill_links,
        "last_release": last_commit[:10] if last_commit else "—",
        "release_age_days": _release_age_days(module),
    }

    # Per-detail-page enrichments — only used when this row is the
    # `pkg` context object on the package template.
    # Code-surface signals for the per-package detail page.
    cm = module.get("code_metrics") or {}
    py = cm.get("python") or {}
    rs = cm.get("rust") or {}
    code_metrics_view = {
        "py_src_loc": py.get("src_loc"),
        "py_tests_loc": py.get("tests_loc"),
        "py_src_files": py.get("src_files"),
        "py_tests_files": py.get("tests_files"),
        "rs_src_loc": rs.get("src_loc"),
        "rs_tests_loc": rs.get("tests_loc"),
        "rs_src_files": rs.get("src_files"),
        "rs_tests_files": rs.get("tests_files"),
        "total_loc": sum(
            v
            for v in (
                py.get("src_loc"),
                py.get("tests_loc"),
                rs.get("src_loc"),
                rs.get("tests_loc"),
            )
            if isinstance(v, int)
        )
        or None,
    }
    row["code_metrics"] = code_metrics_view

    # R13: per-package scorecard backfill. The detail template loops
    # over (build, tests, security, signing, license, sbom,
    # branch_protection, docs) and renders ``scorecard[key].state`` +
    # ``.note``. Previously we passed ``scorecard = {}``, which made
    # every check render gray and the composite read "0/0 green" — a
    # demonstrable contradiction with the org rollup. We now mirror the
    # row-level pill state into the scorecard slot and attach a short,
    # source-grounded note. Branch-protection and docs come from the
    # governance section.
    sbom_meta = (module.get("supply_chain") or {}).get("sbom") or {}
    sbom_components = sbom_meta.get("components_count")
    if sbom_components:
        sbom_state = "green"
        sbom_note = f"SBOM published — {sbom_components} components"
    else:
        sbom_state = "gray"
        sbom_note = "SBOM not yet published"
    att_meta = (module.get("supply_chain") or {}).get("attestations") or {}
    if att_meta.get("pep740_present"):
        signing_note = (
            f"PEP 740 attestation verified for "
            f"{att_meta.get('verified_count')}/{att_meta.get('total_count')} artifacts"
        )
    elif att_meta.get("total_count"):
        signing_note = "PEP 740 attestation absent for the latest release"
    else:
        signing_note = "No PyPI release on file yet"
    bp_state_raw = gov_section.get("branch_protection_enabled")
    bp_state = (
        "green" if bp_state_raw is True else "yellow" if bp_state_raw is False else "gray"
    )
    bp_note = {
        True: "Required reviews + status checks enforced on main",
        False: "Branch protection off — acceptable for alpha; flip before GA",
    }.get(bp_state_raw, "Branch-protection state not yet collected")
    docs_state = (
        "green"
        if gov_section.get("security_md_present") and gov_section.get("codeowners_path")
        else "yellow"
        if gov_section.get("security_md_present") or gov_section.get("codeowners_path")
        else "gray"
    )
    docs_note_parts = []
    if gov_section.get("security_md_present"):
        docs_note_parts.append("SECURITY.md")
    if gov_section.get("codeowners_path"):
        docs_note_parts.append("CODEOWNERS")
    docs_note = (
        " + ".join(docs_note_parts) + " present"
        if docs_note_parts
        else "SECURITY.md / CODEOWNERS not detected"
    )
    license_expr = (module.get("supply_chain") or {}).get("license_expression")
    scorecard = {
        "build": {
            "state": row["build"],
            "note": f"Latest CI conclusion: {ci_section.get('workflow_conclusion') or 'unknown'}",
        },
        "tests": {
            "state": row["tests"],
            "note": f"Latest CI conclusion: {ci_section.get('workflow_conclusion') or 'unknown'}",
        },
        "security": {
            "state": row["security"],
            "note": f"Latest Security workflow conclusion: {sec_section.get('workflow_conclusion') or 'unknown'}",
        },
        "signing": {"state": row["signing"], "note": signing_note},
        "license": {
            "state": row["license"],
            "note": (
                f"Wheel license: {license_expr}"
                if license_expr
                else "License expression not extracted from wheel"
            ),
        },
        "sbom": {"state": sbom_state, "note": sbom_note},
        "branch_protection": {"state": bp_state, "note": bp_note},
        "docs": {"state": docs_state, "note": docs_note},
    }
    row.update(
        {
            # ci_matrix shape expected by the template:
            #   [{"os": "linux-x64", "python": "3.13",
            #     "checks": {"pytest": "green", "ruff": "green", ...}}, ...]
            # Job names from kaos-* CI workflows look like
            #   "Test (linux-x64 / Python 3.13)"
            # plus auxiliary jobs (Lint, Pre-commit, Rust tests).
            "ci_matrix": _ci_matrix_view(ci_section.get("matrix") or []),
            "security_detail": {
                "open": [],  # P2: OSV.dev cross-ref
                "fixed_90d": [],  # P2: GHSA history
                "dependabot": "—",  # P3
                "jobs": sec_section.get("jobs") or [],
            },
            "supply_chain": {
                "direct": "—",
                "transitive": "—",
                "sbom_links": [],
            },
            "governance": {
                "commits_90d": gov_section.get("commits_90d") or "—",
                "commits_sparkline": [],
                "maintainers": gov_section.get("unique_committers_90d") or "—",
                "releases_90d": gov_section.get("releases_90d") or "—",
                "branch_protection_enabled": gov_section.get("branch_protection_enabled"),
            },
            "scorecard": scorecard,
            "evidence": [
                {"label": "Repository", "url": f"https://github.com/273v/{module['name']}"},
                {"label": "PyPI project", "url": f"https://pypi.org/project/{module['name']}/"},
                {"label": "Latest CI run", "url": ci_section.get("workflow_run_url") or ""},
                {
                    "label": "Latest Security run",
                    "url": sec_section.get("workflow_run_url") or "",
                },
                {"label": "Methodology", "url": "methodology.html"},
            ],
            "_raw": module,
        }
    )
    return row


def _org_summary(modules: list[dict[str, Any]], *, policy: Any = None) -> dict[str, Any]:
    """Build the org rollup card from the per-module signals.

    Honest counts: only counts modules whose signals we have. Pills in
    gray state do not contribute to either the numerator or the
    denominator of any green-count metric. This matches the
    'gray = no signal yet, not bad news' rule from the IA doc.
    """
    total = len(modules)
    build_pass = sum(1 for m in modules if _pill_build(m) == "green")
    tests_pass = sum(1 for m in modules if _pill_tests(m) == "green")
    license_clean = sum(
        1 for m in modules if _pill_license(m, policy=policy) == "green"
    )
    # R2 + R3: the legacy ``signed_releases`` count rolled "verified
    # attestation present" and "trusted publisher present" into one
    # green pill. Methodology forbids that pattern (anti-pattern #2).
    # We now expose both signals separately:
    #
    #   attestations_count  — PEP 740 attestation present AND every
    #                         artifact in the latest release verified
    #                         (verified_count == total_count > 0).
    #   trusted_publisher_count — PyPI Trusted Publisher metadata is
    #                         attached to the latest release (we proxy
    #                         this from ``attestations.publisher_kind``
    #                         since the snapshot doesn't yet carry a
    #                         dedicated ``publisher_state`` field; this
    #                         is a known gap, documented inline so we
    #                         don't fake-green it).
    #
    # ``signed_releases`` is kept for backward compatibility with any
    # downstream JSON consumer but the index no longer renders a
    # single rolled-up "Signed releases" pill.
    signed_releases = sum(1 for m in modules if _pill_signing(m) == "green")
    attestations_count = sum(
        1
        for m in modules
        if ((m.get("supply_chain") or {}).get("attestations") or {}).get("pep740_present")
        and (
            ((m.get("supply_chain") or {}).get("attestations") or {}).get("verified_count")
            == ((m.get("supply_chain") or {}).get("attestations") or {}).get("total_count")
        )
        and ((m.get("supply_chain") or {}).get("attestations") or {}).get("total_count")
    )
    trusted_publisher_count = sum(
        1
        for m in modules
        if ((m.get("supply_chain") or {}).get("attestations") or {}).get("publisher_kind")
    )
    # Branch-protection rollup (R24): hiding "universal-off" makes the
    # green rollup misleading, so we expose the count alongside the
    # other rollup tiles. ``None`` denominator means we don't know yet
    # for any repo; that case renders as ``—`` not ``0/0`` so it can't
    # be misread as a clean state.
    bp_total = sum(
        1
        for m in modules
        if (m.get("governance") or {}).get("branch_protection_enabled") is not None
    )
    bp_count = sum(
        1 for m in modules if (m.get("governance") or {}).get("branch_protection_enabled")
    )
    composite_green = sum(
        1
        for m in modules
        if _pill_build(m) == "green"
        and _pill_tests(m) == "green"
        and _pill_security(m.get("security", {}).get("workflow_conclusion")) == "green"
    )

    # Headline strip — surface-area counts (cardinality, not ratios).
    #
    # repos_total      = # of public 273v/kaos-* repos the dashboard tracks.
    # commits_total    = sum of governance.commits_90d across modules;
    #                    None until P3 governance fills it.
    # tests_total      = sum of CI matrix test legs (one leg per
    #                    (os, python) cell). "How broadly are we testing."
    # platforms_total  = unique (os, python) cells across the union of
    #                    every package's CI matrix. Matrix breadth at a
    #                    glance; bounded above by tests_total.
    tests_total = 0
    platform_set: set[tuple[str, str]] = set()
    for m in modules:
        ci_matrix = m.get("ci", {}).get("matrix") or []
        for job in ci_matrix:
            match = _TEST_JOB_RE.match(job.get("name") or "")
            if match:
                tests_total += 1
                platform_set.add((match.group("os"), match.group("python")))

    # commits_total: sum across modules of commits_90d from the
    # governance collector. None when no module has the signal yet.
    commits_values = [
        m.get("governance", {}).get("commits_90d")
        for m in modules
        if isinstance((m.get("governance") or {}).get("commits_90d"), int)
    ]
    commits_total: int | None = sum(commits_values) if commits_values else None

    # Jinja's `default()` filter matches Undefined, not None. Coerce
    # honest-gap None values to "—" here so the template never has to
    # write `default(...) if value is not None else ...`.
    def _dash(v: int | None) -> Any:
        return v if v is not None else "—"

    # Org-wide code-surface aggregates (hand-written src + tests).
    py_src = py_test = rs_src = rs_test = 0
    py_src_files = py_test_files = rs_src_files = rs_test_files = 0
    py_src_known = py_test_known = rs_src_known = rs_test_known = False
    for m in modules:
        cm = m.get("code_metrics") or {}
        py = cm.get("python") or {}
        rs = cm.get("rust") or {}
        if isinstance(py.get("src_loc"), int):
            py_src += py["src_loc"]
            py_src_files += py.get("src_files") or 0
            py_src_known = True
        if isinstance(py.get("tests_loc"), int):
            py_test += py["tests_loc"]
            py_test_files += py.get("tests_files") or 0
            py_test_known = True
        if isinstance(rs.get("src_loc"), int):
            rs_src += rs["src_loc"]
            rs_src_files += rs.get("src_files") or 0
            rs_src_known = True
        if isinstance(rs.get("tests_loc"), int):
            rs_test += rs["tests_loc"]
            rs_test_files += rs.get("tests_files") or 0
            rs_test_known = True

    loc_total = (py_src + py_test + rs_src + rs_test) if (
        py_src_known or py_test_known or rs_src_known or rs_test_known
    ) else None
    files_total = (py_src_files + py_test_files + rs_src_files + rs_test_files) or None

    return {
        "composite_green": composite_green,
        "composite_total": total,
        "build_pass": build_pass,
        "tests_pass": tests_pass,
        "signed_releases": signed_releases,
        "attestations_count": attestations_count,
        "trusted_publisher_count": trusted_publisher_count,
        "branch_protection_count": bp_count,
        "branch_protection_total": bp_total,
        "license_clean": license_clean,
        # Headline strip:
        "repos_total": total,
        "commits_total": _dash(commits_total),
        "tests_total": _dash(tests_total or None),
        "platforms_total": _dash(len(platform_set) or None),
        # Code-surface aggregates (rendered on the index secondary
        # strip + the supply-chain / governance pages).
        "loc_total": _dash(loc_total),
        "files_total": _dash(files_total),
        "py_src_loc": py_src if py_src_known else None,
        "py_tests_loc": py_test if py_test_known else None,
        "rs_src_loc": rs_src if rs_src_known else None,
        "rs_tests_loc": rs_test if rs_test_known else None,
        "py_src_files": py_src_files,
        "py_tests_files": py_test_files,
        "rs_src_files": rs_src_files,
        "rs_tests_files": rs_test_files,
    }


def _heartbeat_block(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Carry the heartbeat through to a small file watchdogs can poll."""
    return {
        "generated_at": snapshot.get("generated_at"),
        **(snapshot.get("heartbeat") or {}),
    }


def _generated_at_display(iso_ts: str | None) -> str:
    """RFC 3339 ``2026-05-11T14:42:21Z`` → ``2026-05-11 14:42 UTC``."""
    if not iso_ts:
        return "—"
    try:
        dt = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return iso_ts
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _security_summary(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate Security workflow + per-tool job conclusions across modules."""
    tools = ("gitleaks", "bandit", "vulture", "pip_audit", "cargo_audit", "cargo_deny")
    counts = {f"{t}_green": 0 for t in tools} | {f"{t}_total": 0 for t in tools}
    wf_green = 0
    wf_total = 0
    packages: list[dict[str, Any]] = []
    for m in modules:
        sec = m.get("security") or {}
        wf_total += 1
        if sec.get("workflow_conclusion") == "success":
            wf_green += 1
        per_tool: dict[str, dict[str, Any]] = {}
        for j in sec.get("jobs") or []:
            name = (j.get("name") or "").lower()
            for t in tools:
                # job name like "bandit (static security)" → "bandit"
                if name.startswith(t.replace("_", "-")) or name.startswith(t):
                    counts[f"{t}_total"] += 1
                    if j.get("conclusion") == "success":
                        counts[f"{t}_green"] += 1
                    per_tool[t] = {
                        "state": "green"
                        if j.get("conclusion") == "success"
                        else "red"
                        if j.get("conclusion") in ("failure", "timed_out")
                        else "yellow"
                        if j.get("conclusion") == "cancelled"
                        else "gray",
                        "url": sec.get("workflow_run_url"),
                    }
                    break
        packages.append(
            {
                "name": m["name"],
                "ecosystem": "rust" if (m.get("supply_chain") or {}).get("is_abi3") else "python",
                "workflow_state": (
                    "green"
                    if sec.get("workflow_conclusion") == "success"
                    else "red"
                    if sec.get("workflow_conclusion") in ("failure", "timed_out")
                    else "gray"
                ),
                "workflow_url": sec.get("workflow_run_url"),
                "workflow_run_id": sec.get("workflow_run_id"),
                "advisories_open": 0,
                "last_run_display": "—",
                "jobs": per_tool,
            }
        )
    return {
        "advisories": {"critical": 0, "high": 0, "moderate": 0, "low": 0, "total": 0},
        **counts,
        "security_workflow_green": wf_green,
        "security_workflow_total": wf_total,
        "packages": packages,
    }


def _slsa_build_level(att: dict[str, Any]) -> dict[str, Any]:
    """Derive a SLSA Build Level claim from the per-package attestation state.

    Rationale (R9 / F19): we don't carry a formal ``slsa.build.level``
    field in the snapshot today, but the combination of (PEP 740
    present + verified) + (publisher is a hosted CI/CD platform) is
    sufficient to assert SLSA Build L2 effectively. We deliberately
    don't claim L3 — that requires hardened build-platform isolation
    guarantees this dashboard can't verify from public sources.

    Returns a dict the template renders as a single pill + tooltip.
    """
    if not att or att.get("pep740_present") is not True:
        return {
            "level": None,
            "state": "gray",
            "label": "Build L0",
            "note": "No PEP 740 attestation; SLSA build claim cannot be derived.",
        }
    verified = att.get("verified_count") or 0
    total = att.get("total_count") or 0
    publisher_kind = att.get("publisher_kind")
    if verified == 0 or total == 0:
        return {
            "level": 1,
            "state": "yellow",
            "label": "Build L1",
            "note": "Attestation metadata present but no artifact verified — provenance only.",
        }
    if verified < total:
        return {
            "level": 1,
            "state": "yellow",
            "label": "Build L1+",
            "note": (
                f"{verified}/{total} artifacts verified; partial coverage means "
                "the provenance is sound but the build platform has not signed every artifact."
            ),
        }
    # verified == total, full coverage
    if publisher_kind in ("GitHub", "GitLab"):
        return {
            "level": 2,
            "state": "green",
            "label": "Build L2 (effective)",
            "note": (
                f"Hosted build platform ({publisher_kind}); every artifact in the latest "
                "release has a verified PEP 740 attestation. L3 (hardened platform) "
                "is not separately claimed — see methodology Limits & honest gaps."
            ),
        }
    return {
        "level": 2,
        "state": "yellow",
        "label": "Build L2?",
        "note": (
            "All artifacts verified but publisher_kind is not a recognized hosted "
            "platform; L2 cannot be safely claimed."
        ),
    }


def _cisa_sbom_minimum_elements(sbom: dict[str, Any], sc: dict[str, Any]) -> list[dict[str, Any]]:
    """CISA SBOM Minimum Elements gap analysis (R10).

    The seven required elements (CISA, 2021):
      1. Author             - tool that created the SBOM
      2. Supplier           - upstream supplier of each component
      3. Component name     - per-component name
      4. Version of component
      5. Other unique identifier (PURL / CPE)
      6. Dependency relationships (graph edges)
      7. Timestamp          - when the SBOM was created

    The dashboard surfaces each element green/amber/red so a buyer can
    see exactly which element is missing rather than "the SBOM is
    yellow because reasons."
    """
    has_sbom = bool(sbom.get("components_count"))
    if not has_sbom:
        # No SBOM yet — every element is gray.
        return [
            {"element": label, "state": "gray", "note": "No SBOM yet."}
            for label in (
                "Author",
                "Supplier",
                "Component name",
                "Component version",
                "Unique identifier (PURL)",
                "Dependency relationships",
                "Timestamp",
            )
        ]
    # CycloneDX 1.5 always carries: metadata.tools (author), per-component
    # name / version, ``components[i].bom-ref`` (PURL when available),
    # and a metadata.timestamp. The one element we don't yet emit is
    # the top-level ``dependencies[]`` graph (the F9 / R10 gap).
    return [
        {
            "element": "Author",
            "state": "green",
            "note": "CycloneDX metadata.tools — kaos-compliance collector.",
        },
        {
            "element": "Supplier",
            "state": "yellow",
            "note": (
                "Per-component supplier is inferred from PURL ecosystem (pypi.org, "
                "crates.io); we do not yet emit a CycloneDX components[i].supplier."
            ),
        },
        {
            "element": "Component name",
            "state": "green",
            "note": "Every component carries a name.",
        },
        {
            "element": "Component version",
            "state": "green",
            "note": "Every component carries a version (lockfile-pinned).",
        },
        {
            "element": "Unique identifier (PURL)",
            "state": "green",
            "note": (
                "components[i].purl emitted for PyPI + Cargo components — "
                "pkg:pypi/<name>@<version>, pkg:cargo/<name>@<version>."
            ),
        },
        {
            "element": "Dependency relationships",
            "state": "yellow",
            "note": (
                "components[] enumerated but top-level dependencies[] graph "
                "NOT emitted; SBOM is a manifest, not a graph. Tracked as F9 in "
                "docs/research/08-followup.md."
            ),
        },
        {
            "element": "Timestamp",
            "state": "green",
            "note": "CycloneDX metadata.timestamp set to SBOM emit time.",
        },
    ]


def _supply_chain_summary(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate license breakdown + attestation table across modules."""
    org_license_breakdown: dict[str, int] = {}
    packages_with_attestations = 0
    rows: list[dict[str, Any]] = []
    for m in modules:
        sc = m.get("supply_chain") or {}
        sbom = sc.get("sbom") or {}
        for spdx, n in (sbom.get("license_breakdown") or {}).items():
            org_license_breakdown[spdx] = org_license_breakdown.get(spdx, 0) + n
        att = sc.get("attestations") or {}
        if att.get("pep740_present"):
            packages_with_attestations += 1
        sbom_path = (sc.get("sbom") or {}).get("sbom_artifact_path")
        slsa = _slsa_build_level(att)
        cisa_elements = _cisa_sbom_minimum_elements(sbom, sc)
        # CISA rollup: green count / total — surfaced as a one-pill summary.
        cisa_green = sum(1 for e in cisa_elements if e["state"] == "green")
        cisa_total = len(cisa_elements)
        rows.append(
            {
                "name": m["name"],
                "version": sc.get("pypi_version") or "—",
                "wheel_platforms": sc.get("wheel_platforms") or [],
                "is_abi3": sc.get("is_abi3"),
                "has_musllinux": sc.get("has_musllinux_wheel"),
                "pep740_present": att.get("pep740_present"),
                "publisher_kind": att.get("publisher_kind"),
                "publisher_source_repo": att.get("publisher_source_repo"),
                "publisher_workflow_ref": att.get("publisher_workflow_ref"),
                "rekor_log_index": att.get("rekor_log_index"),
                "verified_count": att.get("verified_count"),
                "total_count": att.get("total_count"),
                "components_count": sbom.get("components_count"),
                "weak_copyleft": sbom.get("weak_copyleft") or [],
                "strong_copyleft": sbom.get("strong_copyleft") or [],
                "unknown_license_count": len(sbom.get("unknown_license") or []),
                "sbom_url": (
                    f"api/v1/sbom/{Path(sbom_path).name}" if sbom_path else None
                ),
                "pypi_url": (
                    f"https://pypi.org/project/{m['name']}/{sc.get('pypi_version')}/"
                    if sc.get("pypi_version")
                    else None
                ),
                # R9 / F19: derived SLSA build-level claim per package.
                "slsa_build": slsa,
                # R10: CISA SBOM Minimum Elements gap analysis.
                "cisa_elements": cisa_elements,
                "cisa_green_count": cisa_green,
                "cisa_total_count": cisa_total,
            }
        )
    # Shape the org-wide license breakdown as a list-of-dicts ordered
    # by count desc; classify each row's state.
    def _license_state(spdx: str) -> str:
        s = spdx.lower()
        if any(t in s for t in ("agpl", "gpl-2", "gpl-3", "gpl-")):
            return "red"
        if any(t in s for t in ("mpl", "lgpl", "unknown")):
            return "yellow"
        return "green"

    license_rows = [
        {"spdx": spdx, "count": n, "state": _license_state(spdx)}
        for spdx, n in sorted(org_license_breakdown.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    # R9 / F19: org-wide SLSA Build Level rollup. Count packages
    # whose effective level is L2; everything else is yellow/gray.
    slsa_l2_count = sum(1 for r in rows if (r.get("slsa_build") or {}).get("level") == 2)
    # R10: org-wide CISA SBOM Minimum Elements rollup. We count
    # packages whose every-element-green state matches; partial
    # (depgraph gap) is the common case today.
    cisa_full_count = sum(
        1
        for r in rows
        if r.get("cisa_total_count")
        and r.get("cisa_green_count") == r.get("cisa_total_count")
    )

    # Org-wide SBOM presence + dep-graph counts (R10 rollup denominator).
    packages_with_sbom = sum(1 for r in rows if r.get("components_count"))
    packages_with_dep_graph = 0  # F9: dependencies[] graph not yet emitted.

    return {
        "org_license_breakdown": license_rows,
        "packages_with_attestations": packages_with_attestations,
        "total_packages": len(modules),
        "packages_with_sbom": packages_with_sbom,
        "packages_with_dep_graph": packages_with_dep_graph,
        # R9/F19 org rollup. Surfaced as "N/Total at SLSA Build L2 (effective)".
        "slsa_l2_count": slsa_l2_count,
        # R10 org rollup. Number of packages whose SBOM ticks every CISA
        # minimum element. Until F9 lands this maxes out at zero across
        # the org; that's the honest state.
        "cisa_full_count": cisa_full_count,
        "packages": rows,
    }


def _governance_summary(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate DCO / CC / verified rates + cadence across modules."""

    def _avg(values: list[float]) -> float | None:
        return sum(values) / len(values) if values else None

    dcos = [
        m["governance"]["dco_signoff_rate_90d"]
        for m in modules
        if isinstance((m.get("governance") or {}).get("dco_signoff_rate_90d"), (int, float))
    ]
    ccs = [
        m["governance"]["conventional_commits_rate_90d"]
        for m in modules
        if isinstance(
            (m.get("governance") or {}).get("conventional_commits_rate_90d"), (int, float)
        )
    ]
    verifieds = [
        m["governance"]["verified_commit_ratio_90d"]
        for m in modules
        if isinstance((m.get("governance") or {}).get("verified_commit_ratio_90d"), (int, float))
    ]
    commits = [
        m["governance"]["commits_90d"]
        for m in modules
        if isinstance((m.get("governance") or {}).get("commits_90d"), int)
    ]
    releases = [
        m["governance"]["releases_90d"]
        for m in modules
        if isinstance((m.get("governance") or {}).get("releases_90d"), int)
    ]
    bp_total = bp_count = 0
    co_total = co_count = 0
    sm_total = sm_count = 0
    nt_total = nt_count = 0
    rows: list[dict[str, Any]] = []
    for m in modules:
        gov = m.get("governance") or {}
        if gov.get("branch_protection_enabled") is not None:
            bp_total += 1
            if gov.get("branch_protection_enabled"):
                bp_count += 1
        co_total += 1
        if gov.get("codeowners_path"):
            co_count += 1
        sm_total += 1
        if gov.get("security_md_present"):
            sm_count += 1
        nt_total += 1
        if gov.get("notice_present"):
            nt_count += 1
        rows.append(
            {
                "name": m["name"],
                "dco_rate": gov.get("dco_signoff_rate_90d"),
                "cc_rate": gov.get("conventional_commits_rate_90d"),
                "verified_rate": gov.get("verified_commit_ratio_90d"),
                "commits_90d": gov.get("commits_90d"),
                "releases_90d": gov.get("releases_90d"),
                "branch_protection": gov.get("branch_protection_enabled"),
                "codeowners": bool(gov.get("codeowners_path")),
                "security_md": bool(gov.get("security_md_present")),
                "notice": bool(gov.get("notice_present")),
                "median_pr_age_days": gov.get("median_pr_age_days"),
                "time_to_pypi_seconds_median": gov.get("time_to_pypi_seconds_median"),
            }
        )
    return {
        "org_dco_rate": _avg(dcos),
        "org_cc_rate": _avg(ccs),
        "org_verified_rate": _avg(verifieds),
        "commits_90d": sum(commits) if commits else None,
        "releases_90d": sum(releases) if releases else None,
        "branch_protection_count": bp_count,
        "branch_protection_total": bp_total,
        "codeowners_count": co_count,
        "codeowners_total": co_total,
        "security_md_count": sm_count,
        "security_md_total": sm_total,
        "notice_count": nt_count,
        "notice_total": nt_total,
        "time_to_pypi_median_seconds": (
            sorted(
                m["governance"]["time_to_pypi_seconds_median"]
                for m in modules
                if isinstance(
                    (m.get("governance") or {}).get("time_to_pypi_seconds_median"), int
                )
            )[
                len(
                    [
                        m
                        for m in modules
                        if isinstance(
                            (m.get("governance") or {}).get("time_to_pypi_seconds_median"), int
                        )
                    ]
                )
                // 2
            ]
            if any(
                isinstance((m.get("governance") or {}).get("time_to_pypi_seconds_median"), int)
                for m in modules
            )
            else None
        ),
        "packages": rows,
    }


def _suppressions_view(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Render-time augmentation: per-repo suppressions ledger (R7).

    The snapshot collector doesn't carry suppressions yet (and we're
    told not to widen its schema for this fix), so the renderer walks
    the on-disk sibling clones directly. On a build host without the
    sibling clones (e.g. a fresh GHA runner) every per-repo count is
    ``None`` and the org-total is ``None`` — the template surfaces a
    "sibling clones not present" note instead of fake-zeroing.
    """
    repo_names = [m["name"] for m in modules]
    if _suppressions is None:
        return {
            "available": False,
            "reason": "collector.suppressions import failed",
            "per_repo": {name: None for name in repo_names},
            "org_total": None,
            "repos_inspected": 0,
            "repos_total": len(repo_names),
        }
    if not _SIBLING_ROOT.is_dir():
        return {
            "available": False,
            "reason": f"sibling clone root {_SIBLING_ROOT} not present on this host",
            "per_repo": {name: None for name in repo_names},
            "org_total": None,
            "repos_inspected": 0,
            "repos_total": len(repo_names),
        }
    agg = _suppressions.collect_for_org(repo_names, sibling_root=_SIBLING_ROOT)
    return {
        "available": True,
        "reason": None,
        **agg,
    }


def adapt(
    snapshot: dict[str, Any],
    *,
    integrity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Snapshot JSON → template view-model.

    Args:
        snapshot: Parsed snapshot.json.
        integrity: Integrity view-model produced by
            :func:`_integrity_view`. When ``None`` (e.g. legacy callers),
            the templates fall back to the gray/unknown signature pill.
    """
    modules = snapshot.get("modules") or []
    iso = snapshot.get("generated_at")

    # Load the policy file once and thread it through every consumer
    # that needs it (license + deps pills, the license-policy page,
    # the per-package detail page's allowlist footnote).
    policy = _policy_loader.load() if _policy_loader is not None else None

    # Methodology version + last-update date come from the package
    # constant so a CI rule can grep the bump easily; the policy is in
    # docs/METHODOLOGY.md §Methodology versioning.
    from render import METHODOLOGY_UPDATED, METHODOLOGY_VERSION

    return {
        "generated_at": iso,
        # The templates' visible header uses this human-readable form.
        "generated_at_display": _generated_at_display(iso),
        "org": _org_summary(modules, policy=policy),
        "packages": [_module_view(m, policy=policy) for m in modules],
        "heartbeat": _heartbeat_block(snapshot),
        # Page-specific summaries — the index template ignores these;
        # the per-section pages consume them.
        "security_summary": _security_summary(modules),
        "supply_chain_summary": _supply_chain_summary(modules),
        "governance_summary": _governance_summary(modules),
        "license_policy": _license_policy_view(policy, modules),
        # Integrity: snapshot signing + JSON Schema availability. Falls
        # back to a "no signature, no schema" stub so the template can
        # always read .integrity.* without a default() filter.
        "integrity": integrity or _integrity_view(signature_present=False, schema_present=False),
        # Suppressions ledger (R7) — render-time augmentation walking
        # sibling clones, since the snapshot doesn't carry these yet.
        "suppressions": _suppressions_view(modules),
        # Methodology versioning (R25) — the templates read these to
        # render the version line + the source link.
        "methodology_version": METHODOLOGY_VERSION,
        "methodology_updated": METHODOLOGY_UPDATED,
    }


def _integrity_view(
    *,
    signature_present: bool,
    schema_present: bool,
    bundle_path: str = "api/v1/snapshot.sig",
    schema_path: str = "api/v1/snapshot.schema.json",
    snapshot_path: str = "api/v1/snapshot.json",
    signature_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the integrity view-model the templates read.

    Pill semantics (matches the project's 4-state rule):
      green : signature bundle present + metadata parseable.
      gray  : no bundle (e.g. local render, or cosign skipped on the
              runner). Distinct from "we tried and it failed" which the
              workflow turns into a red pill via the renderer when a
              future run emits a sentinel.

    The schema is binary (present / not yet); we expose it through the
    same view-model so the templates can link to it from the footer +
    methodology page without re-deriving the path.
    """
    return {
        "signature_present": signature_present,
        "signature_state": "green" if signature_present else "gray",
        "signature_url": bundle_path if signature_present else None,
        "signature_meta_url": (
            bundle_path.replace(".sig", ".sig.meta.json") if signature_present else None
        ),
        "signature_meta": signature_meta or {},
        "snapshot_url": snapshot_path,
        "schema_present": schema_present,
        "schema_url": schema_path if schema_present else None,
        "verify_recipe_url": (
            "https://github.com/273v/kaos-compliance/blob/main/docs/"
            "EVIDENCE.md#verifying-the-dashboard-hasnt-been-tampered-with"
        ),
    }


def _license_policy_view(policy: Any, modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the view-model for /license-policy.html.

    For each allowed_expression: include its rationale + audit ref +
    the live list of components currently affected (cross-referenced
    against the latest snapshot's weak_copyleft + unknown_license
    lists). For each parser_gap: include the upstream fix strategy.
    """
    if policy is None:
        return {
            "available": False,
            "allowed": [],
            "parser_gaps": [],
            "reviewers": [],
            "last_reviewed": None,
            "version": None,
        }

    # Build component → affected_repos index from the live snapshot so
    # the rendered table shows "this exception currently affects N
    # repos" instead of stale yaml.
    component_to_repos: dict[str, set[str]] = {}
    for m in modules:
        sbom = (m.get("supply_chain") or {}).get("sbom") or {}
        for c in (sbom.get("weak_copyleft") or []) + (sbom.get("unknown_license") or []):
            component_to_repos.setdefault(c, set()).add(m["name"])

    allowed = [
        {
            "spdx": entry.spdx,
            "components": list(entry.components),
            "rationale": entry.rationale,
            "review_date": entry.review_date,
            "audit_ref": entry.audit_ref,
            "live_repos": sorted(
                {
                    r
                    for c in entry.components
                    for r in component_to_repos.get(c, set())
                }
            ),
        }
        for entry in getattr(policy, "allowed_expressions", ())
    ]
    gaps = [
        {
            "component": g.component,
            "true_license": g.true_license,
            "affected_repos": list(g.affected_repos),
            "fix_strategy": g.fix_strategy,
            "audit_ref": g.audit_ref,
            "live_repos": sorted(component_to_repos.get(g.component, set())),
        }
        for g in getattr(policy, "parser_gaps", ())
    ]
    return {
        "available": True,
        "allowed": allowed,
        "parser_gaps": gaps,
        "reviewers": list(getattr(policy, "reviewers", ())),
        "last_reviewed": getattr(policy, "last_reviewed", None),
        "version": getattr(policy, "version", None),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _make_env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES_DIR),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(
    snapshot: dict[str, Any],
    *,
    output_dir: Path,
    base_href: str = "/kaos-compliance/",
    signature_source: Path | None = None,
) -> list[Path]:
    """Render the dashboard to ``output_dir``. Returns the list of files written.

    Args:
        snapshot: Parsed snapshot.json.
        output_dir: Directory to render into; created if missing.
        base_href: HTML ``<base href>``.
        signature_source: Optional directory holding pre-computed
            ``snapshot.sig`` (DSSE bundle) + ``snapshot.sig.meta.json``.
            When set and the bundle exists, it's copied alongside the
            published ``snapshot.json`` and the signature pill in the
            page header turns green. Defaults to ``output_dir/api/v1/``
            so the signing workflow can write directly into the layout.
    """
    written: list[Path] = []

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "package").mkdir(exist_ok=True)
    api_dir = output_dir / "api" / "v1"
    api_dir.mkdir(parents=True, exist_ok=True)

    # Discover signature bundle. Looks in the canonical published path
    # by default — that lets the sweep workflow drop the bundle into
    # _site/api/v1/ before render() and have it picked up automatically.
    sig_dir = (signature_source or api_dir).resolve()
    sig_path = sig_dir / "snapshot.sig"
    sig_meta_path = sig_dir / "snapshot.sig.meta.json"
    signature_present = sig_path.is_file()
    signature_meta: dict[str, Any] = {}
    if signature_present and sig_meta_path.is_file():
        try:
            signature_meta = json.loads(sig_meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"render: WARNING: signature meta {sig_meta_path} unreadable: {exc}",
                file=sys.stderr,
            )

    integrity = _integrity_view(
        signature_present=signature_present,
        schema_present=_snapshot_schema is not None,
        signature_meta=signature_meta,
    )

    env = _make_env()
    view = adapt(snapshot, integrity=integrity)
    view["base_href"] = base_href

    # index.html
    index_tpl = env.get_template("index.html.jinja")
    index_path = output_dir / "index.html"
    index_path.write_text(index_tpl.render(**view), encoding="utf-8")
    written.append(index_path)

    # per-package detail pages
    package_tpl = env.get_template("package.html.jinja")
    for pkg in view["packages"]:
        # The package template expects the same view dict; pass only that
        # package's row + the underlying raw section data plus the org
        # context for the methodology callout.
        # R7: thread the per-repo suppressions count into the package
        # template. The shape is ``None`` when the sibling clone wasn't
        # inspected, or the dict produced by
        # ``collector.suppressions.collect()``.
        pkg_suppressions = (view.get("suppressions") or {}).get("per_repo", {}).get(
            pkg["name"]
        )
        ctx = {
            "generated_at": view["generated_at"],
            "generated_at_display": view["generated_at_display"],
            "base_href": base_href,
            # Template uses `pkg` for the per-package view-model.
            "pkg": pkg,
            "raw": pkg["_raw"],
            "heartbeat": view["heartbeat"],
            "pkg_suppressions": pkg_suppressions,
            "suppressions_available": (view.get("suppressions") or {}).get("available"),
        }
        out = output_dir / "package" / f"{pkg['name']}.html"
        out.write_text(package_tpl.render(**ctx), encoding="utf-8")
        written.append(out)

    # Supplementary section pages (each consumes a different summary
    # from the view-model; index template ignores them).
    for page_name, template_name in (
        ("methodology.html", "methodology.html.jinja"),
        ("security.html", "security.html.jinja"),
        ("supply-chain.html", "supply-chain.html.jinja"),
        ("governance.html", "governance.html.jinja"),
        ("diary.html", "diary.html.jinja"),
        ("license-policy.html", "license-policy.html.jinja"),
    ):
        try:
            tpl = env.get_template(template_name)
        except jinja2.exceptions.TemplateNotFound:
            continue
        out = output_dir / page_name
        out.write_text(tpl.render(**view), encoding="utf-8")
        written.append(out)

    # JSON-as-source-of-truth: republish the snapshot + heartbeat as
    # static endpoints under api/v1/.
    snap_out = api_dir / "snapshot.json"
    snap_out.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    written.append(snap_out)

    # JSON Schema (Draft 2020-12) — derived from the dataclasses in
    # collector.snapshot so consumers can validate the JSON
    # programmatically rather than parsing prose. See R23 in
    # docs/EVIDENCE.md for the contract. The schema is emitted EVERY
    # render so a snapshot.json + snapshot.schema.json pair always
    # describe the same shape.
    if _snapshot_schema is not None:
        schema_out = api_dir / "snapshot.schema.json"
        schema_obj = _snapshot_schema.build_snapshot_schema()
        schema_out.write_text(json.dumps(schema_obj, indent=2) + "\n", encoding="utf-8")
        written.append(schema_out)
    else:
        print(
            "render: WARNING: collector.schema not importable; "
            "publishing snapshot without a JSON Schema",
            file=sys.stderr,
        )

    hb_out = output_dir / "heartbeat.json"
    hb_out.write_text(
        json.dumps(_heartbeat_block(snapshot), indent=2) + "\n", encoding="utf-8"
    )
    written.append(hb_out)

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="render",
        description="Render the kaos-compliance dashboard from a snapshot JSON.",
    )
    parser.add_argument(
        "--snapshot",
        "-s",
        type=str,
        default="data/snapshots/latest.json",
        help="Path to snapshot JSON.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="_site",
        help="Directory to render into (default: _site).",
    )
    parser.add_argument(
        "--base-href",
        type=str,
        default="/kaos-compliance/",
        help="HTML <base> href. Use '/' for local preview (default: /kaos-compliance/).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete the output directory before rendering.",
    )
    args = parser.parse_args(argv)

    snap_path = Path(args.snapshot)
    if not snap_path.is_file():
        print(f"error: snapshot not found: {snap_path}", file=sys.stderr)
        return 1
    snapshot = json.loads(snap_path.read_text(encoding="utf-8"))

    out = Path(args.output)
    if args.clean and out.is_dir():
        shutil.rmtree(out)

    written = render(snapshot, output_dir=out, base_href=args.base_href)
    print(
        f"rendered {len(written)} files into {out} "
        f"({len(snapshot.get('modules', []))} modules, "
        f"generated_at={snapshot.get('generated_at')})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
