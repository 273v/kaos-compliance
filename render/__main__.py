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


def _pill_license(module: dict[str, Any]) -> str:
    """SBOM license-breakdown summary.

    Green: every transitive license resolves to an SPDX expression AND
        none are strong-copyleft (GPL/AGPL).
    Yellow: weak-copyleft (MPL/LGPL) is in play OR there are unknown
        licenses with no strong-copyleft (legal can bless once).
    Red: any strong-copyleft is present.
    Gray: no SBOM yet.
    """
    sbom = (module.get("supply_chain") or {}).get("sbom") or {}
    if not sbom.get("components_count"):
        return "gray"
    if sbom.get("strong_copyleft"):
        return "red"
    if sbom.get("weak_copyleft") or sbom.get("unknown_license"):
        return "yellow"
    return "green"


def _pill_deps(module: dict[str, Any]) -> str:
    """Transitive-dep footprint health.

    Mirrors license today. A future iteration will diverge — pinning
    policy, OSV cross-ref, yanked-version detection live here.
    """
    sbom = (module.get("supply_chain") or {}).get("sbom") or {}
    if not sbom.get("components_count"):
        return "gray"
    if sbom.get("strong_copyleft"):
        return "red"
    if sbom.get("unknown_license"):
        return "yellow"
    return "green"


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
        grouped[key] = {col: pill for col in ("pytest", "ruff", "ty", "bandit", "pip_audit")}
    return [
        {"os": os_name, "python": py, "checks": checks}
        for (os_name, py), checks in sorted(grouped.items())
    ]


def _module_view(module: dict[str, Any]) -> dict[str, Any]:
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
        "license": _pill_license(module),
        "deps": _pill_deps(module),
        "pill_links": pill_links,
        "last_release": last_commit[:10] if last_commit else "—",
        "release_age_days": _release_age_days(module),
    }

    # Per-detail-page enrichments — only used when this row is the
    # `pkg` context object on the package template.
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
                "commits_90d": "—",
                "commits_sparkline": [],
                "maintainers": "—",
                "releases_90d": "—",
            },
            "scorecard": {},
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


def _org_summary(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the org rollup card from the per-module signals.

    Honest counts: only counts modules whose signals we have. Pills in
    gray state do not contribute to either the numerator or the
    denominator of any green-count metric. This matches the
    'gray = no signal yet, not bad news' rule from the IA doc.
    """
    total = len(modules)
    build_pass = sum(1 for m in modules if _pill_build(m) == "green")
    tests_pass = sum(1 for m in modules if _pill_tests(m) == "green")
    license_clean = sum(1 for m in modules if _pill_license(m) == "green")  # gray for now → 0
    signed_releases = sum(1 for m in modules if _pill_signing(m) == "green")  # gray for now → 0
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

    return {
        "composite_green": composite_green,
        "composite_total": total,
        "build_pass": build_pass,
        "tests_pass": tests_pass,
        "signed_releases": signed_releases,
        "license_clean": license_clean,
        # Headline strip:
        "repos_total": total,
        "commits_total": _dash(commits_total),
        "tests_total": _dash(tests_total or None),
        "platforms_total": _dash(len(platform_set) or None),
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


def adapt(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Snapshot JSON → template view-model."""
    modules = snapshot.get("modules") or []
    iso = snapshot.get("generated_at")
    return {
        "generated_at": iso,
        # The templates' visible header uses this human-readable form.
        "generated_at_display": _generated_at_display(iso),
        "org": _org_summary(modules),
        "packages": [_module_view(m) for m in modules],
        "heartbeat": _heartbeat_block(snapshot),
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
) -> list[Path]:
    """Render the dashboard to ``output_dir``. Returns the list of files written."""
    written: list[Path] = []

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "package").mkdir(exist_ok=True)
    (output_dir / "api" / "v1").mkdir(parents=True, exist_ok=True)

    env = _make_env()
    view = adapt(snapshot)
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
        ctx = {
            "generated_at": view["generated_at"],
            "generated_at_display": view["generated_at_display"],
            "base_href": base_href,
            # Template uses `pkg` for the per-package view-model.
            "pkg": pkg,
            "raw": pkg["_raw"],
            "heartbeat": view["heartbeat"],
        }
        out = output_dir / "package" / f"{pkg['name']}.html"
        out.write_text(package_tpl.render(**ctx), encoding="utf-8")
        written.append(out)

    # JSON-as-source-of-truth: republish the snapshot + heartbeat as
    # static endpoints under api/v1/.
    snap_out = output_dir / "api" / "v1" / "snapshot.json"
    snap_out.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    written.append(snap_out)

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
