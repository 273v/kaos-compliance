"""Methodology 2.0.0: scheduled lanes, dependency advisories and PR age reach the page."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from render import __main__ as render_main
from tests.test_render_integrity import _module_stub


def _snapshot(*modules: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-09-23T13:00:00Z",
        "generator": {"name": "kaos-compliance", "version": "0.0.1"},
        "heartbeat": {
            "last_full_sweep_at": "2026-09-23T13:00:00Z",
            "last_light_sweep_at": "2026-09-23T13:00:00Z",
            "last_security_sweep_at": "2026-09-23T13:00:00Z",
            "stale_threshold_hours": 26,
        },
        "modules": list(modules),
    }


def _module(name: str, **overrides: Any) -> dict[str, Any]:
    m: dict[str, Any] = copy.deepcopy(_module_stub(name))
    m["ci"].update(
        workflow_conclusion="success",
        workflow_run_url=f"https://example.test/{name}/ci",
        compat_conclusion="success",
        compat_run_url=f"https://example.test/{name}/compat",
        min_deps_conclusion="success",
        min_deps_run_url=f"https://example.test/{name}/min-deps",
    )
    m["security"].update(
        workflow_conclusion="success",
        workflow_run_url=f"https://example.test/{name}/light",
        jobs=[{"name": "gitleaks (incremental)", "conclusion": "success"}],
        full_workflow_conclusion="success",
        full_workflow_run_url=f"https://example.test/{name}/full",
        full_jobs=[
            {"name": "gitleaks (full history)", "conclusion": "success"},
            {"name": "pip-audit (resolved lock)", "conclusion": "success"},
        ],
    )
    m["advisories"] = {
        "source": "osv.dev",
        "scanned_components": 10,
        "open": [],
        "counts": {"critical": 0, "high": 0, "moderate": 0, "low": 0, "unknown": 0, "total": 0},
        "errors": [],
    }
    m["open_prs"] = {"count": 0, "titles": [], "oldest_age_days": None, "dependabot_count": 0}
    for section, values in overrides.items():
        m[section].update(values)
    return m


def test_security_summary_counts_real_advisories_and_merges_lanes() -> None:
    bad = _module(
        "kaos-bad",
        advisories={
            "open": [
                {
                    "id": "GHSA-crit",
                    "package": "anyio",
                    "version": "4.13.0",
                    "severity": "critical",
                    "url": "https://osv.dev/vulnerability/GHSA-crit",
                }
            ],
            "counts": {
                "critical": 1,
                "high": 0,
                "moderate": 0,
                "low": 0,
                "unknown": 0,
                "total": 1,
            },
        },
    )
    summary = render_main._security_summary([_module("kaos-good"), bad])
    assert summary["advisories"]["critical"] == 1
    assert summary["advisories"]["total"] == 1
    assert summary["advisories_scanned_modules"] == 2
    # gitleaks runs in both lanes: counted once per package, not per job.
    assert summary["gitleaks_total"] == 2
    # pip-audit only runs in security-full, which the old summary never read.
    assert summary["pip_audit_total"] == 2
    rows = {p["name"]: p for p in summary["packages"]}
    assert rows["kaos-bad"]["workflow_state"] == "red"
    assert rows["kaos-bad"]["advisories_open"] == 1
    assert rows["kaos-good"]["workflow_state"] == "green"


def test_unscanned_module_has_no_advisory_claim() -> None:
    m = _module("kaos-x", advisories={"scanned_components": None})
    summary = render_main._security_summary([m])
    assert summary["advisories_scanned_modules"] == 0
    assert summary["packages"][0]["advisories_open"] is None


def test_rendered_pages_show_widened_signals(tmp_path: Path) -> None:
    failing = _module(
        "kaos-bad",
        ci={"min_deps_conclusion": "failure"},
        security={"full_workflow_conclusion": "failure"},
        open_prs={"count": 4, "oldest_age_days": 45, "dependabot_count": 4},
    )
    render_main.render(_snapshot(_module("kaos-good"), failing), output_dir=tmp_path)

    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert '<th scope="col">Updates</th>' in index
    # Failing pills link to the lane that failed, not the green PR lane.
    assert "https://example.test/kaos-bad/min-deps" in index
    assert "https://example.test/kaos-bad/full" in index
    assert 'aria-label="Updates: Fail' in index

    package = (tmp_path / "package" / "kaos-bad.html").read_text(encoding="utf-8")
    assert "min-deps: failure" in package
    assert "security-full: failure" in package
    assert "oldest 45 day(s) old" in package

    security = (tmp_path / "security.html").read_text(encoding="utf-8")
    assert "0 open advisories</strong> in the locked dependencies of 2 package(s)" in security
    assert "OSV.dev" in security


def test_package_page_lists_open_advisories(tmp_path: Path) -> None:
    m = _module(
        "kaos-vuln",
        advisories={
            "open": [
                {
                    "id": "RUSTSEC-2026-0253",
                    "package": "lru",
                    "version": "0.18.1",
                    "severity": "unknown",
                    "informational": "unsound",
                    "summary": "Potential use-after-free",
                    "url": "https://osv.dev/vulnerability/RUSTSEC-2026-0253",
                }
            ],
            "counts": {
                "critical": 0,
                "high": 0,
                "moderate": 0,
                "low": 0,
                "unknown": 1,
                "total": 1,
            },
        },
    )
    render_main.render(_snapshot(m), output_dir=tmp_path)
    package = (tmp_path / "package" / "kaos-vuln.html").read_text(encoding="utf-8")
    assert "https://osv.dev/vulnerability/RUSTSEC-2026-0253" in package
    assert "unknown (unsound)" in package
    assert "across 10 locked dependencies" in package
