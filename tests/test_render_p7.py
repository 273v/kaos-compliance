"""Tests for the P7 trends/baselines/downloads work.

Covers:
  * Sparkline SVG snapshot — exact element types + aria-label format.
  * History view-model wiring through ``render()``: sparklines + diff
    show up in the rendered index.
  * Per-package "Changes since last sweep" section renders for both
    first-deploy ("no prior sweep yet") and the two-day case.
  * /api/v1/index.html lists every published endpoint + curl recipe.
  * Per-package download bundle has the expected top-level keys + is
    valid JSON.
  * /api/v1/diff/<from>/<to>.json is emitted when ≥2 days of history.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from collector import history
from render import __main__ as render_main


def _module_stub(name: str, *, ci: str = "success") -> dict[str, Any]:
    return {
        "name": name,
        "identity": {
            "pypi_version": "1.0.0",
            "pypi_url": None,
            "main_head_sha": None,
            "latest_tag": "v1.0.0",
            "latest_tag_sha": None,
            "tag_at_head": True,
            "commits_past_tag": 0,
            "repo_visibility": "public",
            "last_commit_at": "2026-05-11T00:00:00Z",
        },
        "ci": {
            "workflow_conclusion": ci,
            "workflow_run_id": 1,
            "workflow_run_url": f"https://github.com/273v/{name}/actions/runs/1",
            "head_sha": None,
            "run_completed_at": "2026-05-11T00:00:00Z",
            "matrix": [],
        },
        "security": {
            "workflow_conclusion": "success",
            "workflow_run_id": 2,
            "workflow_run_url": None,
            "jobs": [],
            "run_completed_at": "2026-05-11T00:00:00Z",
        },
        "open_prs": {"count": 0, "titles": []},
        "freshness": {
            "days_since_last_commit": 0,
            "days_since_last_release": 0,
            "days_since_last_security_scan": 0,
        },
        "supply_chain": {
            "pypi_version": "1.0.0",
            "attestations": {
                "pep740_present": True,
                "verified_count": 2,
                "total_count": 2,
                "publisher_kind": "GitHub",
                "publisher_source_repo": f"273v/{name}",
                "publisher_workflow_ref": "release.yml@pypi",
                "rekor_log_index": 42,
            },
            "sbom": {
                "components_count": 5,
                "sbom_artifact_path": f"data/sbom/{name}-1.0.0.cdx.json",
            },
            "license_expression": "Apache-2.0",
        },
        "governance": {
            "branch_protection_enabled": True,
            "commits_90d": 12,
            "releases_90d": 1,
            "codeowners_path": "CODEOWNERS",
            "security_md_present": True,
            "notice_present": True,
            "dco_signoff_rate_90d": 1.0,
            "conventional_commits_rate_90d": 1.0,
            "verified_commit_ratio_90d": 1.0,
        },
        "code_metrics": {},
        "errors": [],
    }


def _bare_module(name: str, *, ci: str = "success") -> dict[str, Any]:
    """Minimal module shape — only the sections collector.history reads."""
    return {
        "name": name,
        "ci": {"workflow_conclusion": ci},
        "security": {},
        "supply_chain": {},
        "governance": {},
    }


def _snapshot(date_iso: str, modules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": f"{date_iso}T00:00:00Z",
        "generator": {"name": "kaos-compliance", "version": "0.0.1"},
        "heartbeat": {
            "last_full_sweep_at": f"{date_iso}T00:00:00Z",
            "last_light_sweep_at": f"{date_iso}T00:00:00Z",
            "last_security_sweep_at": f"{date_iso}T00:00:00Z",
            "stale_threshold_hours": 26,
        },
        "modules": modules,
    }


# ----- _sparkline_svg ---------------------------------------------------------------


def test_sparkline_empty_series() -> None:
    svg = render_main._sparkline_svg([])
    assert svg.startswith("<svg")
    assert "no history" in svg
    assert "<script" not in svg  # JS-free by construction


def test_sparkline_single_point_renders_dot() -> None:
    svg = render_main._sparkline_svg([True], title="kaos-core Build")
    assert "<circle" in svg
    assert "<polyline" not in svg
    assert "kaos-core Build" in svg
    assert "1 day" in svg


def test_sparkline_multi_point_has_polyline_and_final_dot() -> None:
    svg = render_main._sparkline_svg([False, True, True])
    assert "<polyline" in svg
    # Final dot lands at the right end (cx near width-2).
    assert "<circle" in svg
    assert 'aria-label="' in svg


def test_sparkline_handles_none_gap() -> None:
    svg = render_main._sparkline_svg([True, None, True])
    # The gap renders as a small open marker (no fill).
    assert 'fill="none"' in svg


def test_sparkline_dimensions_default() -> None:
    svg = render_main._sparkline_svg([True, False, True])
    assert 'width="80"' in svg
    assert 'height="16"' in svg
    assert 'viewBox="0 0 80 16"' in svg


def test_sparkline_no_javascript_anywhere() -> None:
    svg = render_main._sparkline_svg([True, False, True, None])
    assert "<script" not in svg
    assert "javascript:" not in svg
    assert "onload=" not in svg
    assert "onclick=" not in svg


# ----- _history_view ----------------------------------------------------------------


def test_history_view_empty_when_no_index() -> None:
    v = render_main._history_view(None)
    assert v["available"] is False
    assert v["sparklines"] == {}
    assert v["diff"]["packages"] == {}


def test_history_view_marks_one_day_as_accumulating(tmp_path: Path) -> None:
    history.write_daily_summary(_snapshot("2026-05-11", [_bare_module("kaos-core")]), tmp_path)
    idx = history.rebuild_index(tmp_path)
    v = render_main._history_view(idx)
    assert v["available"] is True
    assert v["accumulating"] is True
    # The per-package sparkline payload is keyed by package name.
    assert "kaos-core" in v["sparklines"]


def test_history_view_decorates_diff_with_labels(tmp_path: Path) -> None:
    history.write_daily_summary(
        _snapshot("2026-05-10", [_bare_module("kaos-core", ci="failure")]), tmp_path
    )
    history.write_daily_summary(
        _snapshot("2026-05-11", [_bare_module("kaos-core", ci="success")]), tmp_path
    )
    idx = history.rebuild_index(tmp_path)
    v = render_main._history_view(idx)
    assert v["accumulating"] is False
    diffs = v["diff"]["packages"]["kaos-core"]
    labels = [d["label"] for d in diffs]
    assert "Build" in labels
    # Every item lists a from/to pair + a delta classification.
    for d in diffs:
        assert d["delta"] in ("better", "worse")


# ----- render() smoke + first-deploy --------------------------------------------------


def test_render_emits_history_files_first_deploy(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    assert (tmp_path / "api" / "v1" / "history" / "2026-05-11.json").is_file()
    assert (tmp_path / "api" / "v1" / "history.json").is_file()


def test_render_first_deploy_shows_accumulating_label(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "accumulating history" in index
    # Sparkline SVG MUST be present.
    assert '<svg class="spark"' in index


def test_render_first_deploy_package_no_prior_sweep(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    pkg_html = (tmp_path / "package" / "kaos-core.html").read_text(encoding="utf-8")
    assert "Changes since last sweep" in pkg_html
    assert "no prior sweep yet" in pkg_html


# ----- render() with two days of history --------------------------------------------


def test_render_emits_diff_endpoint_with_two_days(tmp_path: Path) -> None:
    snap_yesterday = _snapshot("2026-05-10", [_module_stub("kaos-core", ci="failure")])
    # Manually pre-seed yesterday's per-day file as the sweep workflow would.
    history.write_daily_summary(snap_yesterday, tmp_path / "api" / "v1" / "history")

    snap_today = _snapshot("2026-05-11", [_module_stub("kaos-core", ci="success")])
    render_main.render(snap_today, output_dir=tmp_path)

    diff_path = tmp_path / "api" / "v1" / "diff" / "2026-05-10" / "2026-05-11.json"
    assert diff_path.is_file()
    body = json.loads(diff_path.read_text())
    assert body["from"] == "2026-05-10"
    assert body["to"] == "2026-05-11"
    assert body["packages"]["kaos-core"]["build_pass"]["delta"] == "better"


def test_render_changes_section_with_two_days(tmp_path: Path) -> None:
    snap_yesterday = _snapshot("2026-05-10", [_module_stub("kaos-core", ci="failure")])
    history.write_daily_summary(snap_yesterday, tmp_path / "api" / "v1" / "history")

    snap_today = _snapshot("2026-05-11", [_module_stub("kaos-core", ci="success")])
    render_main.render(snap_today, output_dir=tmp_path)

    pkg_html = (tmp_path / "package" / "kaos-core.html").read_text(encoding="utf-8")
    assert "Changes since last sweep" in pkg_html
    assert "no prior sweep yet" not in pkg_html
    assert "Build" in pkg_html
    # The from/to date label is rendered in the section.
    assert "2026-05-10" in pkg_html
    assert "2026-05-11" in pkg_html


# ----- API index page ---------------------------------------------------------------


def test_api_index_page_is_emitted(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    api_index = tmp_path / "api" / "v1" / "index.html"
    assert api_index.is_file()
    body = api_index.read_text(encoding="utf-8")
    # Every published endpoint should appear.
    for path in (
        "api/v1/snapshot.json",
        "api/v1/snapshot.schema.json",
        "api/v1/snapshot.sig",
        "api/v1/history.json",
        "heartbeat.json",
        "api/v1/package/kaos-core.json",
    ):
        assert path in body, f"missing endpoint listing: {path}"
    # The page must include a curl recipe (the answer to "how do I get it").
    assert "curl " in body


def test_footer_links_api_index_from_every_page(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    for page in (
        tmp_path / "index.html",
        tmp_path / "methodology.html",
        tmp_path / "security.html",
        tmp_path / "supply-chain.html",
        tmp_path / "governance.html",
        tmp_path / "diary.html",
        tmp_path / "license-policy.html",
        tmp_path / "package" / "kaos-core.html",
    ):
        if not page.is_file():
            continue
        body = page.read_text(encoding="utf-8")
        assert "api/v1/index.html" in body, f"{page.name} missing API endpoints link"


# ----- per-package download bundles --------------------------------------------------


def test_download_bundle_emitted_per_package(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    bundle_path = tmp_path / "api" / "v1" / "package" / "kaos-core.json"
    assert bundle_path.is_file()
    body = json.loads(bundle_path.read_text())
    # Top-level shape stability — pin the keys a downstream consumer
    # would script against.
    assert set(body.keys()) == {
        "schema_version",
        "bundle_kind",
        "package",
        "version",
        "snapshot_slice",
        "sbom",
        "attestation",
    }
    assert body["bundle_kind"] == "kaos-compliance.package"
    assert body["package"] == "kaos-core"


def test_download_bundle_includes_sbom_and_attestation(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    body = json.loads((tmp_path / "api" / "v1" / "package" / "kaos-core.json").read_text())
    assert body["sbom"]["mirror_path"] == "api/v1/sbom/kaos-core-1.0.0.cdx.json"
    assert body["sbom"]["github_release_url"].endswith("v1.0.0/kaos-core-1.0.0.cdx.json")
    assert body["attestation"]["present"] is True
    assert body["attestation"]["publisher_kind"] == "GitHub"
    assert body["attestation"]["pypi_simple_index_url"] == "https://pypi.org/simple/kaos-core/"


def test_render_copies_referenced_sbom_artifact(tmp_path: Path) -> None:
    mod = _module_stub("kaos-citations")
    mod["identity"]["latest_tag"] = "v0.1.0a2"
    mod["identity"]["pypi_version"] = "0.1.0a2"
    mod["supply_chain"]["pypi_version"] = "0.1.0a2"
    mod["supply_chain"]["sbom"]["sbom_artifact_path"] = (
        "data/sbom/kaos-citations-0.1.0a2.cdx.json"
    )

    snap = _snapshot("2026-05-11", [mod])
    render_main.render(snap, output_dir=tmp_path)

    assert (
        tmp_path / "api" / "v1" / "sbom" / "kaos-citations-0.1.0a2.cdx.json"
    ).is_file()


def test_package_page_has_download_button(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path)
    pkg_html = (tmp_path / "package" / "kaos-core.html").read_text(encoding="utf-8")
    assert "Download JSON" in pkg_html
    assert "api/v1/package/kaos-core.json" in pkg_html


# ----- render() respects history_append=False --------------------------------------


def test_render_history_append_false_does_not_write(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module_stub("kaos-core")])
    render_main.render(snap, output_dir=tmp_path, history_append=False)
    # Per-day file must NOT be written when history_append is False —
    # the sweep workflow uses this when retrying a render without
    # double-counting today.
    assert not (tmp_path / "api" / "v1" / "history" / "2026-05-11.json").exists()
