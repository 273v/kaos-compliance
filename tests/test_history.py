"""Tests for the 90-day rolling history store (collector.history).

Covers:
  * The per-day summary shape produced from a snapshot.
  * Idempotency — re-writing the same date overwrites.
  * The rolling index aggregates dates, aligns per-signal arrays,
    and trims to the configured window.
  * The baseline-diff helper classifies better/worse/same/unknown
    correctly across both boolean + integer signals.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from collector import history


def _module(
    name: str,
    *,
    ci: str | None = "success",
    sec: str | None = "success",
    pep740: bool = True,
    verified: int = 2,
    total: int = 2,
    bp: bool | None = True,
    commits: int | None = 42,
    releases: int | None = 2,
    py_src: int | None = 100,
    py_tests: int | None = 25,
    rs_src: int | None = 10,
    rs_tests: int | None = 5,
) -> dict[str, Any]:
    return {
        "name": name,
        "ci": {"workflow_conclusion": ci},
        "security": {"workflow_conclusion": sec},
        "supply_chain": {
            "attestations": {
                "pep740_present": pep740,
                "verified_count": verified,
                "total_count": total,
            }
        },
        "governance": {
            "branch_protection_enabled": bp,
            "commits_90d": commits,
            "releases_90d": releases,
        },
        "code_metrics": {
            "python": {
                "src_loc": py_src,
                "tests_loc": py_tests,
                "src_files": 3 if py_src is not None else None,
                "tests_files": 2 if py_tests is not None else None,
            },
            "rust": {
                "src_loc": rs_src,
                "tests_loc": rs_tests,
                "src_files": 1 if rs_src is not None else None,
                "tests_files": 1 if rs_tests is not None else None,
            },
        },
    }


def _snapshot(date_iso: str, modules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": f"{date_iso}T00:00:00Z",
        "modules": modules,
    }


# ----- daily_summary_from_snapshot -------------------------------------------------


def test_daily_summary_extracts_expected_fields() -> None:
    """The per-day summary captures the six tracked signals per module."""
    snap = _snapshot("2026-05-11", [_module("kaos-core")])
    summary = history.daily_summary_from_snapshot(snap)
    assert summary["date"] == "2026-05-11"
    assert summary["schema_version"] == history.HISTORY_SCHEMA_VERSION
    assert summary["modules"][0]["name"] == "kaos-core"
    assert summary["modules"][0]["build_pass"] is True
    assert summary["modules"][0]["tests_pass"] is True
    assert summary["modules"][0]["security_pass"] is True
    assert summary["modules"][0]["attestation_present"] is True
    assert summary["modules"][0]["branch_protection_enabled"] is True
    assert summary["modules"][0]["commits_90d"] == 42
    assert summary["modules"][0]["releases_90d"] == 2
    assert summary["modules"][0]["loc_total"] == 140
    assert summary["modules"][0]["src_loc"] == 110
    assert summary["modules"][0]["tests_loc"] == 30
    assert summary["modules"][0]["files_total"] == 7


def test_daily_summary_attestation_partial_is_not_present() -> None:
    """Attestation present iff verified == total and total > 0."""
    snap = _snapshot("2026-05-11", [_module("kaos-core", verified=1, total=2)])
    summary = history.daily_summary_from_snapshot(snap)
    assert summary["modules"][0]["attestation_present"] is False


def test_daily_summary_handles_missing_signals_as_none() -> None:
    """A module with bare sections still produces a row — None for missing ints."""
    snap = _snapshot(
        "2026-05-11",
        [
            {
                "name": "kaos-empty",
                "ci": {},
                "security": {},
                "supply_chain": {},
                "governance": {},
            }
        ],
    )
    summary = history.daily_summary_from_snapshot(snap)
    row = summary["modules"][0]
    assert row["build_pass"] is False
    assert row["attestation_present"] is False
    assert row["branch_protection_enabled"] is None
    assert row["commits_90d"] is None
    assert row["releases_90d"] is None
    assert row["loc_total"] is None
    assert row["files_total"] is None


# ----- write_daily_summary + idempotency -------------------------------------------


def test_write_daily_summary_is_idempotent(tmp_path: Path) -> None:
    """Two writes for the same UTC date overwrite (last write wins)."""
    snap1 = _snapshot("2026-05-11", [_module("kaos-core", ci="success")])
    snap2 = _snapshot("2026-05-11", [_module("kaos-core", ci="failure")])
    p1 = history.write_daily_summary(snap1, tmp_path)
    p2 = history.write_daily_summary(snap2, tmp_path)
    assert p1 == p2
    body = json.loads(p2.read_text())
    assert body["modules"][0]["build_pass"] is False
    # Only one file on disk for the day.
    assert sorted(p.name for p in tmp_path.glob("*.json")) == ["2026-05-11.json"]


# ----- rebuild_index ----------------------------------------------------------------


def test_rebuild_index_with_no_files(tmp_path: Path) -> None:
    """Empty history dir → empty index, no errors."""
    idx = history.rebuild_index(tmp_path)
    assert idx["dates"] == []
    assert idx["packages"] == {}
    assert idx["first_date"] is None
    assert idx["last_date"] is None
    assert idx["window_days"] == history.HISTORY_DAYS


def test_rebuild_index_aligns_per_signal_arrays(tmp_path: Path) -> None:
    """Per-package per-signal array length equals |dates|; values aligned."""
    history.write_daily_summary(
        _snapshot("2026-05-09", [_module("kaos-core", ci="success", commits=10)]),
        tmp_path,
    )
    history.write_daily_summary(
        _snapshot("2026-05-10", [_module("kaos-core", ci="failure", commits=12)]),
        tmp_path,
    )
    history.write_daily_summary(
        _snapshot("2026-05-11", [_module("kaos-core", ci="success", commits=14)]),
        tmp_path,
    )
    idx = history.rebuild_index(tmp_path)
    assert idx["dates"] == ["2026-05-09", "2026-05-10", "2026-05-11"]
    arr = idx["packages"]["kaos-core"]["build_pass"]
    assert arr == [True, False, True]
    assert idx["packages"]["kaos-core"]["commits_90d"] == [10, 12, 14]


def test_rebuild_index_pads_late_arrivals_with_none(tmp_path: Path) -> None:
    """A package that only appears on day 2 gets ``None`` for day 1."""
    history.write_daily_summary(_snapshot("2026-05-10", [_module("kaos-core")]), tmp_path)
    history.write_daily_summary(
        _snapshot("2026-05-11", [_module("kaos-core"), _module("kaos-cli")]),
        tmp_path,
    )
    idx = history.rebuild_index(tmp_path)
    assert idx["packages"]["kaos-cli"]["build_pass"] == [None, True]


def test_rebuild_index_trims_to_window(tmp_path: Path) -> None:
    """Files older than ``window_days`` are dropped from the index."""
    for i, day in enumerate(
        (
            "2026-01-01",
            "2026-01-02",
            "2026-01-03",
            "2026-01-04",
            "2026-01-05",
        )
    ):
        history.write_daily_summary(_snapshot(day, [_module("kaos-core", commits=i)]), tmp_path)
    idx = history.rebuild_index(tmp_path, days=3)
    assert idx["dates"] == ["2026-01-03", "2026-01-04", "2026-01-05"]


def test_write_index_emits_a_file(tmp_path: Path) -> None:
    history.write_daily_summary(_snapshot("2026-05-11", [_module("kaos-core")]), tmp_path)
    idx_path = tmp_path.parent / "history.json"
    history.write_index(tmp_path, index_path=idx_path)
    assert idx_path.is_file()
    obj = json.loads(idx_path.read_text())
    assert obj["dates"] == ["2026-05-11"]


def test_append_and_index_one_shot(tmp_path: Path) -> None:
    snap = _snapshot("2026-05-11", [_module("kaos-core")])
    per_day, idx = history.append_and_index(
        snap, history_dir=tmp_path / "h", index_path=tmp_path / "history.json"
    )
    assert per_day.is_file()
    assert idx.is_file()
    obj = json.loads(idx.read_text())
    assert obj["last_date"] == "2026-05-11"


# ----- diff_packages ----------------------------------------------------------------


def test_diff_returns_none_with_only_one_day(tmp_path: Path) -> None:
    history.write_daily_summary(_snapshot("2026-05-11", [_module("kaos-core")]), tmp_path)
    idx = history.rebuild_index(tmp_path)
    d = history.diff_packages(idx)
    assert d["from"] is None
    assert d["packages"] == {}


def test_diff_classifies_better_worse_same(tmp_path: Path) -> None:
    """One-day → next-day delta classification across the three states."""
    history.write_daily_summary(
        _snapshot("2026-05-10", [_module("kaos-core", ci="failure", commits=10)]),
        tmp_path,
    )
    history.write_daily_summary(
        _snapshot("2026-05-11", [_module("kaos-core", ci="success", commits=10)]),
        tmp_path,
    )
    idx = history.rebuild_index(tmp_path)
    d = history.diff_packages(idx)
    assert d["from"] == "2026-05-10"
    assert d["to"] == "2026-05-11"
    sig = d["packages"]["kaos-core"]
    assert sig["build_pass"]["delta"] == "better"
    assert sig["commits_90d"]["delta"] == "same"


def test_diff_worse_when_signal_regresses(tmp_path: Path) -> None:
    history.write_daily_summary(
        _snapshot("2026-05-10", [_module("kaos-core", ci="success")]), tmp_path
    )
    history.write_daily_summary(
        _snapshot("2026-05-11", [_module("kaos-core", ci="failure")]), tmp_path
    )
    idx = history.rebuild_index(tmp_path)
    d = history.diff_packages(idx)
    assert d["packages"]["kaos-core"]["build_pass"]["delta"] == "worse"


def test_diff_unknown_with_none_signal() -> None:
    """None on either side → unknown classification."""
    assert history._classify_delta("build_pass", None, True) == "unknown"
    assert history._classify_delta("build_pass", True, None) == "unknown"
    assert history._classify_delta("commits_90d", None, 1) == "unknown"


def test_previous_sweep_date_helper(tmp_path: Path) -> None:
    history.write_daily_summary(_snapshot("2026-05-10", [_module("kaos-core")]), tmp_path)
    history.write_daily_summary(_snapshot("2026-05-11", [_module("kaos-core")]), tmp_path)
    idx = history.rebuild_index(tmp_path)
    assert history.previous_sweep_date(idx) == "2026-05-10"


def test_diff_with_explicit_dates(tmp_path: Path) -> None:
    """from/to overrides let the renderer build a 1-day-vs-N-days-ago diff."""
    history.write_daily_summary(
        _snapshot("2026-05-09", [_module("kaos-core", ci="success")]), tmp_path
    )
    history.write_daily_summary(
        _snapshot("2026-05-10", [_module("kaos-core", ci="success")]), tmp_path
    )
    history.write_daily_summary(
        _snapshot("2026-05-11", [_module("kaos-core", ci="failure")]), tmp_path
    )
    idx = history.rebuild_index(tmp_path)
    d = history.diff_packages(idx, from_date="2026-05-09", to_date="2026-05-11")
    assert d["packages"]["kaos-core"]["build_pass"]["delta"] == "worse"


def test_diff_only_surfaces_packages_with_changes(tmp_path: Path) -> None:
    """A package that's identical between sweeps is omitted from the diff."""
    history.write_daily_summary(
        _snapshot(
            "2026-05-10",
            [
                _module("kaos-core", ci="success"),
                _module("kaos-cli", ci="success"),
            ],
        ),
        tmp_path,
    )
    history.write_daily_summary(
        _snapshot(
            "2026-05-11",
            [
                _module("kaos-core", ci="success"),
                _module("kaos-cli", ci="failure"),
            ],
        ),
        tmp_path,
    )
    idx = history.rebuild_index(tmp_path)
    d = history.diff_packages(idx)
    assert "kaos-cli" in d["packages"]
    assert "kaos-core" not in d["packages"]


# ----- file format stability --------------------------------------------------------


def test_per_day_file_format_is_stable(tmp_path: Path) -> None:
    """The per-day summary file is a tight contract — pin the exact key list."""
    snap = _snapshot("2026-05-11", [_module("kaos-core")])
    p = history.write_daily_summary(snap, tmp_path)
    body = json.loads(p.read_text())
    assert set(body.keys()) == {"schema_version", "date", "generated_at", "modules"}
    assert set(body["modules"][0].keys()) == {
        "name",
        "build_pass",
        "tests_pass",
        "security_pass",
        "attestation_present",
        "branch_protection_enabled",
        "commits_90d",
        "releases_90d",
        "loc_total",
        "src_loc",
        "tests_loc",
        "files_total",
    }


def test_rebuild_index_skips_corrupt_files(tmp_path: Path) -> None:
    """A corrupt per-day file is skipped, not raised."""
    good = tmp_path / "2026-05-11.json"
    bad = tmp_path / "2026-05-12.json"
    history.write_daily_summary(_snapshot("2026-05-11", [_module("kaos-core")]), tmp_path)
    assert good.is_file()
    bad.write_text("{not-json", encoding="utf-8")
    idx = history.rebuild_index(tmp_path)
    assert idx["dates"] == ["2026-05-11"]


def test_filename_is_canonical_date(tmp_path: Path) -> None:
    """A daily file's filename (not its JSON ``date``) wins on disagreement."""
    p = tmp_path / "2026-05-11.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "date": "1999-12-31",
                "generated_at": "1999-12-31T00:00:00Z",
                "modules": [{"name": "kaos-core", "build_pass": True}],
            }
        ),
        encoding="utf-8",
    )
    idx = history.rebuild_index(tmp_path)
    assert idx["dates"] == ["2026-05-11"]


# Schema/import marker so renaming the module breaks at the test layer too.
def test_module_exposes_expected_constants() -> None:
    assert "build_pass" in history.TRACKED_BOOL_SIGNALS
    assert "commits_90d" in history.TRACKED_INT_SIGNALS
    assert history.HISTORY_DAYS == 90


def test_attestation_zero_total_is_not_present() -> None:
    """No release at all → attestation_present must be False, not True."""
    snap = _snapshot(
        "2026-05-11",
        [_module("kaos-core", pep740=False, verified=0, total=0)],
    )
    summary = history.daily_summary_from_snapshot(snap)
    assert summary["modules"][0]["attestation_present"] is False


@pytest.mark.parametrize(
    "old,new,expected",
    [
        (False, True, "better"),
        (True, False, "worse"),
        (True, True, "same"),
        (False, False, "same"),
    ],
)
def test_classify_delta_bool(old: bool, new: bool, expected: str) -> None:
    assert history._classify_delta("build_pass", old, new) == expected
