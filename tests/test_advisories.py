"""OSV.dev advisory lookup over locked dependencies (collector/advisories.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from collector import advisories

UV_LOCK = """\
version = 1
revision = 3
requires-python = ">=3.13"

[[package]]
name = "kaos-x"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "anyio"
version = "4.13.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "idna"
version = "3.20"
source = { registry = "https://pypi.org/simple" }
"""

CARGO_LOCK = """\
version = 4

[[package]]
name = "kaos-x"
version = "0.1.0"

[[package]]
name = "vendored"
version = "0.2.4"

[[package]]
name = "lru"
version = "0.18.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00"
"""

DETAILS: dict[str, dict[str, Any]] = {
    "GHSA-crit": {
        "id": "GHSA-crit",
        "aliases": ["CVE-1"],
        "summary": "critical thing",
        "database_specific": {"severity": "CRITICAL"},
    },
    "GHSA-mod": {
        "id": "GHSA-mod",
        "aliases": [],
        "summary": "moderate thing",
        "database_specific": {"severity": "MODERATE"},
    },
    "GHSA-gone": {"id": "GHSA-gone", "withdrawn": "2026-01-01T00:00:00Z"},
    "RUSTSEC-1": {
        "id": "RUSTSEC-1",
        "summary": "unsound thing",
        "affected": [{"database_specific": {"informational": "unsound"}}],
    },
}

HITS = {
    "pkg:pypi/anyio@4.13.0": ["GHSA-crit", "GHSA-mod", "GHSA-gone"],
    "pkg:cargo/lru@0.18.1": ["RUSTSEC-1"],
}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    (tmp_path / "Cargo.lock").write_text(CARGO_LOCK)
    return tmp_path


class FakeOSV:
    def __init__(self) -> None:
        self.queried: list[str] = []
        self.detail_calls: list[str] = []

    def post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        assert url == advisories.OSV_QUERYBATCH_URL
        purls = [q["package"]["purl"] for q in body["queries"]]
        self.queried.extend(purls)
        return {
            "results": [{"vulns": [{"id": i} for i in HITS[p]]} if p in HITS else {} for p in purls]
        }

    def get(self, url: str) -> dict[str, Any]:
        vid = url.rsplit("/", 1)[-1]
        self.detail_calls.append(vid)
        return DETAILS[vid]


def test_collect_counts_by_severity_and_skips_local_packages(repo: Path) -> None:
    osv = FakeOSV()
    out = advisories.collect(repo, url_post_json=osv.post, url_get_json=osv.get)

    # Editable root, path crates (the crate itself and a vendored crate) are not queried.
    assert sorted(osv.queried) == [
        "pkg:cargo/lru@0.18.1",
        "pkg:pypi/anyio@4.13.0",
        "pkg:pypi/idna@3.20",
    ]
    assert out["scanned_components"] == 3
    assert out["counts"] == {
        "critical": 1,
        "high": 0,
        "moderate": 1,
        "low": 0,
        "unknown": 1,
        "total": 3,
    }
    ids = [row["id"] for row in out["open"]]
    assert ids == ["GHSA-crit", "GHSA-mod", "RUSTSEC-1"]  # severity order; withdrawn dropped
    rust = out["open"][-1]
    assert rust["severity"] == "unknown"
    assert rust["informational"] == "unsound"
    assert rust["url"] == "https://osv.dev/vulnerability/RUSTSEC-1"
    assert out["errors"] == []


def test_clean_lock_is_a_real_zero(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV_LOCK.replace("4.13.0", "4.15.1"))
    osv = FakeOSV()
    out = advisories.collect(tmp_path, url_post_json=osv.post, url_get_json=osv.get)
    assert out["scanned_components"] == 2
    assert out["counts"]["total"] == 0
    assert out["open"] == []


def test_query_failure_is_gray_not_zero(repo: Path) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("network down")

    out = advisories.collect(repo, url_post_json=boom, url_get_json=boom)
    assert out["scanned_components"] is None
    assert out["errors"] and "OSV query failed" in out["errors"][0]


def test_no_clone_is_gray(tmp_path: Path) -> None:
    out = advisories.collect(None, url_post_json=FakeOSV().post, url_get_json=FakeOSV().get)
    assert out["scanned_components"] is None
    assert out["errors"]


def test_detail_fetched_once_per_advisory(repo: Path) -> None:
    (repo / "uv.lock").write_text(
        UV_LOCK + '\n[[package]]\nname = "anyio2"\nversion = "1"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    HITS["pkg:pypi/anyio2@1"] = ["GHSA-crit"]
    try:
        osv = FakeOSV()
        advisories.collect(repo, url_post_json=osv.post, url_get_json=osv.get)
        assert osv.detail_calls.count("GHSA-crit") == 1
    finally:
        del HITS["pkg:pypi/anyio2@1"]


def test_aliased_records_are_one_advisory_with_ghsa_severity(tmp_path: Path) -> None:
    """OSV returns PYSEC + GHSA for the same issue; count it once, GHSA severity."""
    (tmp_path / "uv.lock").write_text(UV_LOCK.replace("anyio", "pyjwt").replace("4.13.0", "2.12.1"))
    details = {
        # Both records for issue A came back from the batch query.
        "PYSEC-A": {"id": "PYSEC-A", "aliases": ["CVE-A", "GHSA-A"]},
        "GHSA-A": {
            "id": "GHSA-A",
            "aliases": ["CVE-A", "PYSEC-A"],
            "summary": "issue A",
            "database_specific": {"severity": "HIGH"},
        },
        # Only the PYSEC record for issue B came back; its GHSA alias
        # must be fetched for severity.
        "PYSEC-B": {"id": "PYSEC-B", "aliases": ["CVE-B", "GHSA-B"], "summary": "issue B"},
        "GHSA-B": {"id": "GHSA-B", "database_specific": {"severity": "MODERATE"}},
    }
    hits = {"pkg:pypi/pyjwt@2.12.1": ["PYSEC-A", "GHSA-A", "PYSEC-B"]}

    def post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        purls = [q["package"]["purl"] for q in body["queries"]]
        return {"results": [{"vulns": [{"id": i} for i in hits.get(p, [])]} for p in purls]}

    def get(url: str) -> dict[str, Any]:
        return details[url.rsplit("/", 1)[-1]]

    out = advisories.collect(tmp_path, url_post_json=post, url_get_json=get)
    assert out["counts"]["total"] == 2
    assert out["counts"]["high"] == 1
    assert out["counts"]["moderate"] == 1
    assert out["counts"]["unknown"] == 0
    rows = {r["id"]: r for r in out["open"]}
    assert set(rows) == {"GHSA-A", "PYSEC-B"}
    assert rows["GHSA-A"]["aliases"] == ["CVE-A", "PYSEC-A"]
    assert "GHSA-A" not in rows["GHSA-A"]["aliases"]


def test_missing_ghsa_alias_leaves_severity_unknown_without_failing(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    details = {"PYSEC-X": {"id": "PYSEC-X", "aliases": ["GHSA-missing"]}}

    def post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        purls = [q["package"]["purl"] for q in body["queries"]]
        return {
            "results": [
                {"vulns": [{"id": "PYSEC-X"}]} if p == "pkg:pypi/anyio@4.13.0" else {}
                for p in purls
            ]
        }

    def get(url: str) -> dict[str, Any]:
        vid = url.rsplit("/", 1)[-1]
        if vid not in details:
            raise OSError("HTTP Error 404: Not Found")
        return details[vid]

    out = advisories.collect(tmp_path, url_post_json=post, url_get_json=get)
    assert out["scanned_components"] == 2
    assert out["counts"]["unknown"] == 1
    assert out["errors"] == []


def test_unmaintained_notice_is_listed_but_not_counted(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(CARGO_LOCK.replace("lru", "paste"))
    details = {
        "RUSTSEC-2024-0436": {
            "id": "RUSTSEC-2024-0436",
            "summary": "paste - no longer maintained",
            "affected": [{"database_specific": {"informational": "unmaintained"}}],
        }
    }

    def post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        purls = [q["package"]["purl"] for q in body["queries"]]
        return {
            "results": [
                {"vulns": [{"id": "RUSTSEC-2024-0436"}]} if "paste" in p else {} for p in purls
            ]
        }

    out = advisories.collect(
        tmp_path, url_post_json=post, url_get_json=lambda u: details[u.rsplit("/", 1)[-1]]
    )
    assert out["counts"]["total"] == 0
    assert out["open"] == []
    assert [n["id"] for n in out["notices"]] == ["RUSTSEC-2024-0436"]
