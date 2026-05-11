"""Unit tests for ``collector/supply_chain.py``.

Stdlib + pytest only. The retry-aware HTTP helpers are stubbed via
monkeypatch fixtures that return canned PyPI / simple-index JSON.

The four scenarios covered here intentionally map to the bullets in
``docs/research/02-pypi-extraction-findings.md`` and the dashboard's
documented honest-gaps:

1. ABI3 + manylinux + musllinux flag detection from synthetic wheels.
2. PEP 740 attestation extraction (mirrors kaos-graph 0.1.0a3 shape).
3. Graceful degradation when PyPI returns 404.
4. License-breakdown aggregation from a CycloneDX dict.
"""

from __future__ import annotations

import urllib.error
from pathlib import Path
from typing import Any

import pytest

from collector import supply_chain

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_gh_run(*_args: Any, **_kw: Any) -> Any:
    """Sentinel: tests never need gh; assert here if anyone calls it."""
    raise AssertionError("gh_run should not be invoked by supply_chain.collect")


def _make_url_get_json(responses: dict[str, Any]):
    """Return a stub matching the ``url_get_json`` signature.

    ``responses`` is a mapping of URL -> either a JSON-serialisable object
    or an Exception instance to raise when that URL is requested. Tests
    can use the exception path to simulate 404s / timeouts.
    """

    seen: list[str] = []

    def _fn(url: str, *, headers: dict[str, str] | None = None, **_: Any) -> Any:
        seen.append(url)
        if url not in responses:
            raise AssertionError(f"unexpected URL: {url}")
        val = responses[url]
        if isinstance(val, BaseException):
            raise val
        return val

    _fn.seen = seen  # type: ignore[attr-defined]
    return _fn


# ---------------------------------------------------------------------------
# Test 1: ABI3 + manylinux + musllinux detection
# ---------------------------------------------------------------------------


def test_wheel_platform_detection_abi3_manylinux_musllinux(tmp_path: Path) -> None:
    """Synthetic wheel filenames should map to the expected flag set."""
    pypi_json = {
        "info": {
            "name": "fakepkg",
            "version": "1.2.3",
            "license_expression": "Apache-2.0",
            "license_files": ["LICENSE"],
        },
        "urls": [
            {
                "filename": "fakepkg-1.2.3-cp313-abi3-manylinux_2_28_x86_64.whl",
                "digests": {"sha256": "a" * 64},
                "upload_time_iso_8601": "2026-05-10T12:00:00Z",
            },
            {
                "filename": "fakepkg-1.2.3-cp313-abi3-musllinux_1_2_aarch64.whl",
                "digests": {"sha256": "b" * 64},
                "upload_time_iso_8601": "2026-05-10T12:00:05Z",
            },
            {
                "filename": "fakepkg-1.2.3-cp313-abi3-macosx_11_0_arm64.whl",
                "digests": {"sha256": "c" * 64},
                "upload_time_iso_8601": "2026-05-10T12:00:10Z",
            },
            {
                "filename": "fakepkg-1.2.3-cp313-abi3-win_amd64.whl",
                "digests": {"sha256": "d" * 64},
                "upload_time_iso_8601": "2026-05-10T12:00:15Z",
            },
            {
                "filename": "fakepkg-1.2.3.tar.gz",
                "digests": {"sha256": "e" * 64},
                "upload_time_iso_8601": "2026-05-10T12:00:20Z",
            },
        ],
    }
    simple_json = {
        "name": "fakepkg",
        "files": [
            {"filename": e["filename"], "url": "x", "provenance": None}
            for e in pypi_json["urls"]
        ],
    }

    fetcher = _make_url_get_json(
        {
            f"{supply_chain.PYPI_JSON_BASE}/fakepkg/json": pypi_json,
            f"{supply_chain.PYPI_SIMPLE_BASE}/fakepkg/": simple_json,
        }
    )

    result = supply_chain.collect(
        "fakepkg",
        sibling_dir=None,
        gh_run=_fake_gh_run,
        url_get_json=fetcher,
        data_root=tmp_path,
    )

    assert result["pypi_version"] == "1.2.3"
    assert result["pypi_release_iso"] == "2026-05-10T12:00:20Z"  # max of urls[]
    assert result["is_abi3"] is True
    assert result["has_musllinux_wheel"] is True
    assert result["license_expression"] == "Apache-2.0"
    assert result["license_files_in_wheel"] == ["LICENSE"]

    platforms = result["wheel_platforms"]
    # All three OSes show up; manylinux carries the profile suffix.
    assert "macos-arm64" in platforms
    assert "win-amd64" in platforms
    assert any(p.startswith("linux-x86_64-manylinux") for p in platforms)
    assert any(p.startswith("linux-aarch64-musllinux") for p in platforms)

    # All five files contribute their sha256 to the wheel_sha256s dict
    # (including the sdist — the dashboard pins on every artifact).
    assert len(result["wheel_sha256s"]) == 5
    # No PEP 740 provenance in this test → flag should be False but the
    # rest of the publisher block stays None.
    assert result["attestations"]["pep740_present"] is False
    assert result["attestations"]["publisher_kind"] is None


# ---------------------------------------------------------------------------
# Test 2: PEP 740 attestation extraction (kaos-graph 0.1.0a3 shape)
# ---------------------------------------------------------------------------


def test_attestation_extraction_kaos_graph_shape(tmp_path: Path) -> None:
    """Mimic the live kaos-graph 0.1.0a3 simple-index + integrity bundle."""
    pkg = "kaos-graph"
    version = "0.1.0a3"
    wheel = f"kaos_graph-{version}-cp313-abi3-win_amd64.whl"
    sdist = f"kaos_graph-{version}.tar.gz"

    pypi_json = {
        "info": {
            "name": pkg,
            "version": version,
            "license_expression": "Apache-2.0",
            "license_files": ["LICENSE", "NOTICE"],
        },
        "urls": [
            {
                "filename": wheel,
                "digests": {"sha256": "1" * 64},
                "upload_time_iso_8601": "2026-05-11T01:52:51.166205Z",
            },
            {
                "filename": sdist,
                "digests": {"sha256": "2" * 64},
                "upload_time_iso_8601": "2026-05-11T01:53:01.987133Z",
            },
        ],
    }
    provenance_url = (
        f"https://pypi.org/integrity/{pkg}/{version}/{wheel}/provenance"
    )
    simple_json = {
        "name": pkg,
        "files": [
            {
                "filename": wheel,
                "url": "https://files.pythonhosted.org/x",
                "provenance": provenance_url,
                "hashes": {"sha256": "1" * 64},
            },
            {
                "filename": sdist,
                "url": "https://files.pythonhosted.org/y",
                "provenance": (
                    f"https://pypi.org/integrity/{pkg}/{version}/{sdist}/provenance"
                ),
                "hashes": {"sha256": "2" * 64},
            },
        ],
    }
    bundle = {
        "version": 1,
        "attestation_bundles": [
            {
                "publisher": {
                    "environment": "pypi",
                    "kind": "GitHub",
                    "repository": "273v/kaos-graph",
                    "workflow": "release.yml",
                },
                "attestations": [
                    {
                        "version": 1,
                        "envelope": {"statement": "...", "signature": "..."},
                        "verification_material": {
                            "certificate": "-----BEGIN CERTIFICATE-----...",
                            "transparency_entries": [
                                {
                                    "logIndex": "1501439770",
                                    "logId": {"keyId": "..."},
                                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                                    "integratedTime": "1747119000",
                                    "inclusionPromise": {"signedEntryTimestamp": "..."},
                                    "inclusionProof": {
                                        "logIndex": "1501439770",
                                        "rootHash": "...",
                                        "treeSize": "...",
                                        "hashes": [],
                                    },
                                    "canonicalizedBody": "...",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    fetcher = _make_url_get_json(
        {
            f"{supply_chain.PYPI_JSON_BASE}/{pkg}/json": pypi_json,
            f"{supply_chain.PYPI_SIMPLE_BASE}/{pkg}/": simple_json,
            provenance_url: bundle,
        }
    )

    result = supply_chain.collect(
        pkg,
        sibling_dir=None,
        gh_run=_fake_gh_run,
        url_get_json=fetcher,
        data_root=tmp_path,
    )

    att = result["attestations"]
    assert att["pep740_present"] is True
    assert att["publisher_kind"] == "GitHub"
    assert att["publisher_source_repo"] == "273v/kaos-graph"
    # We surface "<workflow>@<environment>" so reviewers see the env pin.
    assert att["publisher_workflow_ref"] == "release.yml@pypi"
    # Rekor logIndex serialised as a string by PyPI; we coerce to int.
    assert att["rekor_log_index"] == 1501439770
    assert att["verified_count"] == 2
    assert att["total_count"] == 2

    # No supply-chain errors should accumulate when every endpoint
    # returns the documented shape.
    assert result["errors"] == []


# ---------------------------------------------------------------------------
# Test 3: graceful degradation on PyPI 404
# ---------------------------------------------------------------------------


def test_pypi_404_degrades_gracefully(tmp_path: Path) -> None:
    """A brand-new package not yet on PyPI must not blow up the collector."""
    pkg = "nonexistent-package-xyz"

    not_found = urllib.error.HTTPError(
        url=f"{supply_chain.PYPI_JSON_BASE}/{pkg}/json",
        code=404,
        msg="Not Found",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )

    fetcher = _make_url_get_json(
        {
            f"{supply_chain.PYPI_JSON_BASE}/{pkg}/json": not_found,
            f"{supply_chain.PYPI_SIMPLE_BASE}/{pkg}/": urllib.error.HTTPError(
                url=f"{supply_chain.PYPI_SIMPLE_BASE}/{pkg}/",
                code=404,
                msg="Not Found",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            ),
        }
    )

    result = supply_chain.collect(
        pkg,
        sibling_dir=None,
        gh_run=_fake_gh_run,
        url_get_json=fetcher,
        data_root=tmp_path,
    )

    # Every signal should be the documented "unknown" sentinel.
    assert result["pypi_version"] is None
    assert result["pypi_release_iso"] is None
    assert result["wheel_platforms"] == []
    assert result["wheel_sha256s"] == {}
    assert result["is_abi3"] is None
    assert result["has_musllinux_wheel"] is None
    assert result["license_expression"] is None
    assert result["attestations"]["pep740_present"] is None
    # Errors were captured — the dashboard can mark the row stale.
    assert any("pypi_json" in e for e in result["errors"])
    assert any("pypi_simple" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Test 4: license breakdown aggregation from a CycloneDX dict
# ---------------------------------------------------------------------------


def test_license_breakdown_aggregation_from_cyclonedx() -> None:
    """The internal aggregator must classify each CycloneDX shape correctly."""
    cdx = {
        "specVersion": "1.5",
        "components": [
            # Canonical SPDX id
            {"name": "alpha", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"name": "beta", "licenses": [{"license": {"id": "MIT"}}]},
            # Compound expression — counts as ONE bucket
            {
                "name": "gamma",
                "licenses": [{"expression": "Apache-2.0 OR MIT"}],
            },
            # Weak copyleft — MPL
            {"name": "weak-mpl", "licenses": [{"license": {"id": "MPL-2.0"}}]},
            # Weak copyleft — LGPL
            {"name": "weak-lgpl", "licenses": [{"license": {"id": "LGPL-3.0-only"}}]},
            # Strong copyleft — GPL
            {"name": "strong-gpl", "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
            # Strong copyleft — AGPL
            {"name": "strong-agpl", "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
            # Unknown via LicenseRef-unknown
            {
                "name": "mystery",
                "licenses": [{"license": {"name": "LicenseRef-unknown-abcd1234"}}],
            },
            # Missing licenses[] entirely
            {"name": "no-license"},
        ],
    }

    breakdown, weak, strong, unknown = supply_chain._aggregate_license_breakdown(cdx)

    assert breakdown["Apache-2.0"] == 1
    assert breakdown["MIT"] == 1
    assert breakdown["Apache-2.0 OR MIT"] == 1
    assert breakdown["MPL-2.0"] == 1
    assert breakdown["LGPL-3.0-only"] == 1
    assert breakdown["GPL-3.0-only"] == 1
    assert breakdown["AGPL-3.0-only"] == 1
    assert breakdown["LicenseRef-unknown-abcd1234"] == 1
    assert breakdown["unknown"] == 1

    # Weak buckets: MPL + LGPL only.
    assert weak == sorted(["weak-mpl", "weak-lgpl"])
    # Strong buckets: GPL + AGPL only.
    assert strong == sorted(["strong-gpl", "strong-agpl"])
    # Unknown buckets: the LicenseRef-unknown row + the no-license row.
    assert unknown == sorted(["mystery", "no-license"])


# ---------------------------------------------------------------------------
# Extras: smoke-test the classifier + helpers in isolation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spdx", "expected"),
    [
        ("Apache-2.0", "permissive"),
        ("MIT OR Apache-2.0", "permissive"),
        ("MPL-2.0", "weak"),
        ("LGPL-3.0-only", "weak"),
        ("GPL-3.0-only", "strong"),
        ("AGPL-3.0-or-later", "strong"),
        ("LicenseRef-unknown-deadbeef", "unknown"),
        (None, "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_license(spdx: str | None, expected: str) -> None:
    assert supply_chain._classify_license(spdx) == expected


def test_wheel_filename_parser_skips_non_wheels() -> None:
    """Non-wheel filenames must produce no platform label."""
    assert supply_chain._platform_label_from_wheel("foo-1.0.tar.gz") is None
    assert (
        supply_chain._platform_label_from_wheel(
            "fakepkg-1.0-cp313-abi3-manylinux_2_28_x86_64.whl"
        )
        == "linux-x86_64-manylinux_2_28"
    )


def test_collect_with_missing_sibling_dir(tmp_path: Path) -> None:
    """sibling_dir=None must skip the SBOM section cleanly."""
    pypi_json = {
        "info": {"name": "fakepkg", "version": "0.0.1", "license_expression": None},
        "urls": [],
    }
    simple_json = {"name": "fakepkg", "files": []}
    fetcher = _make_url_get_json(
        {
            f"{supply_chain.PYPI_JSON_BASE}/fakepkg/json": pypi_json,
            f"{supply_chain.PYPI_SIMPLE_BASE}/fakepkg/": simple_json,
        }
    )
    result = supply_chain.collect(
        "fakepkg",
        sibling_dir=None,
        gh_run=_fake_gh_run,
        url_get_json=fetcher,
        data_root=tmp_path,
    )
    assert result["sbom"]["components_count"] is None
    assert result["sbom"]["sbom_artifact_path"] is None
    # Nothing failed — sibling=None is a documented "honest gap", not an error.
    assert result["errors"] == []
