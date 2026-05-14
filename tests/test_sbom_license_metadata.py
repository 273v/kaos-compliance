"""Tests for PyPI license metadata normalization in ``collector.sbom``."""

from __future__ import annotations

from typing import Any

from collector import sbom


def test_enrich_from_pypi_uses_trove_classifiers_for_dual_license() -> None:
    """python-dateutil publishes ``license="Dual License"`` plus useful Trove data."""
    component = sbom.Component(
        name="python-dateutil",
        version="2.9.0.post0",
        ecosystem="pypi",
        purl="pkg:pypi/python-dateutil@2.9.0.post0",
    )

    def fetch(_url: str) -> dict[str, Any]:
        return {
            "info": {
                "license_expression": None,
                "license": "Dual License",
                "classifiers": [
                    "License :: OSI Approved :: Apache Software License",
                    "License :: OSI Approved :: BSD License",
                ],
            }
        }

    sbom.enrich_from_pypi([component], gh_run=fetch)

    assert component.license_hint_from_metadata == "Apache-2.0 OR BSD-3-Clause"
    assert component.license_spdx == "Apache-2.0 OR BSD-3-Clause"


def test_enrich_from_pypi_keeps_normalizable_legacy_license() -> None:
    component = sbom.Component(
        name="example",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/example@1.0.0",
    )

    def fetch(_url: str) -> dict[str, Any]:
        return {
            "info": {
                "license_expression": None,
                "license": "MIT",
                "classifiers": ["License :: OSI Approved :: Apache Software License"],
            }
        }

    sbom.enrich_from_pypi([component], gh_run=fetch)

    assert component.license_hint_from_metadata == "MIT"
    assert component.license_spdx == "MIT"
