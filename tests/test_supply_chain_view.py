"""Tests for the supply-chain view-model derivations.

Covers the SLSA Build Level (R9 / F19) and CISA SBOM Minimum Elements
(R10) derivations that the renderer surfaces on
``supply-chain.html``. Both functions are pure: given a per-module
``supply_chain`` block, they produce a dict the template renders.

Anti-pattern guardrail: the SLSA derivation must NOT exceed L2 — L3
needs hardened-build-platform isolation guarantees the dashboard
cannot verify from public sources. The test enforces the cap.
"""

from __future__ import annotations

from render.__main__ import _cisa_sbom_minimum_elements, _slsa_build_level

# ---------------------------------------------------------------------------
# SLSA Build Level (R9 / F19)
# ---------------------------------------------------------------------------


def test_slsa_build_level_no_attestation_is_gray_l0():
    out = _slsa_build_level({"pep740_present": False})
    assert out["level"] is None
    assert out["state"] == "gray"
    assert "Build L0" in out["label"]


def test_slsa_build_level_attestation_with_no_verified_is_yellow_l1():
    out = _slsa_build_level(
        {
            "pep740_present": True,
            "verified_count": 0,
            "total_count": 3,
            "publisher_kind": "GitHub",
        }
    )
    assert out["level"] == 1
    assert out["state"] == "yellow"


def test_slsa_build_level_partial_coverage_is_yellow_l1_plus():
    out = _slsa_build_level(
        {
            "pep740_present": True,
            "verified_count": 2,
            "total_count": 3,
            "publisher_kind": "GitHub",
        }
    )
    assert out["level"] == 1
    assert out["state"] == "yellow"
    assert "2/3" in out["note"]


def test_slsa_build_level_full_coverage_github_is_green_l2():
    out = _slsa_build_level(
        {
            "pep740_present": True,
            "verified_count": 3,
            "total_count": 3,
            "publisher_kind": "GitHub",
        }
    )
    assert out["level"] == 2
    assert out["state"] == "green"
    assert "Build L2 (effective)" in out["label"]


def test_slsa_build_level_unrecognized_publisher_does_not_claim_l2():
    """Anti-pattern guardrail: a non-hosted publisher CANNOT claim L2.
    Without a recognized hosted platform the chain of custody on the
    build environment is opaque — yellow is the correct state."""
    out = _slsa_build_level(
        {
            "pep740_present": True,
            "verified_count": 3,
            "total_count": 3,
            "publisher_kind": "SomeRandomCI",
        }
    )
    # Must NOT be green-L2.
    assert out["state"] != "green"
    # And we must never claim L3 from a public-source signal alone.
    assert out["level"] != 3


def test_slsa_build_level_never_returns_level_3():
    """L3 requires hardened-platform isolation we can't verify.
    No combination of inputs should yield level == 3."""
    cases = [
        {"pep740_present": True, "verified_count": 0, "total_count": 0},
        {
            "pep740_present": True,
            "verified_count": 100,
            "total_count": 100,
            "publisher_kind": "GitHub",
        },
        {
            "pep740_present": True,
            "verified_count": 100,
            "total_count": 100,
            "publisher_kind": "GitLab",
        },
        {"pep740_present": False},
    ]
    for att in cases:
        out = _slsa_build_level(att)
        assert out["level"] != 3, f"L3 claim leaked from input {att}"


# ---------------------------------------------------------------------------
# CISA SBOM Minimum Elements (R10)
# ---------------------------------------------------------------------------


def test_cisa_no_sbom_returns_seven_gray_elements():
    elements = _cisa_sbom_minimum_elements({}, {})
    assert len(elements) == 7
    assert {e["state"] for e in elements} == {"gray"}
    # The seven canonical CISA elements MUST all be present.
    names = {e["element"] for e in elements}
    assert "Author" in names
    assert "Supplier" in names
    assert "Component name" in names
    assert "Component version" in names
    assert "Unique identifier (PURL)" in names
    assert "Dependency relationships" in names
    assert "Timestamp" in names


def test_cisa_with_sbom_flags_relationships_yellow():
    """The dependency-relationships element is the F9 gap. Even with
    a fully-populated SBOM, this element MUST stay yellow until the
    dependencies[] graph emitter lands. The gap is load-bearing for
    the methodology page's honest-gap section."""
    elements = _cisa_sbom_minimum_elements({"components_count": 42}, {"pypi_version": "1.0"})
    relationships = next(e for e in elements if e["element"] == "Dependency relationships")
    assert relationships["state"] == "yellow"
    assert "F9" in relationships["note"]


def test_cisa_with_sbom_marks_author_and_name_green():
    elements = _cisa_sbom_minimum_elements({"components_count": 42}, {"pypi_version": "1.0"})
    author = next(e for e in elements if e["element"] == "Author")
    name = next(e for e in elements if e["element"] == "Component name")
    timestamp = next(e for e in elements if e["element"] == "Timestamp")
    purl = next(e for e in elements if e["element"] == "Unique identifier (PURL)")
    for e in (author, name, timestamp, purl):
        assert e["state"] == "green", f"{e['element']} should be green; got {e['state']}"


def test_cisa_elements_count_is_exactly_seven():
    """Anti-pattern guardrail: the CISA minimums are seven, not eight.
    A future contributor who adds an eighth element to fudge the
    count breaks this test."""
    elements = _cisa_sbom_minimum_elements({"components_count": 1}, {})
    assert len(elements) == 7
