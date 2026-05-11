"""Tests for ``collector.schema`` (R23: published JSON Schema).

These tests cover:

  * The schema is a valid JSON-Schema Draft 2020-12 document (no
    syntax errors, no metaschema violations).
  * The deterministic emission contract holds — re-derivation yields
    identical bytes.
  * A real snapshot (the one currently checked in under ``_site/``)
    validates cleanly against the derived schema. This is the
    end-to-end shape check.

``jsonschema`` is dev-only — no runtime dep added to the collector.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from collector import schema as schema_mod
from collector import snapshot as snap_mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


REPO_ROOT = Path(__file__).resolve().parent.parent


def _sample_snapshot() -> dict[str, Any]:
    """Return a minimal-but-realistic snapshot.

    Built by dataclass-default-instantiating every section. This exercises
    every required field in the schema without depending on the live
    network or a checked-in fixture file.
    """
    ident = snap_mod.IdentitySection()
    ci = snap_mod.CISection()
    sec = snap_mod.SecuritySection()
    prs = snap_mod.OpenPRsSection()
    fresh = snap_mod.FreshnessSection()
    module = snap_mod.ModuleSnapshot(
        name="kaos-test",
        identity=ident,
        ci=ci,
        security=sec,
        open_prs=prs,
        freshness=fresh,
        # Mirrors the real shape emitted by collector.supply_chain.collect()
        # when its sibling clone is missing — every field at default.
        supply_chain={
            "pypi_version": None,
            "pypi_release_iso": None,
            "wheel_platforms": [],
            "wheel_sha256s": {},
            "is_abi3": None,
            "has_musllinux_wheel": None,
            "license_expression": None,
            "license_files_in_wheel": [],
            "attestations": {
                "pep740_present": None,
                "publisher_kind": None,
                "publisher_source_repo": None,
                "publisher_workflow_ref": None,
                "rekor_log_index": None,
                "verified_count": 0,
                "total_count": 0,
            },
            "sbom": {
                "components_count": None,
                "license_breakdown": {},
                "weak_copyleft": [],
                "strong_copyleft": [],
                "unknown_license": [],
                "sbom_artifact_path": None,
            },
            "errors": [],
        },
        governance={
            "dco_signoff_rate_90d": None,
            "conventional_commits_rate_90d": None,
            "verified_commit_ratio_90d": None,
            "commits_90d": None,
            "unique_committers_90d": None,
            "branch_protection_enabled": None,
            "branch_protection_summary": None,
            "codeowners_path": None,
            "security_md_present": False,
            "security_md_disclosure_window_days": None,
            "notice_present": False,
            "license_files_in_sdist": [],
            "releases_90d": None,
            "median_pr_age_days": None,
            "open_pr_count": None,
            "open_issue_count": None,
            "time_to_pypi_seconds_median": None,
            "errors": [],
        },
        code_metrics={
            "python": {
                "src_loc": None,
                "tests_loc": None,
                "src_files": None,
                "tests_files": None,
            },
            "rust": {
                "src_loc": None,
                "tests_loc": None,
                "src_files": None,
                "tests_files": None,
            },
            "errors": [],
        },
    )
    return {
        "schema_version": snap_mod.SCHEMA_VERSION,
        "generated_at": "2026-05-11T13:00:00Z",
        "generator": {"name": "kaos-compliance", "version": "0.0.1"},
        "heartbeat": {
            "last_full_sweep_at": "2026-05-11T00:00:00Z",
            "last_light_sweep_at": "2026-05-11T13:00:00Z",
            "last_security_sweep_at": "2026-05-11T12:00:00Z",
            "stale_threshold_hours": snap_mod.STALE_THRESHOLD_HOURS,
        },
        "modules": [dataclasses.asdict(module)],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_schema_is_metaschema_valid() -> None:
    """The schema must be a valid Draft 2020-12 document."""
    s = schema_mod.build_snapshot_schema()
    # Will raise SchemaError on any metaschema violation. The Validator
    # picked is determined by $schema; we don't pin manually so the test
    # would still pass after a future Draft bump.
    Validator = jsonschema.validators.validator_for(s)
    Validator.check_schema(s)
    assert s["$schema"] == schema_mod.SCHEMA_DRAFT
    assert s["$id"] == schema_mod.SCHEMA_ID_BASE
    assert "$comment" in s, "$comment must carry the collector version"


def test_schema_round_trip_is_deterministic() -> None:
    """Re-deriving the schema must yield identical bytes."""
    a = json.dumps(schema_mod.build_snapshot_schema(), indent=2, sort_keys=False)
    b = json.dumps(schema_mod.build_snapshot_schema(), indent=2, sort_keys=False)
    assert a == b


def test_sample_snapshot_validates() -> None:
    """A defaults-only snapshot must validate against the schema."""
    s = schema_mod.build_snapshot_schema()
    snap = _sample_snapshot()
    jsonschema.validate(instance=snap, schema=s)


def test_required_top_level_fields_are_enforced() -> None:
    """Drop a required top-level field; the validator must complain."""
    s = schema_mod.build_snapshot_schema()
    snap = _sample_snapshot()
    snap.pop("modules")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=snap, schema=s)


def test_additional_properties_blocked_on_root() -> None:
    """Closed-world top-level: an unknown field must fail validation."""
    s = schema_mod.build_snapshot_schema()
    snap = _sample_snapshot()
    snap["bogus_field"] = "should not appear"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=snap, schema=s)


def test_dict_sections_accept_additional_properties() -> None:
    """The dict-backed sections must accept new fields (additive change
    contract documented in docs/DATA-MODEL.md)."""
    s = schema_mod.build_snapshot_schema()
    snap = _sample_snapshot()
    snap["modules"][0]["governance"]["new_signal_added_later"] = 42
    # Must NOT raise.
    jsonschema.validate(instance=snap, schema=s)


def test_schema_version_const_pins_value() -> None:
    """The schema_version field is `const` — wrong values must fail."""
    s = schema_mod.build_snapshot_schema()
    snap = _sample_snapshot()
    snap["schema_version"] = "9.9"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=snap, schema=s)


def test_live_snapshot_validates_if_present() -> None:
    """If ``_site/api/v1/snapshot.json`` is checked in (post-render), it
    must validate. This is the end-to-end smoke test."""
    snap_path = REPO_ROOT / "_site" / "api" / "v1" / "snapshot.json"
    if not snap_path.is_file():
        pytest.skip("no live snapshot to validate (run `python -m render` first)")
    s = schema_mod.build_snapshot_schema()
    snap = json.loads(snap_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=snap, schema=s)


def test_cli_writes_pretty_file(tmp_path: Path) -> None:
    """``python -m collector.schema -o file.json`` produces a parseable file."""
    out = tmp_path / "schema.json"
    rc = schema_mod.main(["--output", str(out), "--pretty"])
    assert rc == 0
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["$schema"] == schema_mod.SCHEMA_DRAFT
