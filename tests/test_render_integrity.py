"""Tests for the renderer's integrity view-model (R4 + R23).

Covers the rendering-side contract:

  * The schema is published alongside the snapshot.
  * The signature pill in the rendered index reflects whether
    ``snapshot.sig`` is present in ``output_dir/api/v1/``.
  * The signature metadata sidecar, when present, is parsed into the
    view-model so templates can show the workflow identity.

The dashboard's templates exercise these claims; this test reads back
the produced HTML to ensure the pill class flips correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from render import __main__ as render_main


def _module_stub(name: str = "kaos-test") -> dict[str, object]:
    """A defaulted module dict — every section's keys present, every
    value at its "no signal yet" sentinel. This is the shape
    ``collector.snapshot.collect_module`` emits when every API call
    fails. The renderer's view-model adapter accepts it cleanly."""
    return {
        "name": name,
        "identity": {
            "pypi_version": None,
            "pypi_url": None,
            "main_head_sha": None,
            "latest_tag": None,
            "latest_tag_sha": None,
            "tag_at_head": None,
            "commits_past_tag": None,
            "repo_visibility": None,
            "last_commit_at": None,
        },
        "ci": {
            "workflow_conclusion": None,
            "workflow_run_id": None,
            "workflow_run_url": None,
            "head_sha": None,
            "run_completed_at": None,
            "matrix": [],
        },
        "security": {
            "workflow_conclusion": None,
            "workflow_run_id": None,
            "workflow_run_url": None,
            "jobs": [],
            "run_completed_at": None,
        },
        "open_prs": {"count": None, "titles": []},
        "freshness": {
            "days_since_last_commit": None,
            "days_since_last_release": None,
            "days_since_last_security_scan": None,
        },
        "supply_chain": {},
        "governance": {},
        "code_metrics": {},
        "errors": [],
    }


@pytest.fixture
def minimal_snapshot() -> dict[str, object]:
    """A trivial-but-renderable snapshot.

    Contains exactly one module so the template's
    ``composite_green / composite_total`` division has a non-zero
    denominator. Adding a module here is cheaper than touching the
    existing template's div-by-zero behavior (pre-existing pre-R4
    issue not in scope for this change set)."""
    return {
        "schema_version": "1.0",
        "generated_at": "2026-05-11T13:00:00Z",
        "generator": {"name": "kaos-compliance", "version": "0.0.1"},
        "heartbeat": {
            "last_full_sweep_at": "2026-05-11T00:00:00Z",
            "last_light_sweep_at": "2026-05-11T13:00:00Z",
            "last_security_sweep_at": "2026-05-11T12:00:00Z",
            "stale_threshold_hours": 26,
        },
        "modules": [_module_stub()],
    }


def test_render_writes_schema(tmp_path: Path, minimal_snapshot: dict[str, object]) -> None:
    """Every render emits snapshot.schema.json alongside snapshot.json."""
    render_main.render(minimal_snapshot, output_dir=tmp_path)
    schema_path = tmp_path / "api" / "v1" / "snapshot.schema.json"
    assert schema_path.is_file()
    parsed = json.loads(schema_path.read_text(encoding="utf-8"))
    assert parsed["$schema"].endswith("/draft/2020-12/schema")
    assert parsed["title"] == "KAOS Compliance Snapshot"


def test_pill_is_gray_without_signature(
    tmp_path: Path, minimal_snapshot: dict[str, object]
) -> None:
    """No snapshot.sig → integrity pill renders as gray ("n" class)."""
    render_main.render(minimal_snapshot, output_dir=tmp_path)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "snapshot unsigned" in index
    # Spot-check the pill class: the gray class is `n` in the template.
    # Find the integrity-claim block and assert the immediately following
    # pill carries `pill n`.
    block_start = index.index("integrity-claim")
    block = index[block_start : block_start + 400]
    assert "pill n" in block


def test_pill_is_green_with_signature(tmp_path: Path, minimal_snapshot: dict[str, object]) -> None:
    """snapshot.sig present → integrity pill renders as green ("g" class)."""
    # First render writes the api/v1 layout the signing step would target.
    render_main.render(minimal_snapshot, output_dir=tmp_path)
    sig_path = tmp_path / "api" / "v1" / "snapshot.sig"
    sig_path.write_text("dGVzdC1ic25kbGU=\n", encoding="utf-8")
    meta_path = tmp_path / "api" / "v1" / "snapshot.sig.meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "scheme": "sigstore-cosign-keyless",
                "bundle_format": "dsse-base64-bundle",
                "bundle_path": "snapshot.sig",
                "expected_identity": (
                    "https://github.com/273v/kaos-compliance/"
                    ".github/workflows/sweep.yml@refs/heads/main"
                ),
                "expected_issuer": "https://token.actions.githubusercontent.com",
                "github_run_id": "424242",
                "github_sha": "deadbeef",
                "github_workflow_ref": (
                    "273v/kaos-compliance/.github/workflows/sweep.yml@refs/heads/main"
                ),
            }
        ),
        encoding="utf-8",
    )
    # Re-render (without --clean) to pick up the signature.
    render_main.render(minimal_snapshot, output_dir=tmp_path)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "snapshot signed" in index
    block_start = index.index("integrity-claim")
    block = index[block_start : block_start + 600]
    assert "pill g" in block
    # The signature URL should be discoverable from the pill block.
    assert "snapshot.sig" in block


def test_verify_recipe_link_always_present(
    tmp_path: Path, minimal_snapshot: dict[str, object]
) -> None:
    """The verify-recipe link is rendered regardless of signature state.

    Goal: a reader who sees an unsigned local render still has a path
    to the verification recipe, so the absence of a signature is
    discoverable (not silent)."""
    render_main.render(minimal_snapshot, output_dir=tmp_path)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "EVIDENCE.md#verifying-the-dashboard-hasnt-been-tampered-with" in index


def test_integrity_view_shape() -> None:
    """The integrity view-model contract: keys templates rely on."""
    v = render_main._integrity_view(signature_present=True, schema_present=True)
    assert v["signature_present"] is True
    assert v["signature_state"] == "green"
    assert v["signature_url"] == "api/v1/snapshot.sig"
    assert v["schema_url"] == "api/v1/snapshot.schema.json"
    assert "verify_recipe_url" in v

    v2 = render_main._integrity_view(signature_present=False, schema_present=False)
    assert v2["signature_state"] == "gray"
    assert v2["signature_url"] is None
    assert v2["schema_url"] is None
