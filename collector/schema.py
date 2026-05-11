"""JSON Schema generation for the kaos-compliance snapshot.

Why this exists
---------------

The dashboard's JSON snapshot is documented in prose in
``docs/DATA-MODEL.md`` and structurally defined by the dataclasses in
:mod:`collector.snapshot`. Downstream compliance ingest tools want to
validate the snapshot programmatically — without a published
machine-readable schema they have to mirror the prose, drift, and quietly
accept malformed payloads.

This module derives a JSON-Schema-Draft-2020-12 document from those
dataclasses (plus hand-written sub-schemas for the per-section dicts
that the ``supply_chain``, ``governance``, and ``code_metrics``
collectors emit). It is intentionally stdlib-only — the project keeps
its runtime dependency set down to ``jinja2``.

Determinism contract
--------------------

The schema is produced by walking the dataclass field types once, so
the same source tree always emits identical bytes. ``$id`` includes the
collector version so consumers can pin against a specific release of
the schema if they care about strict reproducibility. Re-deriving the
schema from a checkout of a given commit yields the same JSON bytes
modulo Python dict ordering (which is insertion-ordered and stable
here).

Not Pydantic — why
------------------

Adding Pydantic for the sake of ``Model.model_json_schema()`` would
double the runtime install size of the collector and pull in an
explicit C extension we currently don't need. The dataclass surface
here is small enough (six top-level sections, ~30 leaf fields) that a
hand-rolled type→schema translator is cheaper than the dependency.
"""

from __future__ import annotations

import dataclasses
import json
import types
import typing
from typing import Any, get_args, get_origin, get_type_hints

from collector import __version__ as COLLECTOR_VERSION
from collector.snapshot import (
    SCHEMA_VERSION,
    STALE_THRESHOLD_HOURS,
    CISection,
    FreshnessSection,
    IdentitySection,
    ModuleSnapshot,
    OpenPRsSection,
    SecuritySection,
)

__all__ = [
    "SCHEMA_ID_BASE",
    "build_snapshot_schema",
    "dataclass_to_schema",
]

# ---------------------------------------------------------------------------
# IDs
# ---------------------------------------------------------------------------

SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_BASE = "https://273v.github.io/kaos-compliance/api/v1/snapshot.schema.json"


# ---------------------------------------------------------------------------
# Type translation
# ---------------------------------------------------------------------------


def _is_optional(tp: Any) -> bool:
    """True iff ``tp`` is ``X | None`` (PEP 604) or ``Optional[X]``."""
    origin = get_origin(tp)
    if origin is typing.Union or origin is types.UnionType:
        return type(None) in get_args(tp)
    return False


def _strip_none(tp: Any) -> Any:
    """Return ``X`` from ``X | None``; pass through otherwise."""
    if not _is_optional(tp):
        return tp
    non_none = [a for a in get_args(tp) if a is not type(None)]
    if len(non_none) == 1:
        return non_none[0]
    # X | Y | None → keep the Union, drop only None. Use functools.reduce
    # over ``X | Y`` instead of typing.Union[...] to satisfy UP007 / py313.
    import functools
    import operator

    return functools.reduce(operator.or_, non_none)


def _type_to_schema(tp: Any) -> dict[str, Any]:
    """Translate a Python type annotation to a JSON Schema fragment.

    Handles the union of constructs that appear in the snapshot
    dataclasses: scalars, ``X | None``, ``list[T]``, ``dict[str, T]``,
    and the per-section dataclasses themselves.
    """
    nullable = _is_optional(tp)
    inner = _strip_none(tp) if nullable else tp
    schema = _non_null_type_to_schema(inner)
    if nullable:
        if "type" in schema and isinstance(schema["type"], str):
            schema = {**schema, "type": [schema["type"], "null"]}
        else:
            # For composite schemas (e.g. enum, $ref) wrap in a oneOf
            # against null. anyOf would also work; oneOf is slightly
            # stricter and matches Draft 2020-12 idioms.
            schema = {"oneOf": [schema, {"type": "null"}]}
    return schema


def _non_null_type_to_schema(tp: Any) -> dict[str, Any]:
    if tp is str:
        return {"type": "string"}
    if tp is bool:
        # Order matters: bool is a subclass of int — check first.
        return {"type": "boolean"}
    if tp is int:
        return {"type": "integer"}
    if tp is float:
        return {"type": "number"}
    if tp is Any:
        return {}  # any JSON value, no constraint
    origin = get_origin(tp)
    if origin in (list, tuple):
        args = get_args(tp)
        if not args:
            return {"type": "array"}
        return {"type": "array", "items": _type_to_schema(args[0])}
    if origin is dict:
        args = get_args(tp)
        if not args:
            return {"type": "object"}
        # JSON objects always have string keys, so we drop args[0] and
        # use additionalProperties for the value type.
        return {
            "type": "object",
            "additionalProperties": _type_to_schema(args[1]),
        }
    if origin is typing.Union or origin is types.UnionType:
        return {"oneOf": [_type_to_schema(a) for a in get_args(tp)]}
    if dataclasses.is_dataclass(tp):
        return dataclass_to_schema(tp)
    # Last-resort fallback: accept any JSON value rather than crash on
    # an unsupported annotation. This is conservative — a future
    # maintainer adding a Decimal field will see overly-permissive
    # validation instead of a hard error, and can extend this function.
    return {}


def dataclass_to_schema(cls: type) -> dict[str, Any]:
    """Build a JSON Schema ``object`` fragment for one dataclass.

    The fragment includes ``properties`` (one per field) and a
    ``required`` array listing every field that has no default. Fields
    typed ``X | None`` are NOT marked required iff they default to
    ``None`` — that pattern is the project's idiom for "we tried and
    couldn't extract it" and consumers MUST tolerate it.
    """
    hints = get_type_hints(cls)
    properties: dict[str, dict[str, Any]] = {}
    required: list[str] = []
    for field in dataclasses.fields(cls):
        properties[field.name] = _type_to_schema(hints[field.name])
        # A field is "required" iff it has no default and no
        # default_factory. The frozen dataclasses in collector.snapshot
        # mostly default to None / [] / {}, so this list is short by
        # design.
        has_default = (
            field.default is not dataclasses.MISSING
            or field.default_factory is not dataclasses.MISSING  # type: ignore[misc]
        )
        if not has_default:
            required.append(field.name)
    schema: dict[str, Any] = {
        "type": "object",
        "title": cls.__name__,
        "properties": properties,
        "additionalProperties": False,
    }
    if cls.__doc__:
        schema["description"] = cls.__doc__.strip().splitlines()[0]
    if required:
        schema["required"] = required
    return schema


# ---------------------------------------------------------------------------
# Hand-written sub-schemas for dict-shaped collector outputs
# ---------------------------------------------------------------------------
#
# The supply_chain, governance, and code_metrics collectors return raw
# dicts rather than dataclasses (the collector module documents this
# tradeoff). Their shapes are stable enough to constrain — but we accept
# additionalProperties so collectors can add new fields without breaking
# existing consumers (an additive change is a non-breaking schema change
# by the Draft 2020-12 conventions documented in
# https://json-schema.org/blog/posts/dynamicref-and-generics).


def _supply_chain_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "title": "SupplyChainSection",
        "description": "Output of collector.supply_chain.collect()",
        "additionalProperties": True,
        "properties": {
            "pypi_version": {"type": ["string", "null"]},
            "pypi_release_iso": {"type": ["string", "null"]},
            "wheel_platforms": {
                "type": "array",
                "items": {"type": "string"},
            },
            "wheel_sha256s": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "is_abi3": {"type": ["boolean", "null"]},
            "has_musllinux_wheel": {"type": ["boolean", "null"]},
            "license_expression": {"type": ["string", "null"]},
            "license_files_in_wheel": {
                "type": "array",
                "items": {"type": "string"},
            },
            "attestations": {
                "type": "object",
                "additionalProperties": True,
                "properties": {
                    "pep740_present": {"type": ["boolean", "null"]},
                    "publisher_kind": {"type": ["string", "null"]},
                    "publisher_source_repo": {"type": ["string", "null"]},
                    "publisher_workflow_ref": {"type": ["string", "null"]},
                    "rekor_log_index": {"type": ["integer", "string", "null"]},
                    "verified_count": {"type": "integer", "minimum": 0},
                    "total_count": {"type": "integer", "minimum": 0},
                },
            },
            "sbom": {
                "type": "object",
                "additionalProperties": True,
                "properties": {
                    "components_count": {"type": ["integer", "null"], "minimum": 0},
                    "license_breakdown": {
                        "type": "object",
                        "additionalProperties": {"type": "integer", "minimum": 0},
                    },
                    "weak_copyleft": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "strong_copyleft": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "unknown_license": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "sbom_artifact_path": {"type": ["string", "null"]},
                },
            },
            "errors": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    }


def _governance_schema() -> dict[str, Any]:
    rate = {"type": ["number", "null"], "minimum": 0.0, "maximum": 1.0}
    nonneg_int = {"type": ["integer", "null"], "minimum": 0}
    return {
        "type": "object",
        "title": "GovernanceSection",
        "description": "Output of collector.governance.collect()",
        "additionalProperties": True,
        "properties": {
            "dco_signoff_rate_90d": rate,
            "conventional_commits_rate_90d": rate,
            "verified_commit_ratio_90d": rate,
            "commits_90d": nonneg_int,
            "unique_committers_90d": nonneg_int,
            "branch_protection_enabled": {"type": ["boolean", "null"]},
            "branch_protection_summary": {"type": ["object", "null"]},
            "codeowners_path": {"type": ["string", "null"]},
            "security_md_present": {"type": "boolean"},
            "security_md_disclosure_window_days": nonneg_int,
            "notice_present": {"type": "boolean"},
            "license_files_in_sdist": {
                "type": "array",
                "items": {"type": "string"},
            },
            "releases_90d": nonneg_int,
            "median_pr_age_days": {"type": ["number", "null"]},
            "open_pr_count": nonneg_int,
            "open_issue_count": nonneg_int,
            "time_to_pypi_seconds_median": {"type": ["integer", "number", "null"]},
            "errors": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    }


def _code_metrics_section() -> dict[str, Any]:
    leaf = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "src_loc": {"type": ["integer", "null"], "minimum": 0},
            "tests_loc": {"type": ["integer", "null"], "minimum": 0},
            "src_files": {"type": ["integer", "null"], "minimum": 0},
            "tests_files": {"type": ["integer", "null"], "minimum": 0},
        },
    }
    return {
        "type": "object",
        "title": "CodeMetricsSection",
        "description": "Output of collector.code_metrics.collect()",
        "additionalProperties": True,
        "properties": {
            "python": leaf,
            "rust": leaf,
            "errors": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    }


# ---------------------------------------------------------------------------
# Top-level snapshot
# ---------------------------------------------------------------------------


def build_snapshot_schema(*, generator_version: str | None = None) -> dict[str, Any]:
    """Return the full JSON Schema document for ``snapshot.json``.

    Args:
        generator_version: Override the version embedded in ``$id``.
            Defaults to the live ``collector.__version__``; tests pin
            this for byte-for-byte reproducibility.
    """
    version = generator_version or COLLECTOR_VERSION
    module_schema = dataclass_to_schema(ModuleSnapshot)
    # Override the dict-typed sections with the richer hand-written
    # sub-schemas — dataclass_to_schema only sees them as `dict[str, Any]`.
    module_schema["properties"]["supply_chain"] = _supply_chain_schema()
    module_schema["properties"]["governance"] = _governance_schema()
    module_schema["properties"]["code_metrics"] = _code_metrics_section()

    return {
        "$schema": SCHEMA_DRAFT,
        # Draft 2020-12 disallows non-empty fragments in $id; the
        # collector version lives in $comment instead, where consumers
        # can grep for it without violating the metaschema.
        "$id": SCHEMA_ID_BASE,
        "$comment": f"kaos-compliance collector version: {version}",
        "title": "KAOS Compliance Snapshot",
        "description": (
            "Source-of-truth JSON published at "
            "/api/v1/snapshot.json. See docs/DATA-MODEL.md for the "
            "prose specification and docs/METHODOLOGY.md for the "
            "collection methodology. Generated by "
            f"kaos-compliance v{version}."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "generated_at", "modules"],
        "properties": {
            "schema_version": {
                "type": "string",
                "const": SCHEMA_VERSION,
                "description": "Snapshot schema version. Bumped on breaking changes only.",
            },
            "generated_at": {
                "type": "string",
                "format": "date-time",
                "description": "RFC 3339 UTC timestamp; trailing Z.",
            },
            "generator": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "version"],
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                },
            },
            "heartbeat": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "last_full_sweep_at",
                    "last_light_sweep_at",
                    "last_security_sweep_at",
                    "stale_threshold_hours",
                ],
                "properties": {
                    "last_full_sweep_at": {"type": "string", "format": "date-time"},
                    "last_light_sweep_at": {"type": "string", "format": "date-time"},
                    "last_security_sweep_at": {"type": "string", "format": "date-time"},
                    "stale_threshold_hours": {
                        "type": "integer",
                        "minimum": 1,
                        "default": STALE_THRESHOLD_HOURS,
                    },
                },
            },
            "modules": {
                "type": "array",
                "items": module_schema,
            },
        },
        "$defs": {
            "IdentitySection": dataclass_to_schema(IdentitySection),
            "CISection": dataclass_to_schema(CISection),
            "SecuritySection": dataclass_to_schema(SecuritySection),
            "OpenPRsSection": dataclass_to_schema(OpenPRsSection),
            "FreshnessSection": dataclass_to_schema(FreshnessSection),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """``python -m collector.schema --output snapshot.schema.json``."""
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="collector.schema",
        description="Emit the JSON Schema (Draft 2020-12) for the snapshot.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="-",
        help="Path to write the schema to; '-' for stdout (default).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print (indent=2). Default for files; ignored for stdout.",
    )
    args = parser.parse_args(argv)

    schema = build_snapshot_schema()
    indent = 2 if (args.pretty or args.output != "-") else None
    payload = json.dumps(schema, indent=indent) + ("\n" if indent else "")

    if args.output == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(f"schema written → {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
