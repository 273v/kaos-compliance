"""License-allowlist policy loader.

Reads `policy/license-allowlist.yaml` and offers two query primitives
the renderer uses to re-classify license pills:

  - :func:`is_allowed(spdx, component, policy)` — True iff the
    (SPDX, component) pair has an explicit allowlist entry. Used to
    promote a yellow-pill component to a green-with-asterisk pill on
    the dashboard.
  - :func:`parser_gap_for(component, policy)` — the pending parser-fix
    entry for an unknown-license component, or None. Used to annotate
    "License clean" pills with "Pending parser fix" instead of a
    silent yellow.

The renderer must NOT enforce the policy silently. Every allowlist
match renders an asterisk on the pill that links to
``/license-policy.html#<component>``, where the public rationale is
visible. This is the transparency guarantee.

Stdlib + PyYAML only. PyYAML ships with the kaos-llm-client transitive
graph; if it's not importable, the policy is treated as empty (pills
stay at their unfiltered state).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

yaml: Any | None
try:
    import yaml as _yaml  # ty: ignore[unresolved-import]

    yaml = _yaml
except ImportError:  # pragma: no cover - PyYAML is a soft dep
    yaml = None


@dataclass(frozen=True, slots=True)
class AllowedExpression:
    """One entry from ``allowed_expressions``."""

    spdx: str
    components: tuple[str, ...]
    rationale: str
    review_date: str
    audit_ref: str


@dataclass(frozen=True, slots=True)
class ParserGap:
    """One entry from ``parser_gaps`` — known true license, pending parser fix."""

    component: str
    true_license: str
    affected_repos: tuple[str, ...]
    fix_strategy: str
    audit_ref: str


@dataclass(frozen=True, slots=True)
class Policy:
    """In-memory representation of license-allowlist.yaml."""

    version: str
    last_reviewed: str
    reviewers: tuple[str, ...]
    allowed_expressions: tuple[AllowedExpression, ...]
    parser_gaps: tuple[ParserGap, ...]
    allowed_license_classes: tuple[str, ...]
    blocked_license_classes: tuple[str, ...]

    # Indexed lookups built once at load time.
    _allow_index: dict[tuple[str, str], AllowedExpression] = field(default_factory=dict)
    _gap_index: dict[str, ParserGap] = field(default_factory=dict)

    def is_allowed(self, spdx: str | None, component: str) -> AllowedExpression | None:
        """Return the matching policy entry for (spdx, component), or None."""
        if not spdx:
            return None
        return self._allow_index.get((spdx, component))

    def parser_gap_for(self, component: str) -> ParserGap | None:
        """Return the pending parser-fix entry for ``component``, or None."""
        return self._gap_index.get(component)

    def is_blocked_class(self, license_class: str | None) -> bool:
        """True iff ``license_class`` is on the hard-fail list."""
        return bool(license_class) and license_class in self.blocked_license_classes


_EMPTY_POLICY = Policy(
    version="0",
    last_reviewed="",
    reviewers=(),
    allowed_expressions=(),
    parser_gaps=(),
    allowed_license_classes=(),
    blocked_license_classes=(),
)


def load(policy_path: Path | None = None) -> Policy:
    """Load the policy file from disk. Returns an empty policy on any failure.

    Failure cases the renderer must be robust to:

    - File missing (fresh checkout, dashboard preview).
    - YAML parse error.
    - PyYAML not importable in the runtime env.

    In all three, the renderer should fall back to the unfiltered pill
    semantics (no false greens). The dashboard already operates without
    the policy file by default, so this is non-fatal.
    """
    if yaml is None:
        return _EMPTY_POLICY

    if policy_path is None:
        # Default: repo-root/policy/license-allowlist.yaml.
        policy_path = Path(__file__).resolve().parent.parent / "policy" / "license-allowlist.yaml"
    if not policy_path.is_file():
        return _EMPTY_POLICY

    try:
        data: dict[str, Any] = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return _EMPTY_POLICY

    allowed = tuple(
        AllowedExpression(
            spdx=entry["spdx"],
            components=tuple(entry.get("components") or []),
            rationale=entry.get("rationale", "").strip(),
            review_date=entry.get("review_date", ""),
            audit_ref=entry.get("audit_ref", ""),
        )
        for entry in (data.get("allowed_expressions") or [])
    )
    gaps = tuple(
        ParserGap(
            component=entry["component"],
            true_license=entry.get("true_license", ""),
            affected_repos=tuple(entry.get("affected_repos") or []),
            fix_strategy=entry.get("fix_strategy", ""),
            audit_ref=entry.get("audit_ref", ""),
        )
        for entry in (data.get("parser_gaps") or [])
    )

    # Indexed lookups: (spdx, component) -> entry, and component -> gap.
    allow_index: dict[tuple[str, str], AllowedExpression] = {}
    for e in allowed:
        for c in e.components:
            allow_index[(e.spdx, c)] = e
    gap_index = {g.component: g for g in gaps}

    return Policy(
        version=str(data.get("policy_version", "0")),
        last_reviewed=str(data.get("last_reviewed", "")),
        reviewers=tuple(data.get("reviewers") or []),
        allowed_expressions=allowed,
        parser_gaps=gaps,
        allowed_license_classes=tuple(data.get("allowed_license_classes") or []),
        blocked_license_classes=tuple(data.get("blocked_license_classes") or []),
        _allow_index=allow_index,
        _gap_index=gap_index,
    )
