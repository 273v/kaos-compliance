"""Per-module health rules shared by the renderer and the history writer.

Every green / yellow / red / gray decision for the Build, Tests, Security
and Updates signals lives here, so the index grid, the org rollup and the
90-day history cannot disagree about what "passing" means. Inputs are the
per-module snapshot dicts produced by :mod:`collector.snapshot`.

4-state semantics (docs/research/05-style-guide.md):
  green  - we have the data and it is good
  yellow - data exists but has a known soft issue
  red    - data exists and it is a problem
  gray   - no data yet (never a synonym for green)

A lane with no observable run (``None`` conclusion) contributes nothing:
it neither passes nor fails the signal. If every input for a signal is
unobservable, the signal is gray.
"""

from __future__ import annotations

from typing import Any

_RED_CONCLUSIONS = ("failure", "timed_out", "action_required", "startup_failure")

# Open-PR age thresholds for the Updates signal (days since the oldest
# open PR was created).
UPDATES_YELLOW_DAYS = 14
UPDATES_RED_DAYS = 30

_SEVERITY_RANK = {"green": 0, "gray": 0, "yellow": 1, "red": 2}


def conclusion_state(conclusion: str | None) -> str:
    """Map one workflow conclusion to a pill state."""
    if conclusion == "success":
        return "green"
    if conclusion in _RED_CONCLUSIONS:
        return "red"
    if conclusion == "cancelled":
        return "yellow"
    return "gray"


def _combine(states: list[str]) -> str:
    """Worst observed state wins; gray only when nothing was observed."""
    observed = [s for s in states if s != "gray"]
    if not observed:
        return "gray"
    return max(observed, key=lambda s: _SEVERITY_RANK[s])


def build_state(module: dict[str, Any]) -> str:
    """quality + test + build lanes on main (the PR-required gate)."""
    return conclusion_state((module.get("ci") or {}).get("workflow_conclusion"))


def tests_state(module: dict[str, Any]) -> str:
    """PR-required lanes plus the scheduled ``compat`` and ``min-deps`` lanes."""
    ci = module.get("ci") or {}
    return _combine(
        [
            conclusion_state(ci.get("workflow_conclusion")),
            conclusion_state(ci.get("compat_conclusion")),
            conclusion_state(ci.get("min_deps_conclusion")),
        ]
    )


def advisories_state(module: dict[str, Any]) -> str:
    """Known advisories against locked dependencies (OSV.dev).

    red for any critical / high advisory, yellow for moderate / low /
    unknown-severity ones, green for a completed scan with none, gray
    when the scan did not run.
    """
    adv = module.get("advisories") or {}
    if adv.get("scanned_components") is None:
        return "gray"
    counts = adv.get("counts") or {}
    if (counts.get("critical") or 0) + (counts.get("high") or 0) > 0:
        return "red"
    if (counts.get("total") or 0) > 0:
        return "yellow"
    return "green"


def security_state(module: dict[str, Any]) -> str:
    """security-light + security-full lanes plus open dependency advisories."""
    sec = module.get("security") or {}
    return _combine(
        [
            conclusion_state(sec.get("workflow_conclusion")),
            conclusion_state(sec.get("full_workflow_conclusion")),
            advisories_state(module),
        ]
    )


def updates_state(module: dict[str, Any]) -> str:
    """Are dependency / contributor PRs being merged, or piling up?"""
    prs = module.get("open_prs") or {}
    count = prs.get("count")
    if count is None:
        return "gray"
    oldest = prs.get("oldest_age_days")
    if count == 0 or oldest is None:
        return "green"
    if oldest > UPDATES_RED_DAYS:
        return "red"
    if oldest > UPDATES_YELLOW_DAYS:
        return "yellow"
    return "green"
