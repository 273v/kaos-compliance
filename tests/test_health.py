"""Health rules shared by the renderer and the history writer."""

from __future__ import annotations

from typing import Any

import pytest

from collector import health


def _module(
    *,
    ci: str | None = "success",
    compat: str | None = "success",
    min_deps: str | None = "success",
    light: str | None = "success",
    full: str | None = "success",
    scanned: int | None = 100,
    counts: dict[str, int] | None = None,
    pr_count: int | None = 0,
    oldest: int | None = None,
) -> dict[str, Any]:
    base_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "unknown": 0}
    base_counts.update(counts or {})
    base_counts["total"] = sum(base_counts.values())
    return {
        "name": "kaos-x",
        "ci": {
            "workflow_conclusion": ci,
            "compat_conclusion": compat,
            "min_deps_conclusion": min_deps,
        },
        "security": {"workflow_conclusion": light, "full_workflow_conclusion": full},
        "advisories": {"scanned_components": scanned, "counts": base_counts},
        "open_prs": {"count": pr_count, "oldest_age_days": oldest},
    }


def test_all_green() -> None:
    m = _module()
    assert health.build_state(m) == "green"
    assert health.tests_state(m) == "green"
    assert health.security_state(m) == "green"
    assert health.updates_state(m) == "green"


# The failure modes the pre-2.0 dashboard reported as green.
@pytest.mark.parametrize(
    ("kwargs", "signal"),
    [
        ({"compat": "failure"}, "tests"),
        ({"min_deps": "failure"}, "tests"),
        ({"full": "failure"}, "security"),
        ({"counts": {"critical": 1}}, "security"),
        ({"counts": {"high": 2}}, "security"),
        ({"pr_count": 46, "oldest": 58}, "updates"),
    ],
)
def test_previously_hidden_failures_are_red(kwargs: dict[str, Any], signal: str) -> None:
    m = _module(**kwargs)
    assert getattr(health, f"{signal}_state")(m) == "red"
    # The PR-required build lane alone stays green; the regression is only
    # visible through the widened signal.
    assert health.build_state(m) == "green"


@pytest.mark.parametrize("sev", ["moderate", "low", "unknown"])
def test_non_high_advisories_are_yellow(sev: str) -> None:
    assert health.security_state(_module(counts={sev: 1})) == "yellow"


def test_unscanned_advisories_do_not_mask_or_fail() -> None:
    m = _module(scanned=None)
    assert health.advisories_state(m) == "gray"
    assert health.security_state(m) == "green"


def test_missing_lanes_are_ignored_not_failed() -> None:
    m = _module(compat=None, min_deps=None, full=None)
    assert health.tests_state(m) == "green"
    assert health.security_state(m) == "green"


def test_nothing_observed_is_gray() -> None:
    m = _module(ci=None, compat=None, min_deps=None, light=None, full=None, scanned=None)
    assert health.tests_state(m) == "gray"
    assert health.security_state(m) == "gray"


def test_cancelled_is_yellow_and_failure_outranks_it() -> None:
    assert health.tests_state(_module(compat="cancelled")) == "yellow"
    assert health.tests_state(_module(compat="cancelled", min_deps="failure")) == "red"


@pytest.mark.parametrize(
    ("oldest", "state"),
    [
        (0, "green"),
        (health.UPDATES_YELLOW_DAYS, "green"),
        (health.UPDATES_YELLOW_DAYS + 1, "yellow"),
        (health.UPDATES_RED_DAYS, "yellow"),
        (health.UPDATES_RED_DAYS + 1, "red"),
    ],
)
def test_updates_thresholds(oldest: int, state: str) -> None:
    assert health.updates_state(_module(pr_count=3, oldest=oldest)) == state


def test_updates_unknown_when_lookup_failed() -> None:
    assert health.updates_state(_module(pr_count=None)) == "gray"
