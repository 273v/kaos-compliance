"""Unit tests for ``collector.governance``.

Stdlib + pytest only, by design. Every test stubs ``gh_run`` and
``url_get_json`` --- no network, no ``gh`` binary on PATH. The injected
helpers are positional-only-friendly callables that emit a tiny shim
matching ``subprocess.CompletedProcess[str]`` (only ``.stdout`` is read).
"""

from __future__ import annotations

import base64
import datetime
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from collector import governance


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _FakeProc:
    """Minimal ``CompletedProcess``-shaped stub."""

    stdout: str


class _NotFound(Exception):
    """Stands in for ``CalledProcessError`` with a 404-flavored stderr."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "HTTP 404: Not Found"


def _fake_gh(routes: dict[str, Any]) -> Callable:
    """Build a ``gh_run`` stub that dispatches on the first arg path.

    ``routes`` maps a URL fragment (substring match against ``args[1]``)
    to either:
      * a JSON-serializable value → returned as a single CompletedProcess
      * a callable(args) → returns CompletedProcess
      * the special value ``_NotFound`` (the class itself) → raises 404
    """

    def _run(args, *, timeout=30.0, **_kwargs):
        # args[0] is the verb (always "api" in this module).
        path = args[1] if len(args) > 1 else ""
        for fragment, payload in routes.items():
            if fragment in path:
                if payload is _NotFound:
                    raise _NotFound()
                if callable(payload):
                    return _FakeProc(payload(args))
                if isinstance(payload, str):
                    return _FakeProc(payload)
                return _FakeProc(json.dumps(payload))
        # Default: pretend it's a 404 so unwired branches return honest gaps.
        raise _NotFound()

    return _run


def _fake_url_get(routes: dict[str, Any]) -> Callable:
    def _get(url, *, headers=None, timeout=15.0, **_kw):
        for fragment, payload in routes.items():
            if fragment in url:
                if payload is _NotFound:
                    raise _NotFound()
                if callable(payload):
                    return payload(url)
                return payload
        raise _NotFound()

    return _get


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _commit(
    msg: str,
    *,
    verified: bool = False,
    author_login: str | None = "alice",
    author_email: str = "alice@example.com",
) -> dict[str, Any]:
    """Shape one element of the ``GET /commits`` response."""
    return {
        "sha": "deadbeef",
        "commit": {
            "message": msg,
            "author": {"email": author_email, "date": "2026-03-01T00:00:00Z"},
            "verification": {"verified": verified},
        },
        "author": {"login": author_login} if author_login else None,
    }


# ---------------------------------------------------------------------------
# Smoke
# ---------------------------------------------------------------------------


def test_collect_returns_all_contract_keys():
    """Even with every call 404'ing, the result has every contracted key."""
    result = governance.collect(
        "kaos-nothing",
        gh_run=_fake_gh({}),
        url_get_json=_fake_url_get({}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
    )
    expected_keys = {
        "dco_signoff_rate_90d",
        "conventional_commits_rate_90d",
        "verified_commit_ratio_90d",
        "commits_90d",
        "unique_committers_90d",
        "branch_protection_enabled",
        "branch_protection_summary",
        "codeowners_path",
        "security_md_present",
        "security_md_disclosure_window_days",
        "notice_present",
        "license_files_in_sdist",
        "releases_90d",
        "median_pr_age_days",
        "open_pr_count",
        "open_issue_count",
        "time_to_pypi_seconds_median",
        "errors",
    }
    assert set(result.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Commit-derived ratios (DCO, CC, verified)
# ---------------------------------------------------------------------------


def test_dco_and_cc_rates_three_decimal_places():
    """8 commits, mixed sign-off + conventional + verified."""
    commits = [
        _commit("feat: add widget\n\nSigned-off-by: Alice <alice@x>", verified=True),
        _commit("fix(core): patch race\n\nSigned-off-by: Alice <alice@x>", verified=True),
        _commit("chore: bump deps", verified=False, author_login="bob"),
        _commit("docs: improve readme\n\nSigned-off-by: Carol <c@x>", verified=False),
        _commit("typo", verified=False),  # neither DCO nor CC
        _commit(
            "refactor!: breaking redesign\n\nSigned-off-by: alice@x",
            verified=True,
        ),
        # Non-CC type ("update") should NOT match.
        _commit("update: bump version", verified=False),
        # CC with scope and bang.
        _commit("perf(io)!: hot path\n\nSigned-off-by: D <d@x>", verified=True),
    ]
    # 5 of 8 have Signed-off-by → 0.625
    # 6 of 8 match CC prefix (feat, fix, chore, docs, refactor!, perf(io)!) → 0.750
    # 4 of 8 are verified → 0.500
    gh = _fake_gh({"/commits?since=": json.dumps(commits)})
    out = governance._commits_section(
        "kaos-test",
        gh_run=gh,
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    assert out["commits_90d"] == 8
    assert out["dco_signoff_rate_90d"] == pytest.approx(0.625, abs=1e-3)
    assert out["conventional_commits_rate_90d"] == pytest.approx(0.750, abs=1e-3)
    assert out["verified_commit_ratio_90d"] == pytest.approx(0.500, abs=1e-3)


def test_dco_signed_off_by_must_anchor_to_line_start():
    """Mentioning ``signed-off-by:`` mid-paragraph must not count."""
    commits = [
        _commit("feat: legit\n\nSigned-off-by: A <a@x>"),
        _commit("feat: trickery\n\nSee discussion at signed-off-by: foo above"),
        _commit("feat: trickery\n\n  Signed-off-by: indented"),  # not at col 0
    ]
    out = governance._commits_section(
        "kaos-test",
        gh_run=_fake_gh({"/commits?since=": json.dumps(commits)}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    # Only the first one is canonical DCO.
    assert out["dco_signoff_rate_90d"] == pytest.approx(0.333, abs=1e-3)


def test_unique_committers_handles_unmapped_author():
    """When GH can't map an email to a user, the commit's email is the key."""
    commits = [
        _commit("feat: a", author_login="alice"),
        _commit("feat: b", author_login=None, author_email="ghost@x"),
        _commit("feat: c", author_login=None, author_email="GHOST@x"),  # case-fold
        _commit("feat: d", author_login="alice"),
    ]
    out = governance._commits_section(
        "kaos-test",
        gh_run=_fake_gh({"/commits?since=": json.dumps(commits)}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    # {login:alice, email:ghost@x}  ← case-folded, so 2 unique.
    assert out["unique_committers_90d"] == 2


def test_empty_commit_window_returns_none_ratios_not_zero():
    """0 commits → ratios are None (undefined), not 0.0."""
    out = governance._commits_section(
        "kaos-test",
        gh_run=_fake_gh({"/commits?since=": "[]"}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    assert out["commits_90d"] == 0
    assert out["dco_signoff_rate_90d"] is None
    assert out["conventional_commits_rate_90d"] is None
    assert out["verified_commit_ratio_90d"] is None
    assert out["unique_committers_90d"] == 0


def test_paginated_commits_concatenated_arrays_are_parsed():
    """gh --paginate emits ``[...][...]`` back-to-back; we must handle it."""
    page1 = [_commit("feat: a"), _commit("fix: b")]
    page2 = [_commit("chore: c")]
    blob = json.dumps(page1) + json.dumps(page2)
    out = governance._commits_section(
        "kaos-test",
        gh_run=_fake_gh({"/commits?since=": blob}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    assert out["commits_90d"] == 3
    assert out["conventional_commits_rate_90d"] == pytest.approx(1.0, abs=1e-3)


# ---------------------------------------------------------------------------
# Branch protection
# ---------------------------------------------------------------------------


def test_branch_protection_404_is_honest_false():
    """404 "Branch not protected" → enabled=False, summary={}, no exception."""
    errors: list[str] = []
    enabled, summary = governance._branch_protection(
        "kaos-test",
        gh_run=_fake_gh({"/branches/main/protection": _NotFound}),
        errors=errors,
    )
    assert enabled is False
    assert summary == {}
    assert errors == []  # 404 is not an error, it's the answer.


def test_branch_protection_present_summarises_three_fields():
    payload = {
        "required_status_checks": {"contexts": ["ci"]},
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "required_signatures": {"enabled": True},
        "url": "https://api.github.com/...",
        "enforce_admins": {"enabled": False},
    }
    errors: list[str] = []
    enabled, summary = governance._branch_protection(
        "kaos-test",
        gh_run=_fake_gh({"/branches/main/protection": payload}),
        errors=errors,
    )
    assert enabled is True
    assert summary is not None
    assert summary["required_signatures"] is True
    assert summary["required_status_checks"] == {"contexts": ["ci"]}
    assert "enforce_admins" not in summary  # we drop noisy fields


def test_branch_protection_retry_exhaustion_yields_none_and_error():
    """A non-404 failure must yield None + None and record an error."""
    def _boom(_args):
        raise RuntimeError("github exploded")

    errors: list[str] = []
    enabled, summary = governance._branch_protection(
        "kaos-test",
        gh_run=_fake_gh({"/branches/main/protection": _boom}),
        errors=errors,
    )
    assert enabled is None
    assert summary is None
    assert any("branch_protection" in e for e in errors)


# ---------------------------------------------------------------------------
# SECURITY.md parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        ("Disclosure within 90 days of report.", 90),
        ("Our 90-day window is firm.", 90),
        ("Coordinated 180-day disclosure as a maximum.", 180),
        ("Target: 60 days from acknowledgement to public disclosure.", 60),
        # The "3 business days" acknowledgement is below the floor and ignored;
        # the "90 days" disclosure target dominates.
        (
            "Acknowledgement within 3 business days. "
            "Target window is 90 days to disclosure.",
            90,
        ),
        ("No mention of any window here.", None),
        # Multiple candidates: largest plausible wins.
        ("Triage in 30 days, public in 120 days.", 120),
    ],
)
def test_disclosure_window_parsing(body, expected):
    assert governance._extract_disclosure_window(body) == expected


def test_security_md_decoded_and_window_extracted():
    body = (
        "# Security policy\n\n"
        "We disclose within 90 days of confirmed reports.\n"
        "Acknowledgement within 3 business days.\n"
    )
    payload = {
        "name": "SECURITY.md",
        "path": "SECURITY.md",
        "content": _b64(body),
        "encoding": "base64",
    }
    errors: list[str] = []
    present, window = governance._security_md(
        "kaos-test",
        gh_run=_fake_gh({"/contents/SECURITY.md": payload}),
        errors=errors,
    )
    assert present is True
    assert window == 90
    assert errors == []


def test_security_md_404_is_present_false_window_none():
    present, window = governance._security_md(
        "kaos-test",
        gh_run=_fake_gh({"/contents/SECURITY.md": _NotFound}),
        errors=[],
    )
    assert present is False
    assert window is None


# ---------------------------------------------------------------------------
# CODEOWNERS lookup order
# ---------------------------------------------------------------------------


def test_codeowners_prefers_github_dir_then_root():
    routes = {
        "/contents/.github/CODEOWNERS": {"path": ".github/CODEOWNERS"},
        "/contents/CODEOWNERS": {"path": "CODEOWNERS"},
    }
    assert (
        governance._codeowners_path(
            "kaos-test", gh_run=_fake_gh(routes), errors=[]
        )
        == ".github/CODEOWNERS"
    )


def test_codeowners_falls_back_to_root_when_github_missing():
    # The default ``_fake_gh`` raises NotFound on unwired paths, which is
    # exactly the canonical "no file there" answer.
    routes = {"/contents/CODEOWNERS": {"path": "CODEOWNERS"}}
    assert (
        governance._codeowners_path(
            "kaos-test", gh_run=_fake_gh(routes), errors=[]
        )
        == "CODEOWNERS"
    )


def test_codeowners_missing_returns_none():
    assert (
        governance._codeowners_path(
            "kaos-test", gh_run=_fake_gh({}), errors=[]
        )
        is None
    )


# ---------------------------------------------------------------------------
# Open PRs / median age
# ---------------------------------------------------------------------------


def test_median_pr_age_days_empty_list_is_none_not_zero():
    """Empty open-PR list → median is None, NOT 0."""
    count, median_age = governance._open_pr_signals(
        "kaos-test",
        gh_run=_fake_gh({"/pulls?state=open": "[]"}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    assert count == 0
    assert median_age is None


def test_median_pr_age_days_three_prs():
    now = datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC)
    prs = [
        {"created_at": "2026-05-10T00:00:00Z"},  # 1 day
        {"created_at": "2026-05-08T00:00:00Z"},  # 3 days
        {"created_at": "2026-05-01T00:00:00Z"},  # 10 days
    ]
    count, median_age = governance._open_pr_signals(
        "kaos-test",
        gh_run=_fake_gh({"/pulls?state=open": json.dumps(prs)}),
        now=now,
        errors=[],
    )
    assert count == 3
    assert median_age == pytest.approx(3.0, abs=1e-3)


# ---------------------------------------------------------------------------
# Releases / time-to-PyPI failure isolation
# ---------------------------------------------------------------------------


def test_releases_90d_filters_to_window():
    now = datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC)
    releases = [
        {"tag_name": "v0.2.0", "published_at": "2026-05-01T00:00:00Z"},   # in
        {"tag_name": "v0.1.0", "published_at": "2026-04-01T00:00:00Z"},   # in
        {"tag_name": "v0.0.1", "published_at": "2025-01-01T00:00:00Z"},   # out
    ]
    count, in_window = governance._releases_90d(
        "kaos-test",
        gh_run=_fake_gh({"/releases?per_page=100": json.dumps(releases)}),
        now=now,
        errors=[],
    )
    assert count == 2
    assert [r["tag_name"] for r in in_window] == ["v0.2.0", "v0.1.0"]


def test_time_to_pypi_failure_sets_field_none_and_records_error_other_fields_populate():
    """The headline failure-isolation test.

    ``url_get_json`` is wired ONLY for ``pypi.org/.../json`` so that
    ``_pypi_upload_time`` blows up for every release; meanwhile every
    governance signal that does NOT depend on PyPI must still populate.
    """
    now = datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC)

    # One commit so commit ratios populate.
    commits = [
        _commit("feat: a\n\nSigned-off-by: A <a@x>", verified=True),
        _commit("fix: b", verified=False),
    ]
    one_release = [
        {"tag_name": "v0.1.0", "published_at": "2026-05-01T00:00:00Z"},
    ]
    security_body = "Coordinated disclosure within 90 days."

    gh = _fake_gh(
        {
            "/commits?since=": json.dumps(commits),
            "/branches/main/protection": _NotFound,
            "/contents/.github/CODEOWNERS": {"path": ".github/CODEOWNERS"},
            "/contents/SECURITY.md": {"content": _b64(security_body)},
            "/contents/NOTICE": {"content": _b64("notice")},
            "/releases?per_page=100": json.dumps(one_release),
            "/pulls?state=open": "[]",
            "/issues?state=open": "[]",
            # Tag lookup succeeds...
            "/git/ref/tags/v0.1.0": {
                "object": {"sha": "deadbeef", "type": "tag"},
            },
            "/git/tags/deadbeef": {
                "tagger": {"date": "2026-05-01T00:00:00Z"},
            },
        }
    )

    # ...but the PyPI side always raises (NotFound for the package JSON).
    url_get = _fake_url_get({})  # default raises _NotFound

    result = governance.collect(
        "kaos-broken", gh_run=gh, url_get_json=url_get, now=now
    )

    # The headline assertion:
    assert result["time_to_pypi_seconds_median"] is None
    assert any("time_to_pypi" in e for e in result["errors"])

    # And every other field still populated honestly:
    assert result["commits_90d"] == 2
    assert result["dco_signoff_rate_90d"] == pytest.approx(0.5, abs=1e-3)
    assert result["verified_commit_ratio_90d"] == pytest.approx(0.5, abs=1e-3)
    assert result["branch_protection_enabled"] is False
    assert result["branch_protection_summary"] == {}
    assert result["codeowners_path"] == ".github/CODEOWNERS"
    assert result["security_md_present"] is True
    assert result["security_md_disclosure_window_days"] == 90
    assert result["notice_present"] is True
    assert result["releases_90d"] == 1
    assert result["open_pr_count"] == 0
    assert result["median_pr_age_days"] is None  # empty list → None, not 0
    assert result["open_issue_count"] == 0


def test_time_to_pypi_median_seconds_round_trip():
    """Happy-path time-to-pypi calculation across two releases."""
    now = datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC)
    releases = [
        {"tag_name": "v0.2.0", "published_at": "2026-05-01T00:00:00Z"},
        {"tag_name": "v0.1.0", "published_at": "2026-04-01T00:00:00Z"},
    ]
    # Tag pushed at 2026-05-01T00:00:00Z; PyPI at 00:01:00Z → 60s.
    # Tag pushed at 2026-04-01T00:00:00Z; PyPI at 00:05:00Z → 300s.
    # Median = 180s.
    gh = _fake_gh(
        {
            "/releases?per_page=100": json.dumps(releases),
            "/git/ref/tags/v0.2.0": {
                "object": {"sha": "sha02", "type": "tag"},
            },
            "/git/tags/sha02": {"tagger": {"date": "2026-05-01T00:00:00Z"}},
            "/git/ref/tags/v0.1.0": {
                "object": {"sha": "sha01", "type": "commit"},
            },
            "/git/commits/sha01": {
                "committer": {"date": "2026-04-01T00:00:00Z"}
            },
        }
    )
    url_get = _fake_url_get(
        {
            "/pypi/kaos-test/0.2.0/json": {
                "urls": [
                    {"upload_time_iso_8601": "2026-05-01T00:01:00Z"},
                ]
            },
            "/pypi/kaos-test/0.1.0/json": {
                "urls": [
                    {"upload_time_iso_8601": "2026-04-01T00:05:00Z"},
                ]
            },
        }
    )
    errors: list[str] = []
    _, in_window = governance._releases_90d(
        "kaos-test", gh_run=gh, now=now, errors=errors
    )
    median = governance._time_to_pypi_seconds_median(
        "kaos-test",
        in_window,
        gh_run=gh,
        url_get_json=url_get,
        errors=errors,
    )
    assert median == 180
    assert errors == []


# ---------------------------------------------------------------------------
# Cost-bounded loop guard
# ---------------------------------------------------------------------------


def test_commits_hard_cap_truncates_to_1000():
    """The commit loop must never process more than 1000 entries."""
    huge = [_commit("feat: spam") for _ in range(1500)]
    out = governance._commits_section(
        "kaos-test",
        gh_run=_fake_gh({"/commits?since=": json.dumps(huge)}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
        errors=[],
    )
    assert out["commits_90d"] == 1000


# ---------------------------------------------------------------------------
# Anti-pattern guardrails (docs/research/01-compliance-signal-inventory.md)
# ---------------------------------------------------------------------------


def test_no_forbidden_keys_in_output_contract():
    """The result dict must NOT carry any of the explicitly-skipped signals."""
    result = governance.collect(
        "kaos-empty",
        gh_run=_fake_gh({}),
        url_get_json=_fake_url_get({}),
        now=datetime.datetime(2026, 5, 11, tzinfo=datetime.UTC),
    )
    for forbidden in (
        "stars",
        "fork_count",
        "maintainer_country",
        "real_name",
        "signed_releases",
        "governance_score",
        "composite_score",
        "contributor_org_count",
    ):
        assert forbidden not in result
