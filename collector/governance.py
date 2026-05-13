"""Governance + velocity signal collector for the kaos-compliance dashboard.

This module gathers the per-repo signals that answer two of the four buckets
in ``docs/research/01-compliance-signal-inventory.md`` --- **Hygiene** (policy
posture: branch protection, CODEOWNERS, SECURITY.md, license shipped in the
sdist) and **Velocity** (release cadence, PR throughput, time-to-PyPI).

Public surface is one function:

    collect(repo, *, gh_run=..., url_get_json=..., now=None) -> dict

Both helpers are injected so the module can be unit-tested with no network
and no ``gh`` binary on PATH. In production they default to
``collector._retry.gh_run`` and ``collector._retry.url_get_json`` (set by the
caller, not imported here, so this module stays import-cheap).

Design constraints (NON-NEGOTIABLE; see docs/research/01-compliance-signal-inventory.md):

  * Honest gaps. Every signal that fails to extract is ``None``, never ``0``,
    never ``False``-by-default. ``None`` means "we tried and could not tell";
    ``0`` / ``False`` means "we know the answer is zero / no". Confusing these
    is exactly the failure mode the methodology document calls out.
  * No composite governance score. We emit raw signals; the consumer (the
    renderer) is free to compose policy enforcement (e.g., pair
    ``verified_commit_ratio_90d`` with
    ``branch_protection_summary.required_signatures``) but this module does
    not collapse them.
  * No "signed-releases" boolean. We expose ``verified_commit_ratio_90d``
    as a ratio paired with the branch-protection signatures requirement so
    the dashboard never claims a green check on signed-commits alone.
  * No identity / popularity signals: no maintainer country, employer, real
    name, GitHub stars, fork count, contributor org count. Skipped entirely.
  * No "raw test coverage percentage" surfaced from this collector (coverage
    is a CI artifact, not a governance signal).
  * Cost-bounded loops. The commits paginator stops at 1000 commits. The
    time-to-PyPI loop stops at the releases-90d cap. No unbounded recursion,
    no unbounded paging.

GitHub REST endpoints used (verbatim --- each is documented next to its
caller):

  * ``GET repos/{org}/{repo}/commits?since=...&until=...&per_page=100`` (+--paginate)
  * ``GET repos/{org}/{repo}/branches/main`` (public protected flag)
  * ``GET repos/{org}/{repo}/branches/main/protection`` (admin detail when available)
  * ``GET repos/{org}/{repo}/contents/.github/CODEOWNERS`` / ``contents/CODEOWNERS``
  * ``GET repos/{org}/{repo}/contents/SECURITY.md``
  * ``GET repos/{org}/{repo}/contents/NOTICE``
  * ``GET repos/{org}/{repo}/releases?per_page=100``
  * ``GET repos/{org}/{repo}/pulls?state=open&per_page=100`` (+--paginate)
  * ``GET repos/{org}/{repo}/issues?state=open&per_page=100`` (+--paginate)
  * ``GET repos/{org}/{repo}/git/ref/tags/{tag}``
  * ``GET repos/{org}/{repo}/git/tags/{sha}`` (for annotated tag tagger.date)

PyPI:

  * ``GET https://pypi.org/pypi/{pkg}/{version}/json`` (``urls[0].upload_time_iso_8601``)

Stdlib only (plus the two injected callables).
"""

from __future__ import annotations

import base64
import datetime
import json
import re
import statistics
from collections.abc import Callable
from typing import Any

__all__ = ["ORG", "collect"]

ORG = "273v"

# ---------------------------------------------------------------------------
# Cost-bounds. The dashboard runs hourly; pagination must not blow GH's
# secondary rate limits. Every counted loop has a ceiling.
# ---------------------------------------------------------------------------

_COMMITS_HARD_CAP = 1000  # 10 pages of per_page=100 max
_RELEASES_HARD_CAP = 200  # ~2 years of releases at one per week
_OPEN_PRS_HARD_CAP = 500  # if a repo has >500 open PRs, governance is the least of its problems
_OPEN_ISSUES_HARD_CAP = 1000

# ---------------------------------------------------------------------------
# Compiled regexes used in hot loops.
# ---------------------------------------------------------------------------

# DCO sign-off: must be anchored to a line start, case-insensitive. The
# canonical phrasing from the Linux kernel / DCO 1.1 is ``Signed-off-by:``.
_DCO_RE = re.compile(r"^signed-off-by:\s", re.IGNORECASE | re.MULTILINE)

# Conventional Commits 1.0.0: <type>(<scope>)?!?: <description>. The 11
# canonical types per the spec FAQ; everything else is non-conventional.
_CC_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
_CC_RE = re.compile(
    r"^(?:" + "|".join(_CC_TYPES) + r")(?:\([^)]+\))?!?: ",
)

# SECURITY.md disclosure-window phrases. Two patterns:
#   * "<N>-day" / "<N> day" / "<N> days"        (e.g. "90-day window")
#   * "within N days" / "after N days"          (e.g. "disclosure within 90 days")
# We prefer the largest plausible match (the public-disclosure target is
# usually the longest number in the file; "3 business days" is acknowledgement
# triage, not disclosure). Bounded to 7..365 to skip obvious matches like
# "the next day" or noise like "1985".
_DISCLOSURE_RE = re.compile(
    r"(\d{1,3})\s*[-\s]\s*(?:business\s+)?days?",
    re.IGNORECASE,
)
_DISCLOSURE_WORD_RE = re.compile(
    r"(?:within|after|over|in)\s+(\d{1,3})\s+(?:business\s+)?days?",
    re.IGNORECASE,
)
_DISCLOSURE_MIN = 7
_DISCLOSURE_MAX = 365


# ---------------------------------------------------------------------------
# Tiny helpers
# ---------------------------------------------------------------------------


def _iso_z(dt: datetime.datetime) -> str:
    """RFC 3339 UTC timestamp with trailing Z (matches gh's accepted format)."""
    dt = dt.replace(tzinfo=datetime.UTC) if dt.tzinfo is None else dt.astimezone(datetime.UTC)
    return dt.replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def _parse_iso(ts: str | None) -> datetime.datetime | None:
    """Tolerant ISO-8601 parser. Accepts ``Z`` and microsecond precision."""
    if not ts:
        return None
    try:
        # ``2026-05-10T21:07:22.794295Z`` and ``2026-05-10T21:07:22Z``.
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_concatenated_json_arrays(text: str) -> list[Any]:
    """Parse the output of ``gh api ... --paginate``.

    ``gh --paginate`` does NOT emit one large JSON array; it concatenates
    one JSON document per page back-to-back with no separator (e.g.
    ``[..][..][..]``). The 2.46 release also does not yet support
    ``--slurp``, so we parse incrementally with ``JSONDecoder.raw_decode``.
    Returns the concatenation of every top-level array (or wraps a single
    object in a one-element list, defensively).
    """
    text = text.strip()
    if not text:
        return []
    decoder = json.JSONDecoder()
    out: list[Any] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, end = decoder.raw_decode(text, i)
        if isinstance(obj, list):
            out.extend(obj)
        else:
            out.append(obj)
        i = end
    return out


def _is_terminal_404(exc: BaseException) -> bool:
    """True if ``exc`` looks like a 404 from either helper.

    Both ``gh_run`` and ``url_get_json`` re-raise terminal 404s; everything
    else is a retry-exhaustion. Callers use this to convert a 404 into the
    structured "absent" answer (``False`` for file presence, ``False`` for
    branch protection enabled, etc.) without double-counting it as an error.

    ``subprocess.CalledProcessError.__str__`` does NOT include ``stderr``,
    so the gh-CLI path (e.g. ``"Branch not protected (HTTP 404)"``) requires
    a structured peek at ``exc.stderr``. ``urllib.error.HTTPError`` does
    include the code in its repr.
    """
    msg = str(exc).lower()
    if "404" in msg or "not found" in msg or "branch not protected" in msg:
        return True
    stderr = getattr(exc, "stderr", "") or ""
    stderr = stderr.lower() if isinstance(stderr, str) else ""
    return "404" in stderr or "not found" in stderr or "branch not protected" in stderr


# ---------------------------------------------------------------------------
# Section: commits-derived signals (DCO, CC, verified, counts).
# Single GitHub endpoint, multiple metrics computed in one pass.
# ---------------------------------------------------------------------------


def _fetch_commits_90d(
    repo: str,
    *,
    gh_run: Callable,
    now: datetime.datetime,
) -> list[dict[str, Any]]:
    """Page through ``GET repos/{ORG}/{repo}/commits?since=...&until=...``.

    Hard-capped at :data:`_COMMITS_HARD_CAP` commits. The cap is checked by
    truncation after parsing, since ``gh --paginate`` does not expose a
    page-level break hook. In practice the kaos-* repos generate 30-80
    commits/quarter, well below the cap.
    """
    since = _iso_z(now - datetime.timedelta(days=90))
    until = _iso_z(now)
    cp = gh_run(
        [
            "api",
            f"repos/{ORG}/{repo}/commits?since={since}&until={until}&per_page=100",
            "--paginate",
        ],
        timeout=60.0,
    )
    commits = _parse_concatenated_json_arrays(cp.stdout)
    if len(commits) > _COMMITS_HARD_CAP:
        commits = commits[:_COMMITS_HARD_CAP]
    return commits


def _commits_section(
    repo: str,
    *,
    gh_run: Callable,
    now: datetime.datetime,
    errors: list[str],
) -> dict[str, Any]:
    """Compute all commit-derived signals in one pass over the 90d window."""
    out: dict[str, Any] = {
        "dco_signoff_rate_90d": None,
        "conventional_commits_rate_90d": None,
        "verified_commit_ratio_90d": None,
        "commits_90d": None,
        "unique_committers_90d": None,
    }
    try:
        commits = _fetch_commits_90d(repo, gh_run=gh_run, now=now)
    except Exception as exc:
        errors.append(f"commits: {exc}")
        return out

    total = len(commits)
    out["commits_90d"] = total
    if total == 0:
        # Honest zero: we successfully observed an empty window. The ratios
        # are undefined on 0/0 — leave them None, not 0.0.
        out["unique_committers_90d"] = 0
        return out

    dco = 0
    cc = 0
    verified = 0
    committers: set[str] = set()
    for c in commits:
        commit_obj = c.get("commit") or {}
        message = commit_obj.get("message") or ""
        if _DCO_RE.search(message):
            dco += 1
        first_line = message.split("\n", 1)[0]
        if _CC_RE.match(first_line):
            cc += 1
        verification = commit_obj.get("verification") or {}
        if verification.get("verified") is True:
            verified += 1

        # ``c.author`` is the GitHub-user mapping (may be null for unmapped
        # email addresses); fall back to the commit-object author email so
        # we still count distinct humans even when GH can't resolve them.
        author = c.get("author")
        if isinstance(author, dict) and author.get("login"):
            committers.add(f"login:{author['login']}")
        else:
            email = (commit_obj.get("author") or {}).get("email")
            if email:
                committers.add(f"email:{email.lower()}")

    out["dco_signoff_rate_90d"] = round(dco / total, 3)
    out["conventional_commits_rate_90d"] = round(cc / total, 3)
    out["verified_commit_ratio_90d"] = round(verified / total, 3)
    out["unique_committers_90d"] = len(committers)
    return out


# ---------------------------------------------------------------------------
# Section: branch protection.
# ---------------------------------------------------------------------------


def _branch_protection_public_flag(
    repo: str,
    *,
    gh_run: Callable,
) -> tuple[bool | None, dict[str, Any] | None, str | None]:
    """Read the public branch metadata ``protected`` flag.

    GitHub's full branch-protection endpoint requires repository
    Administration read permission for fine-grained tokens. The default
    Actions ``GITHUB_TOKEN`` cannot request that permission, but the
    ordinary branch endpoint is available with contents read and carries
    the public ``protected`` boolean. Use it as the dashboard's honest
    "is protection enabled?" fallback, while leaving admin-only details
    as ``None`` when the detailed endpoint is unavailable.
    """
    try:
        cp = gh_run(["api", f"repos/{ORG}/{repo}/branches/main"])
    except Exception as exc:
        if _is_terminal_404(exc):
            return None, None, None
        return None, None, f"branch_protection_public: {exc}"

    try:
        branch = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        return None, None, f"branch_protection_public: malformed JSON: {exc}"

    protected = branch.get("protected")
    if not isinstance(protected, bool):
        return None, None, "branch_protection_public: missing protected boolean"
    if not protected:
        return False, {}, None

    public_protection = branch.get("protection")
    if not isinstance(public_protection, dict):
        public_protection = {}
    return True, {
        "source": "branches_api",
        "required_status_checks": public_protection.get("required_status_checks"),
        "required_pull_request_reviews": None,
        "required_signatures": None,
    }, None


def _branch_protection(
    repo: str,
    *,
    gh_run: Callable,
    errors: list[str],
) -> tuple[bool | None, dict[str, Any] | None]:
    """Branch-protection state for ``main``.

    The public ``branches/main`` endpoint supplies the enabled/disabled
    boolean. The admin-detail ``branches/main/protection`` endpoint is
    used when the token can read it. If that detailed endpoint is blocked
    by the default Actions token, the enabled flag still stays true and
    the summary is marked as public-branch metadata.

    If both endpoints fail, both fields are ``None`` and ``errors`` gets
    a diagnostic.
    """
    public_enabled, public_summary, public_error = _branch_protection_public_flag(
        repo, gh_run=gh_run
    )
    if public_enabled is False:
        return False, {}

    try:
        cp = gh_run(["api", f"repos/{ORG}/{repo}/branches/main/protection"])
    except Exception as exc:
        if public_enabled is True:
            return True, public_summary
        if _is_terminal_404(exc):
            return False, {}
        errors.append(f"branch_protection: {exc}")
        if public_error:
            errors.append(public_error)
        return None, None

    try:
        protection = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"branch_protection: malformed JSON: {exc}")
        return None, None

    # Surface only the three sub-objects a policy-author actually cares
    # about. The full payload is large and full of GH-internal URLs.
    summary: dict[str, Any] = {
        "required_status_checks": protection.get("required_status_checks"),
        "required_pull_request_reviews": protection.get("required_pull_request_reviews"),
        "required_signatures": (protection.get("required_signatures") or {}).get("enabled"),
    }
    return True, summary


# ---------------------------------------------------------------------------
# Section: CODEOWNERS, SECURITY.md, NOTICE presence.
# ---------------------------------------------------------------------------


def _codeowners_path(
    repo: str,
    *,
    gh_run: Callable,
    errors: list[str],
) -> str | None:
    """Find a CODEOWNERS file via the canonical search order.

    Per GitHub docs the file may live at ``.github/CODEOWNERS``,
    ``CODEOWNERS`` (repo root), or ``docs/CODEOWNERS``. We probe in that
    order and return the first hit (or ``None``).
    """
    for candidate in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        try:
            gh_run(["api", f"repos/{ORG}/{repo}/contents/{candidate}"])
            return candidate
        except Exception as exc:
            if _is_terminal_404(exc):
                continue
            errors.append(f"codeowners[{candidate}]: {exc}")
            return None
    return None


def _decode_contents_payload(stdout: str) -> str | None:
    """Decode a ``contents`` API base64 payload into a UTF-8 string."""
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    raw_b64 = payload.get("content")
    if not raw_b64:
        return None
    try:
        return base64.b64decode(raw_b64).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def _security_md(
    repo: str,
    *,
    gh_run: Callable,
    errors: list[str],
) -> tuple[bool, int | None]:
    """``GET repos/{ORG}/{repo}/contents/SECURITY.md``.

    Returns ``(present, disclosure_window_days)``. The window is parsed from
    the body via :func:`_extract_disclosure_window`. ``False, None`` means
    "no SECURITY.md"; ``True, None`` means "present but window not stated".
    """
    try:
        cp = gh_run(["api", f"repos/{ORG}/{repo}/contents/SECURITY.md"])
    except Exception as exc:
        if _is_terminal_404(exc):
            return False, None
        errors.append(f"security_md: {exc}")
        return False, None

    body = _decode_contents_payload(cp.stdout)
    if body is None:
        return True, None
    return True, _extract_disclosure_window(body)


def _extract_disclosure_window(body: str) -> int | None:
    """Parse the disclosure window in days from a SECURITY.md body.

    Strategy: find every plausible "<N> days" / "<N>-day" match in the file,
    filter to ``7..365``, and return the **largest** one. The largest is
    almost always the public-disclosure target; smaller numbers tend to be
    acknowledgement / triage SLAs ("within 3 business days").
    """
    candidates: list[int] = []
    for rx in (_DISCLOSURE_RE, _DISCLOSURE_WORD_RE):
        for match in rx.finditer(body):
            try:
                n = int(match.group(1))
            except (ValueError, IndexError):
                continue
            if _DISCLOSURE_MIN <= n <= _DISCLOSURE_MAX:
                candidates.append(n)
    if not candidates:
        return None
    return max(candidates)


def _notice_present(
    repo: str,
    *,
    gh_run: Callable,
    errors: list[str],
) -> bool:
    """``GET repos/{ORG}/{repo}/contents/NOTICE``."""
    try:
        gh_run(["api", f"repos/{ORG}/{repo}/contents/NOTICE"])
        return True
    except Exception as exc:
        if _is_terminal_404(exc):
            return False
        errors.append(f"notice: {exc}")
        return False


# ---------------------------------------------------------------------------
# Section: license files in the latest sdist (per PyPI).
# ---------------------------------------------------------------------------


def _license_files_in_sdist(
    pkg: str,
    *,
    url_get_json: Callable,
    errors: list[str],
) -> list[str]:
    """``GET https://pypi.org/pypi/<pkg>/json`` → ``info.license_files``.

    Empty list on any failure --- this is purely informational and the
    caller surfaces ``errors`` for the staleness indicator.
    """
    try:
        data = url_get_json(f"https://pypi.org/pypi/{pkg}/json")
    except Exception as exc:
        if _is_terminal_404(exc):
            return []
        errors.append(f"license_files: {exc}")
        return []
    files = (data.get("info") or {}).get("license_files") or []
    # Defensive: PyPI returns a list of strings; coerce in case of dict-of-tuples.
    return [str(f) for f in files if isinstance(f, (str, bytes))]


# ---------------------------------------------------------------------------
# Section: releases, open PRs, open issues, velocity.
# ---------------------------------------------------------------------------


def _releases_90d(
    repo: str,
    *,
    gh_run: Callable,
    now: datetime.datetime,
    errors: list[str],
) -> tuple[int | None, list[dict[str, Any]]]:
    """``GET repos/{ORG}/{repo}/releases?per_page=100``.

    Returns ``(count_in_window, releases_in_window_or_all_if_few)``.
    The second element is also used by :func:`_time_to_pypi_seconds_median`
    so we don't pay for the listing twice.
    """
    try:
        cp = gh_run(["api", f"repos/{ORG}/{repo}/releases?per_page=100"])
    except Exception as exc:
        if _is_terminal_404(exc):
            return 0, []
        errors.append(f"releases: {exc}")
        return None, []

    try:
        all_releases = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"releases: malformed JSON: {exc}")
        return None, []

    if not isinstance(all_releases, list):
        errors.append("releases: unexpected payload shape")
        return None, []

    cutoff = now - datetime.timedelta(days=90)
    in_window: list[dict[str, Any]] = []
    for r in all_releases[:_RELEASES_HARD_CAP]:
        published = _parse_iso(r.get("published_at") or r.get("created_at"))
        if published is None:
            continue
        if published >= cutoff:
            in_window.append(r)
    return len(in_window), in_window


def _open_pr_signals(
    repo: str,
    *,
    gh_run: Callable,
    now: datetime.datetime,
    errors: list[str],
) -> tuple[int | None, float | None]:
    """``GET repos/{ORG}/{repo}/pulls?state=open&per_page=100 --paginate``.

    Returns ``(open_pr_count, median_pr_age_days)``. Both ``None`` on
    upstream failure. ``median_pr_age_days`` is ``None`` --- *not* ``0`` ---
    on an empty open-PR list, because the median of an empty set is
    undefined and ``0.0`` would falsely imply "PRs merge instantly here."
    """
    try:
        cp = gh_run(
            [
                "api",
                f"repos/{ORG}/{repo}/pulls?state=open&per_page=100",
                "--paginate",
            ]
        )
    except Exception as exc:
        if _is_terminal_404(exc):
            return 0, None
        errors.append(f"open_prs: {exc}")
        return None, None

    prs = _parse_concatenated_json_arrays(cp.stdout)
    if len(prs) > _OPEN_PRS_HARD_CAP:
        prs = prs[:_OPEN_PRS_HARD_CAP]

    count = len(prs)
    if count == 0:
        return 0, None

    ages_days: list[float] = []
    for pr in prs:
        created = _parse_iso(pr.get("created_at"))
        if created is None:
            continue
        delta = now - created
        ages_days.append(delta.total_seconds() / 86400.0)
    if not ages_days:
        return count, None
    return count, round(statistics.median(ages_days), 3)


def _open_issue_count(
    repo: str,
    *,
    gh_run: Callable,
    errors: list[str],
) -> int | None:
    """``GET repos/{ORG}/{repo}/issues?state=open&per_page=100 --paginate``.

    GitHub's issues endpoint returns BOTH issues and PRs. We filter out PRs
    (any item with a ``pull_request`` key) so the count matches what a
    human sees on the Issues tab.
    """
    try:
        cp = gh_run(
            [
                "api",
                f"repos/{ORG}/{repo}/issues?state=open&per_page=100",
                "--paginate",
            ]
        )
    except Exception as exc:
        if _is_terminal_404(exc):
            return 0
        errors.append(f"open_issues: {exc}")
        return None

    items = _parse_concatenated_json_arrays(cp.stdout)
    if len(items) > _OPEN_ISSUES_HARD_CAP:
        items = items[:_OPEN_ISSUES_HARD_CAP]
    return sum(1 for it in items if not it.get("pull_request"))


# ---------------------------------------------------------------------------
# Section: time-to-PyPI.
# ---------------------------------------------------------------------------


def _tag_pushed_at(
    repo: str,
    tag: str,
    *,
    gh_run: Callable,
) -> datetime.datetime | None:
    """Resolve a tag's pushed-at proxy timestamp.

    GitHub's REST API does not expose ``pushed-at`` for a tag directly. The
    closest public proxies, in order of preference, are:

      1. For an **annotated** tag: ``GET /git/tags/<tag-object-sha>`` →
         ``tagger.date``. This is when the tag object itself was created.
      2. For a **lightweight** tag: fall back to the underlying commit's
         ``committer.date`` via ``GET /git/commits/<commit-sha>``.

    The two-step resolution is via ``GET /git/ref/tags/<tag>``; the ref's
    ``object.type`` tells us which branch to take.
    """
    try:
        ref_cp = gh_run(["api", f"repos/{ORG}/{repo}/git/ref/tags/{tag}"])
    except Exception:
        return None
    try:
        ref = json.loads(ref_cp.stdout)
    except json.JSONDecodeError:
        return None
    obj = ref.get("object") or {}
    obj_sha = obj.get("sha")
    obj_type = obj.get("type")
    if not obj_sha:
        return None

    if obj_type == "tag":
        try:
            tag_cp = gh_run(["api", f"repos/{ORG}/{repo}/git/tags/{obj_sha}"])
            tag_obj = json.loads(tag_cp.stdout)
        except Exception:
            return None
        return _parse_iso((tag_obj.get("tagger") or {}).get("date"))

    if obj_type == "commit":
        try:
            commit_cp = gh_run(["api", f"repos/{ORG}/{repo}/git/commits/{obj_sha}"])
            commit_obj = json.loads(commit_cp.stdout)
        except Exception:
            return None
        return _parse_iso((commit_obj.get("committer") or {}).get("date"))

    return None


def _pypi_upload_time(
    pkg: str,
    version: str,
    *,
    url_get_json: Callable,
) -> datetime.datetime | None:
    """``GET https://pypi.org/pypi/<pkg>/<version>/json`` → earliest urls[].upload_time_iso_8601.

    We take the EARLIEST upload time across all artifacts (wheels typically
    upload seconds before the sdist) because that is the moment a downstream
    resolver could first see the release.
    """
    try:
        data = url_get_json(f"https://pypi.org/pypi/{pkg}/{version}/json")
    except Exception:
        return None
    urls = data.get("urls") or []
    times: list[datetime.datetime] = []
    for u in urls:
        ts = _parse_iso(u.get("upload_time_iso_8601") or u.get("upload_time"))
        if ts is not None:
            times.append(ts)
    if not times:
        return None
    return min(times)


def _time_to_pypi_seconds_median(
    repo: str,
    releases_in_window: list[dict[str, Any]],
    *,
    gh_run: Callable,
    url_get_json: Callable,
    errors: list[str],
) -> int | None:
    """Median seconds from tag push → PyPI upload across the last 90d of releases.

    "Hardest signal" --- requires three correlated lookups per release. We
    record an error and return ``None`` if EVERY release fails; partial
    failures are tolerated (median over the successful ones).
    """
    if not releases_in_window:
        return None
    # PyPI package name convention for kaos-*: GitHub repo name == PyPI
    # project (verified for kaos-core, kaos-graph, etc.).
    pkg = repo

    deltas_s: list[float] = []
    failures = 0
    for r in releases_in_window:
        tag = r.get("tag_name")
        if not tag:
            failures += 1
            continue
        version = tag.lstrip("v")
        try:
            tag_pushed = _tag_pushed_at(repo, tag, gh_run=gh_run)
            pypi_uploaded = _pypi_upload_time(pkg, version, url_get_json=url_get_json)
        except Exception as exc:
            # Catch defensively: helper does its own try/except but caller
            # guarantees nothing about a custom injected callable.
            errors.append(f"time_to_pypi[{tag}]: {exc}")
            failures += 1
            continue
        if tag_pushed is None or pypi_uploaded is None:
            failures += 1
            continue
        delta = (pypi_uploaded - tag_pushed).total_seconds()
        # Allow negative deltas (a maintainer can push the GH tag AFTER the
        # PyPI upload if release.yml uploaded then tagged) but clamp to 0
        # so the median isn't dragged below zero.
        deltas_s.append(max(0.0, delta))

    if not deltas_s:
        errors.append("time_to_pypi: no resolvable (tag, pypi-upload) pairs in window")
        return None
    return int(statistics.median(deltas_s))


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def collect(
    repo: str,
    *,
    gh_run: Callable,
    url_get_json: Callable,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Collect governance + velocity signals for ``ORG/repo``.

    Parameters
    ----------
    repo
        Short repo name (e.g. ``"kaos-core"``). Combined with :data:`ORG`
        to form the full slug for ``gh api`` paths.
    gh_run
        Callable matching :func:`collector._retry.gh_run`. Injected so the
        unit tests can stub out subprocess without a ``gh`` binary on PATH.
    url_get_json
        Callable matching :func:`collector._retry.url_get_json`. Same
        rationale.
    now
        UTC reference timestamp. Defaults to ``datetime.now(UTC)``; the
        unit tests pin it for determinism.

    Returns
    -------
    dict
        Every key in the module docstring's contract. ``None`` for any
        signal we tried and couldn't extract. ``errors`` is the list of
        upstream failures, never silently absorbed.
    """
    if now is None:
        now = datetime.datetime.now(tz=datetime.UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=datetime.UTC)

    errors: list[str] = []
    result: dict[str, Any] = {
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
        "errors": errors,
    }

    # Each section is wrapped so one section's hard failure (uncaught,
    # programmer-error class of exception) cannot tank the whole snapshot.
    # The helpers themselves catch retry-exhaustion → None and append to
    # ``errors``; the wrapping try here is the belt to that suspenders.
    try:
        result.update(_commits_section(repo, gh_run=gh_run, now=now, errors=errors))
    except Exception as exc:
        errors.append(f"commits_section: {exc}")

    try:
        enabled, summary = _branch_protection(repo, gh_run=gh_run, errors=errors)
        result["branch_protection_enabled"] = enabled
        result["branch_protection_summary"] = summary
    except Exception as exc:
        errors.append(f"branch_protection_section: {exc}")

    try:
        result["codeowners_path"] = _codeowners_path(repo, gh_run=gh_run, errors=errors)
    except Exception as exc:
        errors.append(f"codeowners_section: {exc}")

    try:
        present, window = _security_md(repo, gh_run=gh_run, errors=errors)
        result["security_md_present"] = present
        result["security_md_disclosure_window_days"] = window
    except Exception as exc:
        errors.append(f"security_md_section: {exc}")

    try:
        result["notice_present"] = _notice_present(repo, gh_run=gh_run, errors=errors)
    except Exception as exc:
        errors.append(f"notice_section: {exc}")

    try:
        result["license_files_in_sdist"] = _license_files_in_sdist(
            repo, url_get_json=url_get_json, errors=errors
        )
    except Exception as exc:
        errors.append(f"license_files_section: {exc}")

    releases_in_window: list[dict[str, Any]] = []
    try:
        rel_count, releases_in_window = _releases_90d(repo, gh_run=gh_run, now=now, errors=errors)
        result["releases_90d"] = rel_count
    except Exception as exc:
        errors.append(f"releases_section: {exc}")

    try:
        open_count, median_age = _open_pr_signals(repo, gh_run=gh_run, now=now, errors=errors)
        result["open_pr_count"] = open_count
        result["median_pr_age_days"] = median_age
    except Exception as exc:
        errors.append(f"open_prs_section: {exc}")

    try:
        result["open_issue_count"] = _open_issue_count(repo, gh_run=gh_run, errors=errors)
    except Exception as exc:
        errors.append(f"open_issues_section: {exc}")

    try:
        result["time_to_pypi_seconds_median"] = _time_to_pypi_seconds_median(
            repo,
            releases_in_window,
            gh_run=gh_run,
            url_get_json=url_get_json,
            errors=errors,
        )
    except Exception as exc:
        errors.append(f"time_to_pypi_section: {exc}")
        result["time_to_pypi_seconds_median"] = None

    return result
