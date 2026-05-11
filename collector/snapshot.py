"""kaos-compliance snapshot orchestrator.

Produces the source-of-truth JSON document that every render and every
compliance ingest reads from.

The snapshot is intentionally flat (one entry per public 273v/kaos-*
repo) so consumers can answer per-package questions without traversing
relationships. Inter-package dependency relationships live in the
per-package CycloneDX SBOM under data/sbom/, not in this snapshot.

Heartbeat policy
----------------

Every run emits a ``heartbeat`` block alongside the modules array. The
dashboard renders the page red-flagged when the heartbeat is more than
26 hours old (allows for one missed cron + slack), regardless of what
the per-module signals report. This closes the "freshness lying"
failure mode where a silently-broken cron leaves the page serving
stale green pills indefinitely.

JSON shape
----------

::

    {
      "schema_version": "1.0",
      "generated_at": "2026-05-11T13:00:00Z",
      "generator": {"name": "kaos-compliance", "version": "0.0.1"},
      "heartbeat": {
        "last_full_sweep_at": "2026-05-11T00:00:00Z",
        "last_light_sweep_at": "2026-05-11T13:00:00Z",
        "last_security_sweep_at": "2026-05-11T12:00:00Z",
        "stale_threshold_hours": 26
      },
      "modules": [
        {
          "name": "kaos-core",
          "identity": {...},
          "ci": {...},
          "security": {...},
          "open_prs": {...},
          "freshness": {...}
        },
        ...
      ]
    }

The deeper supply-chain, governance, and PEP 740 sections are added by
``P2`` / ``P3`` modules and live under the same per-module dict.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from collector import __version__ as COLLECTOR_VERSION
from collector import governance, supply_chain
from collector._retry import gh_run, url_get_json

ORG = "273v"
SCHEMA_VERSION = "1.0"
STALE_THRESHOLD_HOURS = 26


@dataclass(frozen=True, slots=True)
class IdentitySection:
    """What is this package today?"""

    pypi_version: str | None = None
    pypi_url: str | None = None
    main_head_sha: str | None = None
    latest_tag: str | None = None
    latest_tag_sha: str | None = None
    tag_at_head: bool | None = None
    commits_past_tag: int | None = None
    repo_visibility: str | None = None  # "public" | "private"
    last_commit_at: str | None = None


@dataclass(frozen=True, slots=True)
class CISection:
    """Continuous integration posture for the latest main commit."""

    workflow_conclusion: str | None = None  # success | failure | cancelled | None
    workflow_run_id: int | None = None
    workflow_run_url: str | None = None
    head_sha: str | None = None
    run_completed_at: str | None = None
    matrix: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SecuritySection:
    """Aggregate of every job inside the Security workflow."""

    workflow_conclusion: str | None = None
    workflow_run_id: int | None = None
    workflow_run_url: str | None = None
    jobs: list[dict[str, Any]] = field(default_factory=list)
    run_completed_at: str | None = None


@dataclass(frozen=True, slots=True)
class OpenPRsSection:
    """Open PRs against main right now."""

    count: int | None = None  # None if lookup failed after retries
    titles: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class FreshnessSection:
    """How stale is everything?"""

    days_since_last_commit: int | None = None
    days_since_last_release: int | None = None
    days_since_last_security_scan: int | None = None


@dataclass(frozen=True, slots=True)
class ModuleSnapshot:
    """One row in the dashboard's per-package grid."""

    name: str
    identity: IdentitySection
    ci: CISection
    security: SecuritySection
    open_prs: OpenPRsSection
    freshness: FreshnessSection
    # The supply-chain and governance sections are returned as raw
    # dicts by their dedicated collector modules; we keep them dicts
    # (rather than refactoring those modules to share dataclasses)
    # because the dashboard schema is the only place that needs the
    # exact shape, and adding adapter dataclasses adds friction
    # without buying anything.
    supply_chain: dict[str, Any] = field(default_factory=dict)
    governance: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_public_kaos_repos() -> list[str]:
    """List every public ``273v/kaos-*`` repository name."""
    raw = gh_run(
        [
            "repo",
            "list",
            ORG,
            "--limit",
            "100",
            "--visibility",
            "public",
            "--json",
            "name",
        ]
    ).stdout
    names = [r["name"] for r in json.loads(raw)]
    return sorted(n for n in names if n.startswith("kaos-"))


# ---------------------------------------------------------------------------
# Per-section collectors
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """RFC 3339 UTC timestamp with trailing Z (drops the +00:00 offset)."""
    return (
        datetime.datetime.now(tz=datetime.UTC)
        .replace(microsecond=0, tzinfo=None)
        .isoformat()
        + "Z"
    )


def _parse_iso(ts: str | None) -> datetime.datetime | None:
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(ts: str | None) -> int | None:
    dt = _parse_iso(ts)
    if dt is None:
        return None
    return (datetime.datetime.now(tz=datetime.UTC) - dt).days


def _latest_run(repo: str, workflow: str) -> dict[str, Any] | None:
    """Return the most recent run of ``workflow`` for ``repo``, or None."""
    try:
        raw = gh_run(
            [
                "run",
                "list",
                "--repo",
                f"{ORG}/{repo}",
                "--branch",
                "main",
                "--workflow",
                workflow,
                "--limit",
                "1",
                "--json",
                "databaseId,headSha,status,conclusion,createdAt,updatedAt,url",
            ]
        ).stdout
    except Exception:  # noqa: BLE001 — retry exhaustion is intentional fall-through
        return None
    runs = json.loads(raw or "[]")
    return runs[0] if runs else None


def _identity(repo: str) -> IdentitySection:
    """Branch HEAD + latest tag + tag-vs-head + repo visibility."""
    main_sha: str | None = None
    last_commit_at: str | None = None
    visibility: str | None = None

    try:
        branch_raw = gh_run(
            ["api", f"repos/{ORG}/{repo}/branches/main"],
        ).stdout
        branch = json.loads(branch_raw)
        main_sha = branch.get("commit", {}).get("sha")
        last_commit_at = branch.get("commit", {}).get("commit", {}).get("author", {}).get("date")
    except Exception:  # noqa: BLE001
        pass

    try:
        repo_raw = gh_run(["api", f"repos/{ORG}/{repo}"]).stdout
        repo_meta = json.loads(repo_raw)
        visibility = "private" if repo_meta.get("private") else "public"
    except Exception:  # noqa: BLE001
        pass

    latest_tag: str | None = None
    latest_tag_sha: str | None = None
    try:
        tags_raw = gh_run(
            ["api", f"repos/{ORG}/{repo}/tags?per_page=20"],
        ).stdout
        tags = json.loads(tags_raw)
        v_tags = [t for t in tags if t.get("name", "").startswith("v")]
        if v_tags:
            latest_tag = v_tags[0]["name"]
            latest_tag_sha = v_tags[0]["commit"]["sha"]
    except Exception:  # noqa: BLE001
        pass

    tag_at_head: bool | None = (
        (main_sha == latest_tag_sha) if (main_sha and latest_tag_sha) else None
    )

    return IdentitySection(
        pypi_version=None,  # filled by P2 (collector/pypi.py)
        pypi_url=None,
        main_head_sha=main_sha,
        latest_tag=latest_tag,
        latest_tag_sha=latest_tag_sha,
        tag_at_head=tag_at_head,
        commits_past_tag=None,  # computed by P3
        repo_visibility=visibility,
        last_commit_at=last_commit_at,
    )


def _ci_section(repo: str) -> CISection:
    """Latest CI workflow run on main + matrix breakdown."""
    run = _latest_run(repo, "CI")
    if not run:
        return CISection()

    matrix: list[dict[str, Any]] = []
    try:
        jobs_raw = gh_run(
            ["api", f"repos/{ORG}/{repo}/actions/runs/{run['databaseId']}/jobs?per_page=100"],
        ).stdout
        jobs = json.loads(jobs_raw).get("jobs", [])
        for j in jobs:
            matrix.append(
                {
                    "name": j.get("name"),
                    "conclusion": j.get("conclusion"),
                    "status": j.get("status"),
                    "started_at": j.get("started_at"),
                    "completed_at": j.get("completed_at"),
                    "duration_seconds": _duration_seconds(
                        j.get("started_at"), j.get("completed_at")
                    ),
                }
            )
    except Exception:  # noqa: BLE001
        pass

    return CISection(
        workflow_conclusion=run.get("conclusion"),
        workflow_run_id=run.get("databaseId"),
        workflow_run_url=run.get("url"),
        head_sha=run.get("headSha"),
        run_completed_at=run.get("updatedAt"),
        matrix=matrix,
    )


def _security_section(repo: str) -> SecuritySection:
    """Latest Security workflow + per-job breakdown."""
    run = _latest_run(repo, "Security")
    if not run:
        return SecuritySection()

    jobs: list[dict[str, Any]] = []
    try:
        jobs_raw = gh_run(
            ["api", f"repos/{ORG}/{repo}/actions/runs/{run['databaseId']}/jobs?per_page=100"],
        ).stdout
        for j in json.loads(jobs_raw).get("jobs", []):
            jobs.append(
                {
                    "name": j.get("name"),
                    "conclusion": j.get("conclusion"),
                    "status": j.get("status"),
                    "completed_at": j.get("completed_at"),
                }
            )
    except Exception:  # noqa: BLE001
        pass

    return SecuritySection(
        workflow_conclusion=run.get("conclusion"),
        workflow_run_id=run.get("databaseId"),
        workflow_run_url=run.get("url"),
        jobs=jobs,
        run_completed_at=run.get("updatedAt"),
    )


def _duration_seconds(started_at: str | None, completed_at: str | None) -> int | None:
    start = _parse_iso(started_at)
    if start is None:
        return None
    end = _parse_iso(completed_at) or datetime.datetime.now(tz=datetime.UTC)
    return max(0, int((end - start).total_seconds()))


def _open_prs(repo: str) -> OpenPRsSection:
    try:
        raw = gh_run(
            [
                "pr",
                "list",
                "--repo",
                f"{ORG}/{repo}",
                "--state",
                "open",
                "--json",
                "number,title",
            ]
        ).stdout
    except Exception:  # noqa: BLE001
        return OpenPRsSection(count=None, titles=[])
    try:
        items = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return OpenPRsSection(count=None, titles=[])
    titles = [f"#{p['number']} {p['title']}" for p in items]
    return OpenPRsSection(count=len(items), titles=titles)


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


_SIBLING_ROOT = Path("/home/mjbommar/projects/273v")


def collect_module(repo: str) -> ModuleSnapshot:
    """Gather every signal for one repo into a single snapshot row.

    Each section is gathered in its own try/except so a failure in one
    section (e.g., PyPI rate-limit on the supply-chain path) leaves
    every other section's data intact. The errors list carries
    per-section failure messages so the dashboard's render can downgrade
    just the affected card instead of zeroing out the whole row.
    """
    errors: list[str] = []

    try:
        ident = _identity(repo)
    except Exception as exc:  # noqa: BLE001
        ident = IdentitySection()
        errors.append(f"identity: {exc}")
    try:
        ci = _ci_section(repo)
    except Exception as exc:  # noqa: BLE001
        ci = CISection()
        errors.append(f"ci: {exc}")
    try:
        sec = _security_section(repo)
    except Exception as exc:  # noqa: BLE001
        sec = SecuritySection()
        errors.append(f"security: {exc}")
    try:
        prs = _open_prs(repo)
    except Exception as exc:  # noqa: BLE001
        prs = OpenPRsSection(count=None, titles=[])
        errors.append(f"open_prs: {exc}")

    # Supply-chain depth (collector/supply_chain.py): PyPI metadata,
    # PEP 740 attestations, license breakdown, SBOM emission. Sibling
    # clone is read from the local filesystem so we can parse uv.lock
    # / Cargo.lock without re-cloning every sweep.
    sibling_dir = _SIBLING_ROOT / repo
    try:
        sc = supply_chain.collect(
            repo,
            sibling_dir if sibling_dir.is_dir() else None,
            gh_run=gh_run,
            url_get_json=url_get_json,
        )
    except Exception as exc:  # noqa: BLE001
        sc = {"errors": [f"supply_chain: {exc}"]}
        errors.append(f"supply_chain: {exc}")

    # Governance + velocity (collector/governance.py): DCO sign-off
    # rate, conventional-commits rate, branch protection, release
    # cadence, time-to-PyPI.
    try:
        gov = governance.collect(
            repo,
            gh_run=gh_run,
            url_get_json=url_get_json,
        )
    except Exception as exc:  # noqa: BLE001
        gov = {"errors": [f"governance: {exc}"]}
        errors.append(f"governance: {exc}")

    fresh = FreshnessSection(
        days_since_last_commit=_days_since(ident.last_commit_at),
        days_since_last_release=_days_since(sc.get("pypi_release_iso")),
        days_since_last_security_scan=_days_since(sec.run_completed_at),
    )

    return ModuleSnapshot(
        name=repo,
        identity=ident,
        ci=ci,
        security=sec,
        open_prs=prs,
        freshness=fresh,
        supply_chain=sc,
        governance=gov,
        errors=errors,
    )


def build_snapshot(*, repos: list[str] | None = None) -> dict[str, Any]:
    """Build the org-wide JSON snapshot."""
    target_repos = repos or discover_public_kaos_repos()
    modules = [collect_module(r) for r in target_repos]
    now = _now_iso()

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "generator": {"name": "kaos-compliance", "version": COLLECTOR_VERSION},
        "heartbeat": {
            "last_full_sweep_at": now,
            "last_light_sweep_at": now,
            "last_security_sweep_at": now,
            "stale_threshold_hours": STALE_THRESHOLD_HOURS,
        },
        "modules": [asdict(m) for m in modules],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="collector.snapshot",
        description="Build the kaos-compliance JSON snapshot.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="data/snapshots/latest.json",
        help="Where to write the JSON (default: data/snapshots/latest.json)",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        help="Restrict to one or more repos. Repeatable.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output (indent=2).",
    )
    args = parser.parse_args(argv)

    snapshot = build_snapshot(repos=args.module)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    out_path.write_text(json.dumps(snapshot, indent=indent) + "\n", encoding="utf-8")

    print(
        f"snapshot written → {out_path} | "
        f"{len(snapshot['modules'])} modules | "
        f"{snapshot['generated_at']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
