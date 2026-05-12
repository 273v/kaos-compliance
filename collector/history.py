"""90-day rolling history store for the kaos-compliance dashboard.

The dashboard's primary surface is one snapshot — the latest. P7 adds
a lightweight historical store so the dashboard can show trend lines
(sparklines) for the handful of binary per-package signals that
matter at a glance: build, tests, security, attestation, branch
protection, and commits_90d.

Storage layout
--------------

::

    _site/api/v1/history/YYYY-MM-DD.json     # one file per UTC day
    _site/api/v1/history.json                # rolling 90-day summary

Each ``YYYY-MM-DD.json`` carries the compact per-package summary for
that day (one snapshot per UTC day; last write wins). The rolling
``history.json`` is rebuilt every sweep from the last 90 of those
files so it stays <100KB and the dashboard can render trend lines
without any client-side state.

Key design properties
---------------------

* **Idempotent.** Two sweeps in the same UTC day overwrite the same
  file. ``rebuild_index`` then sees one row per day, not duplicate
  rows.
* **No faking.** The very first sweep has exactly one day of data;
  the renderer surfaces a single-dot sparkline + an "accumulating
  history" label. We never extrapolate or backfill.
* **Snapshot-rooted.** Every per-day file is derived from the
  ``OrgSnapshot`` shape in :mod:`collector.snapshot`. If the
  collector schema changes, ``daily_summary_from_snapshot`` is the
  only place to update.

The schema is intentionally minimal — wider per-day captures
(LoC, license breakdown, dep counts) wait for P8.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

HISTORY_DAYS = 90
HISTORY_SCHEMA_VERSION = "1.0"

# Signals we track in history. Booleans capture "did the signal flip
# green on this day" — that's the trend line a buyer asks for. The
# count column (``commits_90d``) is the only non-binary signal kept
# in the rolling index; richer counters wait for P8.
TRACKED_BOOL_SIGNALS = (
    "build_pass",
    "tests_pass",
    "security_pass",
    "attestation_present",
    "branch_protection_enabled",
)
TRACKED_INT_SIGNALS = ("commits_90d",)


def _today_utc() -> str:
    """UTC date stamp ``YYYY-MM-DD``."""
    return datetime.datetime.now(tz=datetime.UTC).date().isoformat()


def _module_summary(module: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full module dict to the per-day summary the dashboard reads.

    Returns booleans / ints only — no nested objects, no URLs. The
    snapshot.json is the canonical source for everything else;
    history is for trends, not detail.
    """
    ci = module.get("ci") or {}
    sec = module.get("security") or {}
    att = (module.get("supply_chain") or {}).get("attestations") or {}
    gov = module.get("governance") or {}

    # "attestation present and every artifact verified" — same rule
    # the renderer uses for the green-signing pill.
    total = att.get("total_count") or 0
    verified = att.get("verified_count") or 0
    attestation_present = bool(att.get("pep740_present") and total > 0 and verified == total)

    return {
        "name": module.get("name"),
        "build_pass": ci.get("workflow_conclusion") == "success",
        "tests_pass": ci.get("workflow_conclusion") == "success",
        "security_pass": sec.get("workflow_conclusion") == "success",
        "attestation_present": attestation_present,
        "branch_protection_enabled": gov.get("branch_protection_enabled"),
        "commits_90d": gov.get("commits_90d"),
    }


def daily_summary_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build the per-day summary file body from a full snapshot dict.

    The returned shape:

    ::

        {
          "schema_version": "1.0",
          "date": "2026-05-11",
          "generated_at": "2026-05-11T13:00:00Z",
          "modules": [
            {"name": "kaos-core", "build_pass": true, ...},
            ...
          ]
        }
    """
    generated_at = snapshot.get("generated_at")
    date = (generated_at[:10] if isinstance(generated_at, str) else None) or _today_utc()
    modules = [_module_summary(m) for m in (snapshot.get("modules") or []) if m.get("name")]
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "date": date,
        "generated_at": generated_at,
        "modules": modules,
    }


def write_daily_summary(
    snapshot: dict[str, Any], history_dir: Path, *, today: str | None = None
) -> Path:
    """Write today's per-day summary file. Idempotent (overwrites).

    The filename's date defaults to the snapshot's ``generated_at``
    day; passing ``today`` is the test-time hook for date-stamp
    forcing.
    """
    history_dir.mkdir(parents=True, exist_ok=True)
    payload = daily_summary_from_snapshot(snapshot)
    stamp = today or payload["date"]
    out = history_dir / f"{stamp}.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def _read_daily_files(history_dir: Path) -> list[dict[str, Any]]:
    """Read every YYYY-MM-DD.json under ``history_dir``, sorted by date asc.

    Files that fail to parse are skipped (with no fanfare — the next
    sweep will overwrite them). We don't raise from a render path
    over a single bad file; the buyer's surface is the rolling index,
    not the per-day raw.
    """
    if not history_dir.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for f in sorted(history_dir.glob("*.json")):
        try:
            obj = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        # Belt + braces: the file's name is the canonical date stamp.
        # If the JSON's ``date`` disagrees with the filename, trust
        # the filename (the JSON was written there, presumably by a
        # past version of the schema we'd rather not honor blindly).
        obj["date"] = f.stem
        rows.append(obj)
    return rows


def rebuild_index(history_dir: Path, *, days: int = HISTORY_DAYS) -> dict[str, Any]:
    """Build the rolling N-day summary from the per-day files.

    Returns the dict to be written to ``history.json``. Schema:

    ::

        {
          "schema_version": "1.0",
          "window_days": 90,
          "first_date": "2026-02-10",
          "last_date":  "2026-05-11",
          "dates": ["2026-02-10", ...],   # chronological
          "packages": {
             "kaos-core": {
               "build_pass":        [true, true, false, ...],   # len == |dates|
               "tests_pass":        [...],
               "security_pass":     [...],
               "attestation_present":[...],
               "branch_protection_enabled":[...],
               "commits_90d":       [12, 13, 14, ...]
             },
             ...
          }
        }

    Each per-signal array is aligned to ``dates`` — index ``i`` of
    every array corresponds to ``dates[i]``. ``null`` is preserved
    for days we genuinely don't have a signal for, which the renderer
    treats as gray when drawing the sparkline.
    """
    rows = _read_daily_files(history_dir)
    if len(rows) > days:
        rows = rows[-days:]

    dates = [r["date"] for r in rows]
    packages: dict[str, dict[str, list[Any]]] = {}

    # First pass: collect every package name that appeared on any day
    # within the window. We pre-allocate per-package columns with the
    # correct length so a package that didn't exist yet on day i gets
    # a ``null`` at that position rather than a shorter array.
    names: set[str] = set()
    for r in rows:
        for m in r.get("modules") or []:
            if m.get("name"):
                names.add(m["name"])

    for name in sorted(names):
        packages[name] = {
            sig: [None] * len(rows) for sig in (*TRACKED_BOOL_SIGNALS, *TRACKED_INT_SIGNALS)
        }

    # Second pass: project each day's modules into the per-package arrays.
    for i, r in enumerate(rows):
        for m in r.get("modules") or []:
            name = m.get("name")
            if not name or name not in packages:
                continue
            for sig in (*TRACKED_BOOL_SIGNALS, *TRACKED_INT_SIGNALS):
                if sig in m:
                    packages[name][sig][i] = m[sig]

    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "window_days": days,
        "first_date": dates[0] if dates else None,
        "last_date": dates[-1] if dates else None,
        "dates": dates,
        "packages": packages,
    }


def write_index(history_dir: Path, *, index_path: Path, days: int = HISTORY_DAYS) -> Path:
    """Rebuild + write the rolling-summary index file."""
    obj = rebuild_index(history_dir, days=days)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return index_path


def append_and_index(
    snapshot: dict[str, Any],
    *,
    history_dir: Path,
    index_path: Path,
    today: str | None = None,
    days: int = HISTORY_DAYS,
) -> tuple[Path, Path]:
    """Append today's summary + rebuild the rolling index.

    This is the one-shot the sweep workflow calls. Returns
    ``(per_day_path, index_path)``.
    """
    per_day = write_daily_summary(snapshot, history_dir, today=today)
    idx = write_index(history_dir, index_path=index_path, days=days)
    return per_day, idx


# ---------------------------------------------------------------------------
# Baseline diff
# ---------------------------------------------------------------------------


def previous_sweep_date(index: dict[str, Any]) -> str | None:
    """Return the second-to-last date in the rolling index, or None.

    The "previous sweep" is the dashboard's baseline — the most
    recent day before today. None when only one day of history
    exists; the renderer shows "no prior sweep yet" in that case.
    """
    dates = index.get("dates") or []
    if len(dates) < 2:
        return None
    return dates[-2]


def diff_packages(
    index: dict[str, Any],
    *,
    from_date: str | None = None,
    to_date: str | None = None,
) -> dict[str, Any]:
    """Per-package signal diff between two dates in the rolling index.

    Defaults: ``from_date`` = previous_sweep_date, ``to_date`` = last_date.
    Returns ``{"from": ..., "to": ..., "packages": {name: {signal: {from, to, delta}}}}``
    where ``delta`` is one of ``"better"``, ``"worse"``, ``"same"``,
    ``"unknown"``.
    """
    dates = index.get("dates") or []
    if not dates:
        return {"from": None, "to": None, "packages": {}}
    last = to_date or dates[-1]
    prev = from_date or previous_sweep_date(index)
    if prev is None:
        return {"from": None, "to": last, "packages": {}}
    try:
        i_from = dates.index(prev)
        i_to = dates.index(last)
    except ValueError:
        return {"from": prev, "to": last, "packages": {}}

    out: dict[str, dict[str, dict[str, Any]]] = {}
    for name, sigs in (index.get("packages") or {}).items():
        per_signal: dict[str, dict[str, Any]] = {}
        for sig, arr in sigs.items():
            if i_from >= len(arr) or i_to >= len(arr):
                continue
            old = arr[i_from]
            new = arr[i_to]
            per_signal[sig] = {
                "from": old,
                "to": new,
                "delta": _classify_delta(sig, old, new),
            }
        # Only surface the package if at least one signal changed.
        if any(v["delta"] in ("better", "worse") for v in per_signal.values()):
            out[name] = per_signal
    return {"from": prev, "to": last, "packages": out}


def _classify_delta(signal: str, old: Any, new: Any) -> str:
    """Return one of better/worse/same/unknown for a per-signal pair.

    Boolean signals: True>False (better/worse). None on either side
    → unknown (we don't pretend to know the direction without data).
    Int signals: numeric comparison; None either side → unknown.
    """
    if old is None or new is None:
        # Treat first-ever-known as a "better" if it lands on True/positive,
        # but that requires the OTHER side to be known. With one side
        # missing the honest answer is unknown.
        if old == new:
            return "same"
        return "unknown"
    if signal in TRACKED_BOOL_SIGNALS:
        if old == new:
            return "same"
        return "better" if (bool(new) and not bool(old)) else "worse"
    # Int signal — commits_90d. More commits ≠ "better" universally,
    # but for a buyer "the project is more active" is the trend they
    # want flagged. Equal stays same; otherwise direction.
    if isinstance(old, (int, float)) and isinstance(new, (int, float)):
        if new == old:
            return "same"
        return "better" if new > old else "worse"
    return "unknown"
