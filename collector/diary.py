"""LLM-generated daily diary collector for the kaos-compliance dashboard.

This module aggregates the last 24 hours of git activity across every
local clone of the public ``273v/kaos-*`` repos and asks an LLM to
produce a structured compliance-flavored summary. The summary is
persisted as a per-UTC-day Markdown file under ``data/diary/`` so the
dashboard can surface a rolling history.

Public surface is a single function::

    collect(repo_paths: dict[str, pathlib.Path], *,
            anthropic_api_key=None,
            model="claude-sonnet-4-6",
            cutoff_hours=24,
            max_diff_chars=80_000,
            data_root=pathlib.Path("data"),
            now=None) -> dict[str, Any]

Design constraints (NON-NEGOTIABLE):

  * Honest gaps. If no LLM client is importable, or no API key is
    available, we set ``skipped=True`` with a structured reason and
    return without writing. We never raise on a missing key — the
    full sweep cron must keep running even on machines without LLM
    credentials wired.
  * Provider isolation. The model call is wrapped in defensive
    try/except so a transport failure surfaces in ``errors`` rather
    than tanking the whole sweep.
  * Cost-bounded prompt. Each repo's diff-stat blob is truncated to
    ``max_diff_chars`` so a single noisy repo cannot inflate the
    prompt to the point of bankrupting the model account.
  * No marketing copy. The system prompt instructs the model to write
    in the compliance/auditor register documented in ``METHODOLOGY.md``
    — no emoji, no exclamations, no superlatives.

Stdlib only at import time. ``kaos_llm_client`` and ``anthropic`` are
both detected at call time via ``importlib`` so this module can be
imported anywhere even when neither SDK is installed.
"""

from __future__ import annotations

import datetime
import importlib
import json
import os
import pathlib
import re
import subprocess
from typing import Any

__all__ = ["collect", "DEFAULT_MODEL"]

DEFAULT_MODEL = "claude-sonnet-4-6"

# Cost-bound on the prompt regardless of how many repos report changes.
# The full per-repo aggregate is concatenated with separators; this is
# the ceiling per repo, not for the prompt as a whole.
_DEFAULT_MAX_DIFF_CHARS = 80_000

# Rough per-million-token blended prices for Anthropic Sonnet-class
# models. Used only for the footer of the Markdown artifact ("Prompt
# cost: $..."). If we cannot retrieve actual token usage from the SDK
# we leave the cost blank rather than invent a number.
_USD_PER_M_INPUT = 3.0
_USD_PER_M_OUTPUT = 15.0

# The model is told to return EXACTLY this shape.
_EXPECTED_KEYS = ("narrative", "notable_items", "end_user_changes", "risk_callouts")

_SYSTEM_PROMPT = """\
You are summarizing the last 24 hours of code changes across the KAOS \
open-source ecosystem (the 273v/kaos-* family of Python and Rust \
packages). Your reader is a compliance and information-security \
auditor, not a developer.

Surface, in order of priority:
  1. License changes (additions, removals, file rewrites of LICENSE or \
     NOTICE).
  2. Security regressions: deleted tests, removed sandboxing, weakened \
     CSP or transport flags, suspected secret-looking strings, \
     force-push markers, history rewrites.
  3. Risk callouts: any dependency change that brings in a new \
     transitive license family, any change to a `release.yml`, \
     `publish.yml`, or signing workflow.
  4. End-user-facing improvements: API additions, bug fixes that a \
     downstream consumer would notice, performance work that ships in \
     a release.

Write in the register of a compliance methodology document: precise, \
neutral, no marketing, no emoji, no exclamations, no superlatives. \
Reference repos by their short name (e.g. `kaos-core`). \
Lists may be empty if nothing in the input warrants the bullet; never \
invent items the input does not support.

Reply with a single JSON object containing exactly four keys: \
`narrative` (string, 3-5 sentences of plain prose), `notable_items` \
(array of 0-12 short strings), `end_user_changes` (array of 0-12 short \
strings), `risk_callouts` (array of 0-6 short strings). No prose \
before or after the JSON, no Markdown code fences.
"""


# ---------------------------------------------------------------------------
# Helpers — time + repr
# ---------------------------------------------------------------------------


def _iso_z(dt: datetime.datetime) -> str:
    """Format ``dt`` as an RFC 3339 UTC timestamp with trailing ``Z``."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    else:
        dt = dt.astimezone(datetime.UTC)
    return dt.replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def _resolve_now(now: datetime.datetime | None) -> datetime.datetime:
    """Normalise ``now`` to a UTC-aware ``datetime``."""
    if now is None:
        return datetime.datetime.now(tz=datetime.UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=datetime.UTC)
    return now.astimezone(datetime.UTC)


# ---------------------------------------------------------------------------
# Git aggregation
# ---------------------------------------------------------------------------


def _run_git(args: list[str], *, cwd: pathlib.Path, timeout: float = 30.0) -> str:
    """Run ``git`` with the given args under ``cwd``. Returns stdout or "".

    We deliberately catch every subprocess error and degrade to an
    empty string: a single broken clone (missing .git, shallow, locked
    index) must not tank the whole diary.
    """
    try:
        cp = subprocess.run(  # noqa: S603 — args are constructed locally
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if cp.returncode != 0:
        return ""
    return cp.stdout or ""


def _parse_commit_lines(raw: str) -> list[dict[str, str]]:
    """Parse the ``%H|%an|%aI|%s``-formatted ``git log`` output."""
    commits: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        sha, author, when, subject = parts
        commits.append(
            {"sha": sha, "author": author, "when": when, "subject": subject},
        )
    return commits


def _count_file_changes(stat_blob: str) -> int:
    """Count file-change rows in a ``git log --stat`` blob.

    ``git --stat`` emits one line per file followed by a summary line
    like ``2 files changed, 9 insertions(+), 3 deletions(-)``. We count
    via the summary lines so we don't double-count rename arrows.
    """
    total = 0
    for m in re.finditer(r"^\s*(\d+)\s+files? changed", stat_blob, re.MULTILINE):
        try:
            total += int(m.group(1))
        except ValueError:
            continue
    return total


def _truncate(blob: str, limit: int) -> str:
    """Return ``blob`` truncated to ``limit`` chars with a marker tail.

    The marker is human-readable and machine-greppable so the model can
    explicitly acknowledge truncation in its risk callouts if it wants.
    """
    if len(blob) <= limit:
        return blob
    remainder = len(blob) - limit
    return blob[:limit] + f"\n... [truncated {remainder} more bytes]\n"


def _collect_repo_activity(
    repo: str,
    path: pathlib.Path,
    *,
    cutoff_iso: str,
    max_diff_chars: int,
) -> dict[str, Any]:
    """Gather the 24-hour summary for one repo clone.

    Returns a dict with ``commits`` (list), ``stat`` (truncated string),
    ``file_change_count`` (int), and ``error`` (str | None). Repos that
    have no ``.git`` or are unreadable yield zero commits and a recorded
    error; they do NOT raise.
    """
    if not path.is_dir() or not (path / ".git").exists():
        return {
            "commits": [],
            "stat": "",
            "file_change_count": 0,
            "error": f"{repo}: not a git clone at {path}",
        }

    log_raw = _run_git(
        [
            "-C",
            str(path),
            "log",
            f"--since={cutoff_iso}",
            "--pretty=format:%H|%an|%aI|%s",
            "--no-merges",
        ],
        cwd=path,
    )
    stat_raw = _run_git(
        [
            "-C",
            str(path),
            "log",
            f"--since={cutoff_iso}",
            "--stat",
            "--pretty=format:COMMIT %H",
            "--no-merges",
        ],
        cwd=path,
    )

    commits = _parse_commit_lines(log_raw)
    file_change_count = _count_file_changes(stat_raw)
    truncated_stat = _truncate(stat_raw, max_diff_chars)

    return {
        "commits": commits,
        "stat": truncated_stat,
        "file_change_count": file_change_count,
        "error": None,
    }


def _build_user_prompt(per_repo: dict[str, dict[str, Any]]) -> str:
    """Compose the LLM user message from the per-repo aggregation.

    The shape is intentionally flat and labeled so the model has no
    ambiguity about which lines belong to which repo. A repo with zero
    commits is omitted (the model is told only about repos that moved).
    """
    chunks: list[str] = [
        "Aggregated 24h git activity across the KAOS open-source ecosystem.",
        "Each repo block lists its commits (one per line: SHA | author | "
        "when | subject) followed by its file-change stats.",
        "",
    ]
    for repo, data in sorted(per_repo.items()):
        if not data["commits"]:
            continue
        chunks.append(f"=== {repo} ===")
        chunks.append(f"Commits ({len(data['commits'])}):")
        for c in data["commits"]:
            chunks.append(f"  {c['sha'][:10]} | {c['author']} | {c['when']} | {c['subject']}")
        if data["stat"]:
            chunks.append("File-change stats:")
            chunks.append(data["stat"])
        chunks.append("")
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# LLM transport (provider isolation)
# ---------------------------------------------------------------------------


def _load_llm_client():  # noqa: ANN202 — opaque adapter object
    """Detect which LLM SDK is importable. Returns one of:

    * ``("kaos", module)`` — kaos_llm_client is available.
    * ``("anthropic", module)`` — anthropic SDK is available.
    * ``(None, None)`` — neither is importable.

    ``importlib.import_module`` is used (instead of top-level import) so
    the unit tests can inject a fake module via ``sys.modules`` without
    a real install on PATH.
    """
    try:
        mod = importlib.import_module("kaos_llm_client")
        return "kaos", mod
    except ImportError:
        pass
    try:
        mod = importlib.import_module("anthropic")
        return "anthropic", mod
    except ImportError:
        return None, None


def _call_kaos_llm_client(
    mod: Any,
    *,
    api_key: str,
    model: str,
    system: str,
    user: str,
) -> dict[str, Any]:
    """Invoke the org's own multi-provider client.

    The kaos-llm-client API contract for this call is::

        client = LLMClient(provider="anthropic", api_key=api_key)
        response = client.chat(model=model, messages=[...])
        text = response.text
        usage = {"input_tokens": int, "output_tokens": int}  # if available

    Defensive extraction: the response object may expose ``.text``, a
    ``.content`` blob, or just ``str(response)``. Token usage may live
    on ``.usage`` or be absent entirely.
    """
    client = mod.LLMClient(provider="anthropic", api_key=api_key)
    response = client.chat(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    text = _extract_response_text(response)
    usage = _extract_usage(response)
    return {"text": text, "usage": usage}


def _call_anthropic(
    mod: Any,
    *,
    api_key: str,
    model: str,
    system: str,
    user: str,
) -> dict[str, Any]:
    """Invoke the anthropic SDK directly.

    The SDK's ``messages.create`` returns an object whose ``content``
    is a list of typed blocks; we pull the first text block.
    """
    client = mod.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = _extract_response_text(response)
    usage = _extract_usage(response)
    return {"text": text, "usage": usage}


def _extract_response_text(response: Any) -> str:
    """Defensively pull text out of an LLM response object."""
    text = getattr(response, "text", None)
    if isinstance(text, str) and text:
        return text
    content = getattr(response, "content", None)
    if isinstance(content, str) and content:
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            # anthropic SDK: TextBlock has .text; dicts have ["text"].
            block_text = getattr(block, "text", None)
            if isinstance(block_text, str):
                parts.append(block_text)
                continue
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        if parts:
            return "".join(parts)
    return str(response) if response is not None else ""


def _extract_usage(response: Any) -> dict[str, int]:
    """Pull ``{input_tokens, output_tokens}`` out of a response, if present."""
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return {}
    out: dict[str, int] = {}
    for src_key, dst_key in (
        ("input_tokens", "input_tokens"),
        ("prompt_tokens", "input_tokens"),
        ("output_tokens", "output_tokens"),
        ("completion_tokens", "output_tokens"),
    ):
        val = getattr(usage, src_key, None)
        if val is None and isinstance(usage, dict):
            val = usage.get(src_key)
        if isinstance(val, int):
            out[dst_key] = val
    return out


def _estimate_cost_usd(usage: dict[str, int]) -> float | None:
    """Rough USD cost of the call given token usage. ``None`` if no usage."""
    if not usage:
        return None
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    if not inp and not out:
        return None
    cost = (inp / 1_000_000) * _USD_PER_M_INPUT + (out / 1_000_000) * _USD_PER_M_OUTPUT
    return round(cost, 4)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _parse_model_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse the model's JSON envelope. Returns ``(payload, error)``.

    Defensive against the model emitting a Markdown code fence around
    the JSON, or a stray trailing prose line.
    """
    if not text:
        return None, "empty response from model"

    stripped = text.strip()
    if stripped.startswith("```"):
        # Strip Markdown fence: ```json\n...\n```
        stripped = re.sub(r"^```(?:json)?\s*\n?", "", stripped)
        stripped = re.sub(r"\n?```\s*$", "", stripped)

    # Find the first balanced { ... } object in the text. The model is
    # told not to add prose, but defensive parsing means we still cope.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < 0 or end < start:
        return None, "no JSON object found in model response"

    candidate = stripped[start : end + 1]
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        return None, f"JSON decode failed: {exc}"

    if not isinstance(payload, dict):
        return None, "model returned non-object JSON"

    # Coerce the four expected keys; missing keys become empty defaults.
    out: dict[str, Any] = {
        "narrative": "",
        "notable_items": [],
        "end_user_changes": [],
        "risk_callouts": [],
    }
    nar = payload.get("narrative")
    out["narrative"] = nar if isinstance(nar, str) else ""
    for key in ("notable_items", "end_user_changes", "risk_callouts"):
        val = payload.get(key)
        if isinstance(val, list):
            out[key] = [str(x).strip() for x in val if str(x).strip()]
    return out, None


# ---------------------------------------------------------------------------
# Markdown artifact
# ---------------------------------------------------------------------------


def _format_markdown(
    *,
    date_str: str,
    generated_at: str,
    commit_count: int,
    repos_with_changes: int,
    narrative: str,
    notable_items: list[str],
    end_user_changes: list[str],
    risk_callouts: list[str],
    model: str,
    cost_usd: float | None,
    skipped_reason: str | None,
) -> str:
    """Render the per-day Markdown artifact.

    Format mirrors the audit-report register from ``METHODOLOGY.md`` —
    plain prose, no emoji, no exclamations.
    """
    lines: list[str] = []
    lines.append(f"# KAOS daily diary — {date_str}")
    lines.append("")
    lines.append(
        f"*Generated {generated_at}. Window: last 24h. "
        f"{commit_count} commits across {repos_with_changes} repos.*",
    )
    lines.append("")
    lines.append("## Narrative")
    lines.append("")
    lines.append(narrative or "(no narrative)")
    lines.append("")

    lines.append("## Notable items")
    lines.append("")
    if notable_items:
        lines.extend(f"- {item}" for item in notable_items)
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("## End-user-facing changes")
    lines.append("")
    if end_user_changes:
        lines.extend(f"- {item}" for item in end_user_changes)
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("## Risk callouts")
    lines.append("")
    if risk_callouts:
        lines.extend(f"- {item}" for item in risk_callouts)
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("---")
    footer_bits = [f"Model: {model}."]
    if cost_usd is not None:
        footer_bits.append(f"Prompt cost: ${cost_usd:.4f}.")
    else:
        footer_bits.append("Prompt cost: (unavailable).")
    if skipped_reason:
        footer_bits.append(skipped_reason)
    lines.append("*" + " ".join(footer_bits) + "*")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def collect(
    repo_paths: dict[str, pathlib.Path],
    *,
    anthropic_api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    cutoff_hours: int = 24,
    max_diff_chars: int = _DEFAULT_MAX_DIFF_CHARS,
    data_root: pathlib.Path = pathlib.Path("data"),
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Produce a per-day diary across every local kaos-* clone.

    Parameters
    ----------
    repo_paths
        Mapping of ``{repo_short_name: pathlib.Path}`` pointing at the
        local clone of each kaos-* repository.
    anthropic_api_key
        Explicit API key. Falls back to ``KAOS_LLM_ANTHROPIC_API_KEY``
        then ``ANTHROPIC_API_KEY``. No key → ``skipped=True``.
    model
        Anthropic model id. Passed verbatim to the underlying SDK.
    cutoff_hours
        Lookback window for ``git log --since=...``. Defaults to 24.
    max_diff_chars
        Per-repo cap on the ``--stat`` blob. Bounds prompt cost.
    data_root
        Directory containing the ``diary/`` subdirectory. Created on
        write if missing.
    now
        UTC reference timestamp. Defaults to ``datetime.now(UTC)``.
        Pinned by unit tests for determinism.

    Returns
    -------
    dict
        See the module docstring for the full schema. Always includes
        every contracted key, even when ``skipped=True``.
    """
    now_dt = _resolve_now(now)
    cutoff_dt = now_dt - datetime.timedelta(hours=cutoff_hours)
    generated_at = _iso_z(now_dt)
    cutoff_iso = _iso_z(cutoff_dt)
    date_str = now_dt.strftime("%Y-%m-%d")

    errors: list[str] = []

    # Aggregate git activity. We do this BEFORE checking for an API key
    # so the dashboard still gets honest commit counts even on a
    # no-key skip — the counts are useful in their own right.
    per_repo: dict[str, dict[str, Any]] = {}
    for repo, path in repo_paths.items():
        activity = _collect_repo_activity(
            repo,
            path,
            cutoff_iso=cutoff_iso,
            max_diff_chars=max_diff_chars,
        )
        if activity["error"]:
            errors.append(activity["error"])
        per_repo[repo] = activity

    repos_observed = len(repo_paths)
    repos_with_changes = sum(1 for d in per_repo.values() if d["commits"])
    commit_count = sum(len(d["commits"]) for d in per_repo.values())
    file_change_count = sum(d["file_change_count"] for d in per_repo.values())

    # Build the skeleton result so every early-return path returns the
    # same shape. ``narrative`` / lists default empty.
    result: dict[str, Any] = {
        "generated_at": generated_at,
        "cutoff_iso": cutoff_iso,
        "repos_observed": repos_observed,
        "repos_with_changes": repos_with_changes,
        "commit_count": commit_count,
        "file_change_count": file_change_count,
        "skipped": False,
        "skipped_reason": None,
        "narrative": "",
        "notable_items": [],
        "end_user_changes": [],
        "risk_callouts": [],
        "artifact_path": "",
        "errors": errors,
    }

    # Provider detection: skip cleanly if no SDK is installed.
    flavor, mod = _load_llm_client()
    if flavor is None:
        result["skipped"] = True
        result["skipped_reason"] = (
            "kaos-llm-client and anthropic SDK both unavailable"
        )
        return result

    # API-key resolution. Argument wins; then the org-prefixed env var;
    # then the generic ANTHROPIC_API_KEY. Empty strings count as absent.
    api_key = (
        anthropic_api_key
        or os.environ.get("KAOS_LLM_ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or None
    )
    if not api_key:
        result["skipped"] = True
        result["skipped_reason"] = "no API key"
        return result

    # If nothing moved in the window, we still produce a stub artifact
    # so the dashboard has an entry for the day. The LLM call is
    # skipped on the empty-window path to save cost.
    if commit_count == 0:
        narrative = (
            f"No commits landed across {repos_observed} tracked repositories "
            f"in the last {cutoff_hours} hours."
        )
        artifact_path = _write_markdown_artifact(
            data_root=data_root,
            date_str=date_str,
            generated_at=generated_at,
            commit_count=0,
            repos_with_changes=0,
            narrative=narrative,
            notable_items=[],
            end_user_changes=[],
            risk_callouts=[],
            model=model,
            cost_usd=None,
            skipped_reason="No model call: empty window.",
        )
        result["narrative"] = narrative
        result["artifact_path"] = artifact_path
        return result

    # Compose prompt + call model. Each call is wrapped so a transport
    # blow-up downgrades to an empty narrative + recorded error.
    user_prompt = _build_user_prompt(per_repo)

    try:
        if flavor == "kaos":
            llm_response = _call_kaos_llm_client(
                mod,
                api_key=api_key,
                model=model,
                system=_SYSTEM_PROMPT,
                user=user_prompt,
            )
        else:
            llm_response = _call_anthropic(
                mod,
                api_key=api_key,
                model=model,
                system=_SYSTEM_PROMPT,
                user=user_prompt,
            )
    except Exception as exc:  # noqa: BLE001 — provider failures must not raise
        errors.append(f"llm_call: {type(exc).__name__}: {exc}")
        narrative = "(diary unavailable: model call failed)"
        artifact_path = _write_markdown_artifact(
            data_root=data_root,
            date_str=date_str,
            generated_at=generated_at,
            commit_count=commit_count,
            repos_with_changes=repos_with_changes,
            narrative=narrative,
            notable_items=[],
            end_user_changes=[],
            risk_callouts=[],
            model=model,
            cost_usd=None,
            skipped_reason="Model call failed; see errors.",
        )
        result["narrative"] = narrative
        result["artifact_path"] = artifact_path
        return result

    parsed, parse_error = _parse_model_json(llm_response["text"])
    if parse_error is not None or parsed is None:
        errors.append(f"parse: {parse_error}")
        narrative = "(diary unavailable: model returned unparseable output)"
        artifact_path = _write_markdown_artifact(
            data_root=data_root,
            date_str=date_str,
            generated_at=generated_at,
            commit_count=commit_count,
            repos_with_changes=repos_with_changes,
            narrative=narrative,
            notable_items=[],
            end_user_changes=[],
            risk_callouts=[],
            model=model,
            cost_usd=_estimate_cost_usd(llm_response.get("usage") or {}),
            skipped_reason="Model response unparseable; see errors.",
        )
        result["narrative"] = narrative
        result["artifact_path"] = artifact_path
        return result

    cost_usd = _estimate_cost_usd(llm_response.get("usage") or {})

    artifact_path = _write_markdown_artifact(
        data_root=data_root,
        date_str=date_str,
        generated_at=generated_at,
        commit_count=commit_count,
        repos_with_changes=repos_with_changes,
        narrative=parsed["narrative"],
        notable_items=parsed["notable_items"][:12],
        end_user_changes=parsed["end_user_changes"][:12],
        risk_callouts=parsed["risk_callouts"][:6],
        model=model,
        cost_usd=cost_usd,
        skipped_reason=None,
    )

    result["narrative"] = parsed["narrative"]
    result["notable_items"] = parsed["notable_items"][:12]
    result["end_user_changes"] = parsed["end_user_changes"][:12]
    result["risk_callouts"] = parsed["risk_callouts"][:6]
    result["artifact_path"] = artifact_path
    return result


def _write_markdown_artifact(
    *,
    data_root: pathlib.Path,
    date_str: str,
    generated_at: str,
    commit_count: int,
    repos_with_changes: int,
    narrative: str,
    notable_items: list[str],
    end_user_changes: list[str],
    risk_callouts: list[str],
    model: str,
    cost_usd: float | None,
    skipped_reason: str | None,
) -> str:
    """Write ``<data_root>/diary/<date>.md``; return the relative path."""
    diary_dir = data_root / "diary"
    diary_dir.mkdir(parents=True, exist_ok=True)
    out_path = diary_dir / f"{date_str}.md"
    body = _format_markdown(
        date_str=date_str,
        generated_at=generated_at,
        commit_count=commit_count,
        repos_with_changes=repos_with_changes,
        narrative=narrative,
        notable_items=notable_items,
        end_user_changes=end_user_changes,
        risk_callouts=risk_callouts,
        model=model,
        cost_usd=cost_usd,
        skipped_reason=skipped_reason,
    )
    out_path.write_text(body, encoding="utf-8")
    # Return a path that lines up with the dashboard's expectation of
    # "data/diary/<date>.md". We compute it relative to ``data_root``
    # then re-prefix with the canonical "data/" segment so the path is
    # stable across collectors, regardless of whether ``data_root`` was
    # passed as an absolute or relative path.
    rel_from_root = out_path.relative_to(data_root)
    return str(pathlib.Path("data") / rel_from_root)
