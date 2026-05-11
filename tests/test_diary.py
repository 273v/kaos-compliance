"""Unit tests for ``collector.diary``.

Fully offline: every LLM call is mocked at the import boundary by
injecting a fake module into ``sys.modules`` so the SDK is never
imported and no real API call is made. Git is exercised against a
local ``tmp_path`` repo built by the test fixtures themselves.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import subprocess
import sys
import types
from typing import Any

import pytest

from collector import diary


# ---------------------------------------------------------------------------
# Fixtures: fake LLM modules
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_llm_modules(monkeypatch):
    """Strip any real LLM SDK from ``sys.modules`` for the duration of a test.

    The tests inject fakes as needed; this guarantees a clean slate
    even when the host happens to have a real SDK installed.
    """
    monkeypatch.delitem(sys.modules, "kaos_llm_client", raising=False)
    monkeypatch.delitem(sys.modules, "anthropic", raising=False)


def _install_fake_kaos_llm_client(monkeypatch, response_text: str, usage=None):
    """Drop a minimal ``kaos_llm_client`` into ``sys.modules``."""
    captured: dict[str, Any] = {}

    class _Response:
        def __init__(self) -> None:
            self.text = response_text
            self.usage = usage or {"input_tokens": 1200, "output_tokens": 400}

    class _LLMClient:
        def __init__(self, *, provider: str, api_key: str) -> None:
            captured["provider"] = provider
            captured["api_key"] = api_key

        def chat(self, *, model: str, messages):
            captured["model"] = model
            captured["messages"] = messages
            return _Response()

    fake = types.ModuleType("kaos_llm_client")
    fake.LLMClient = _LLMClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "kaos_llm_client", fake)
    return captured


def _install_fake_anthropic(monkeypatch, response_text: str, usage=None):
    """Drop a minimal ``anthropic`` SDK shim into ``sys.modules``."""
    captured: dict[str, Any] = {}

    class _Block:
        def __init__(self, text: str) -> None:
            self.text = text

    class _Response:
        def __init__(self) -> None:
            self.content = [_Block(response_text)]
            self.usage = types.SimpleNamespace(
                **(usage or {"input_tokens": 800, "output_tokens": 200})
            )

    class _Messages:
        def __init__(self) -> None:
            pass

        def create(self, *, model, max_tokens, system, messages):
            captured["model"] = model
            captured["max_tokens"] = max_tokens
            captured["system"] = system
            captured["messages"] = messages
            return _Response()

    class _Anthropic:
        def __init__(self, *, api_key: str) -> None:
            captured["api_key"] = api_key
            self.messages = _Messages()

    fake = types.ModuleType("anthropic")
    fake.Anthropic = _Anthropic  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    return captured


# ---------------------------------------------------------------------------
# Fixtures: a real on-disk git repo with timed commits
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: pathlib.Path, *, env_extra: dict[str, str] | None = None) -> None:
    env = {
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test Author",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    if env_extra:
        env.update(env_extra)
    # Inherit PATH etc. so ``git`` itself is findable.
    import os as _os

    full_env = {**_os.environ, **env}
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=full_env,
        check=True,
        capture_output=True,
        text=True,
    )


def _make_repo_with_timed_commits(
    path: pathlib.Path,
    commits: list[tuple[str, str]],
) -> None:
    """Initialize a git repo at ``path`` with commits at fixed dates.

    ``commits`` is a list of ``(subject, iso_date)`` pairs. We rebuild
    the index between commits with ``GIT_*_DATE`` overrides so the
    ``--since=`` filter can be tested deterministically.
    """
    path.mkdir(parents=True, exist_ok=True)
    _git(["init", "-b", "main"], cwd=path)
    _git(["config", "commit.gpgsign", "false"], cwd=path)
    _git(["config", "tag.gpgsign", "false"], cwd=path)
    for i, (subject, iso_date) in enumerate(commits):
        f = path / f"file_{i}.txt"
        f.write_text(f"line {i}\n", encoding="utf-8")
        _git(["add", str(f.name)], cwd=path)
        _git(
            ["commit", "-m", subject],
            cwd=path,
            env_extra={
                "GIT_AUTHOR_DATE": iso_date,
                "GIT_COMMITTER_DATE": iso_date,
            },
        )


# ---------------------------------------------------------------------------
# Skip behaviour
# ---------------------------------------------------------------------------


def test_skip_when_no_sdk_available(tmp_path, monkeypatch):
    """Neither SDK importable → skipped=True, structured reason, no file."""
    # Force both imports to fail.
    real_import = __import__

    def _blocking_import(name, *a, **kw):
        if name in ("kaos_llm_client", "anthropic"):
            raise ImportError(f"blocked: {name}")
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", _blocking_import)

    result = diary.collect(
        repo_paths={},
        anthropic_api_key="sk-fake",
        data_root=tmp_path / "data",
    )

    assert result["skipped"] is True
    assert "unavailable" in (result["skipped_reason"] or "")
    assert result["artifact_path"] == ""
    # No file written when SDK is missing.
    assert not (tmp_path / "data" / "diary").exists()


def test_skip_when_no_api_key(tmp_path, monkeypatch):
    """SDK available but no key → skipped=True, reason='no API key'."""
    _install_fake_kaos_llm_client(monkeypatch, response_text="")
    monkeypatch.delenv("KAOS_LLM_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = diary.collect(
        repo_paths={},
        anthropic_api_key=None,
        data_root=tmp_path / "data",
    )
    assert result["skipped"] is True
    assert result["skipped_reason"] == "no API key"
    assert result["artifact_path"] == ""
    # No diary directory created on skip.
    assert not (tmp_path / "data" / "diary").exists()


def test_skip_uses_env_var_fallback(tmp_path, monkeypatch):
    """Argument absent → KAOS_LLM_ANTHROPIC_API_KEY → ANTHROPIC_API_KEY."""
    _install_fake_kaos_llm_client(
        monkeypatch,
        response_text=json.dumps(
            {
                "narrative": "Quiet day.",
                "notable_items": [],
                "end_user_changes": [],
                "risk_callouts": [],
            }
        ),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fallback")
    monkeypatch.delenv("KAOS_LLM_ANTHROPIC_API_KEY", raising=False)

    result = diary.collect(
        repo_paths={},
        anthropic_api_key=None,
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )
    # commit_count==0 → no model call, but a stub file is written.
    assert result["skipped"] is False
    assert result["narrative"].startswith("No commits")


# ---------------------------------------------------------------------------
# Malformed model output
# ---------------------------------------------------------------------------


def test_malformed_model_json_falls_back_and_records_error(tmp_path, monkeypatch):
    """Unparseable model output → graceful narrative + error in list + file written."""
    repo = tmp_path / "kaos-core"
    _make_repo_with_timed_commits(
        repo,
        [("feat: add widget", "2026-05-11T12:00:00+00:00")],
    )

    _install_fake_kaos_llm_client(
        monkeypatch,
        response_text="this is not JSON at all, sorry",
    )

    result = diary.collect(
        repo_paths={"kaos-core": repo},
        anthropic_api_key="sk-fake",
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert result["skipped"] is False
    assert "unavailable" in result["narrative"]
    assert any("parse" in e.lower() or "json" in e.lower() for e in result["errors"])
    # File is still written so the dashboard has an entry for the day.
    written = tmp_path / "data" / "diary" / "2026-05-11.md"
    assert written.is_file()
    body = written.read_text(encoding="utf-8")
    assert "Model response unparseable" in body


def test_partial_json_with_code_fence_is_parsed(tmp_path, monkeypatch):
    """A model that wraps JSON in ```json fences is still handled."""
    repo = tmp_path / "kaos-core"
    _make_repo_with_timed_commits(
        repo,
        [("fix: tighten input validation", "2026-05-11T10:00:00+00:00")],
    )

    fenced = (
        "```json\n"
        + json.dumps(
            {
                "narrative": (
                    "kaos-core tightened input validation. One commit landed; "
                    "no license or workflow changes were observed. The change "
                    "is contained to a single module. No risk callouts."
                ),
                "notable_items": ["kaos-core: input validation hardened"],
                "end_user_changes": [],
                "risk_callouts": [],
            }
        )
        + "\n```"
    )
    _install_fake_kaos_llm_client(monkeypatch, response_text=fenced)

    result = diary.collect(
        repo_paths={"kaos-core": repo},
        anthropic_api_key="sk-fake",
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert result["skipped"] is False
    assert result["errors"] == []
    assert "input validation" in result["narrative"]
    assert result["notable_items"] == ["kaos-core: input validation hardened"]


# ---------------------------------------------------------------------------
# Git cutoff window
# ---------------------------------------------------------------------------


def test_cutoff_window_filters_old_commits(tmp_path, monkeypatch):
    """A 24h cutoff must drop commits authored more than a day ago."""
    repo = tmp_path / "kaos-core"
    _make_repo_with_timed_commits(
        repo,
        [
            ("feat: from a week ago",  "2026-05-04T12:00:00+00:00"),  # outside
            ("fix: from yesterday",     "2026-05-10T20:00:00+00:00"),  # inside
            ("docs: from this morning", "2026-05-11T08:00:00+00:00"),  # inside
        ],
    )

    _install_fake_kaos_llm_client(
        monkeypatch,
        response_text=json.dumps(
            {
                "narrative": "Two commits landed in the last day.",
                "notable_items": [],
                "end_user_changes": [],
                "risk_callouts": [],
            }
        ),
    )

    result = diary.collect(
        repo_paths={"kaos-core": repo},
        anthropic_api_key="sk-fake",
        cutoff_hours=24,
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert result["commit_count"] == 2
    assert result["repos_with_changes"] == 1
    assert result["repos_observed"] == 1


def test_missing_repo_directory_is_a_recorded_error_not_a_crash(tmp_path, monkeypatch):
    """A path that doesn't exist must yield a structured error, not raise."""
    _install_fake_kaos_llm_client(monkeypatch, response_text="")
    monkeypatch.delenv("KAOS_LLM_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = diary.collect(
        repo_paths={"kaos-ghost": tmp_path / "does" / "not" / "exist"},
        anthropic_api_key=None,
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert any("not a git clone" in e for e in result["errors"])
    # Without a key we still skip cleanly.
    assert result["skipped"] is True


# ---------------------------------------------------------------------------
# Truncation marker
# ---------------------------------------------------------------------------


def test_max_diff_chars_truncation_appends_marker():
    """``_truncate`` must leave a machine-greppable marker tail."""
    blob = "x" * 1000
    out = diary._truncate(blob, limit=100)
    assert out.startswith("x" * 100)
    assert "truncated" in out
    assert "900 more bytes" in out


def test_per_repo_stat_is_truncated_at_max_diff_chars(tmp_path, monkeypatch):
    """The actual collect() path must enforce the per-repo cap."""
    repo = tmp_path / "kaos-large"
    repo.mkdir()
    _git(["init", "-b", "main"], cwd=repo)
    _git(["config", "commit.gpgsign", "false"], cwd=repo)
    # Many files in a single commit so --stat produces a long blob.
    for i in range(200):
        (repo / f"f_{i}.txt").write_text(("y" * 100) + "\n", encoding="utf-8")
    _git(["add", "."], cwd=repo)
    _git(
        ["commit", "-m", "chore: bulk add"],
        cwd=repo,
        env_extra={
            "GIT_AUTHOR_DATE": "2026-05-11T08:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-05-11T08:00:00+00:00",
        },
    )

    activity = diary._collect_repo_activity(
        "kaos-large",
        repo,
        cutoff_iso="2026-05-10T08:00:00Z",
        max_diff_chars=500,
    )

    assert len(activity["stat"]) <= 500 + 64  # 64 = generous marker overhead
    assert "truncated" in activity["stat"]


# ---------------------------------------------------------------------------
# Markdown artifact path + body
# ---------------------------------------------------------------------------


def test_artifact_path_is_relative_and_anchored_at_data(tmp_path, monkeypatch):
    """The returned ``artifact_path`` must be ``data/diary/<date>.md``."""
    repo = tmp_path / "kaos-core"
    _make_repo_with_timed_commits(
        repo,
        [("feat: x", "2026-05-11T12:00:00+00:00")],
    )

    _install_fake_kaos_llm_client(
        monkeypatch,
        response_text=json.dumps(
            {
                "narrative": "One commit landed.",
                "notable_items": [],
                "end_user_changes": [],
                "risk_callouts": [],
            }
        ),
    )

    result = diary.collect(
        repo_paths={"kaos-core": repo},
        anthropic_api_key="sk-fake",
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert result["artifact_path"] == "data/diary/2026-05-11.md"
    written = tmp_path / "data" / "diary" / "2026-05-11.md"
    assert written.is_file()
    body = written.read_text(encoding="utf-8")
    assert body.startswith("# KAOS daily diary — 2026-05-11")
    assert "## Narrative" in body
    assert "## Notable items" in body
    assert "## End-user-facing changes" in body
    assert "## Risk callouts" in body
    assert "Model: claude-sonnet-4-6" in body


def test_anthropic_sdk_path_is_exercised_when_kaos_client_absent(tmp_path, monkeypatch):
    """If kaos_llm_client is missing but anthropic is present, use the SDK."""
    # Make sure kaos_llm_client cannot be imported.
    real_import = __import__

    def _blocking_import(name, *a, **kw):
        if name == "kaos_llm_client":
            raise ImportError("blocked")
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", _blocking_import)

    captured = _install_fake_anthropic(
        monkeypatch,
        response_text=json.dumps(
            {
                "narrative": "All quiet.",
                "notable_items": [],
                "end_user_changes": [],
                "risk_callouts": [],
            }
        ),
    )

    repo = tmp_path / "kaos-core"
    _make_repo_with_timed_commits(
        repo,
        [("fix: y", "2026-05-11T12:00:00+00:00")],
    )

    result = diary.collect(
        repo_paths={"kaos-core": repo},
        anthropic_api_key="sk-fake",
        data_root=tmp_path / "data",
        now=datetime.datetime(2026, 5, 11, 15, tzinfo=datetime.UTC),
    )

    assert result["skipped"] is False
    assert captured["model"] == diary.DEFAULT_MODEL
    assert captured["api_key"] == "sk-fake"
    # The system prompt must be the auditor-register one.
    assert "compliance" in captured["system"].lower()


# ---------------------------------------------------------------------------
# Contract shape
# ---------------------------------------------------------------------------


def test_return_shape_always_has_every_contracted_key(tmp_path, monkeypatch):
    """Even on the no-key skip path, every contracted key is present."""
    monkeypatch.delenv("KAOS_LLM_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _install_fake_kaos_llm_client(monkeypatch, response_text="")

    result = diary.collect(
        repo_paths={},
        anthropic_api_key=None,
        data_root=tmp_path / "data",
    )
    expected = {
        "generated_at",
        "cutoff_iso",
        "repos_observed",
        "repos_with_changes",
        "commit_count",
        "file_change_count",
        "skipped",
        "skipped_reason",
        "narrative",
        "notable_items",
        "end_user_changes",
        "risk_callouts",
        "artifact_path",
        "errors",
    }
    assert set(result.keys()) == expected
