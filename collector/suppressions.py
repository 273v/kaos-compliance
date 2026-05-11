"""Per-repo suppressions ledger.

A "suppression" is a marker in source or config that silences a linter,
type-checker, or security scanner for a specific line, rule, or rule
family. Suppressions are legitimate engineering tools, but the *count*
is a credibility signal: a dashboard that claims 16/16 green across
six security scanners while hiding the underlying suppressions count
is over-claiming. This collector surfaces that count so a reviewer can
see whether the green came from clean code or from quiet rules.

What is counted
---------------

Per file, we count one suppression for each occurrence of:

  - ``# nosec``         — bandit (Python static security)
  - ``# noqa``          — ruff / flake8 (Python style + lints)
  - ``# ty: ignore``    — ty (Python static types)
  - ``# type: ignore``  — mypy / pyright (Python static types)
  - ``#[allow(...)]``   — clippy / rustc (Rust lints)

Per config file, we count the list-length of:

  - ``ignore = [...]``  in any ``deny.toml`` or ``Cargo.toml``
                        (cargo-deny advisory ignores, [bans] ignores)
  - ``skips:``          list entries in any ``.bandit`` config

The walker excludes the usual generated / vendored directories
(``.git``, ``.venv``, ``target``, ``dist``, ``build``, ``__pycache__``,
``node_modules``, ``_site``, ``site-packages``, ``.pytest_cache``,
``.ruff_cache``, ``.ty_cache``, ``.mypy_cache``) and lockfiles
(``uv.lock``, ``Cargo.lock``, ``poetry.lock``).

Returned shape
--------------

The :func:`collect` function returns a flat dict the renderer can
consume directly. Numbers are honest ints; ``None`` means "we couldn't
inspect the repo" (sibling clone missing) — never a silent zero.

::

    {
        "noqa": int | None,
        "nosec": int | None,
        "ty_ignore": int | None,
        "type_ignore": int | None,
        "rust_allow": int | None,
        "cargo_deny_ignore": int | None,
        "bandit_skips": int | None,
        "total": int | None,
        "errors": list[str],
    }
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "target",
        "dist",
        "build",
        "__pycache__",
        "node_modules",
        "_site",
        ".pytest_cache",
        ".ruff_cache",
        ".ty_cache",
        ".mypy_cache",
        "site-packages",
    }
)

_LOCKFILES: frozenset[str] = frozenset({"uv.lock", "Cargo.lock", "poetry.lock"})

# Line markers. Each pattern is intentionally permissive on the
# right-hand side (rule list, message text) so renames in upstream
# tooling don't silently break the count.
_RE_NOSEC = re.compile(r"#\s*nosec(\b|[:\s])")
_RE_NOQA = re.compile(r"#\s*noqa(\b|[:\s])")
_RE_TY_IGNORE = re.compile(r"#\s*ty:\s*ignore(\b|\[)")
_RE_TYPE_IGNORE = re.compile(r"#\s*type:\s*ignore(\b|\[)")
# Rust: #[allow(...)] or #![allow(...)]. We count occurrences,
# regardless of how many lints are inside.
_RE_RUST_ALLOW = re.compile(r"#!?\[allow\b")

# Inline list openers we care about in TOML configs. We only count
# entries inside an ``ignore = [...]`` block; the regex is a coarse
# stateful scanner over the file text so we don't need a TOML parser.
_RE_TOML_IGNORE_OPEN = re.compile(r"^\s*ignore\s*=\s*\[(?P<rest>.*)$")
_RE_TOML_LIST_ITEM = re.compile(
    r"""(?xs)
    (?:                       # one list element: a string, version-req, or {...} table
      "(?:[^"\\]|\\.)*"        #   double-quoted string
      | '(?:[^'\\]|\\.)*'      #   single-quoted string
      | \{[^{}]*\}             #   inline TOML table (e.g. {name = "x"})
    )
    """
)

_RE_BANDIT_SKIPS = re.compile(r"^\s*skips\s*:\s*(?P<rest>.*)$", re.MULTILINE)


def _is_excluded(parts: tuple[str, ...]) -> bool:
    return any(p in EXCLUDE_DIRS for p in parts)


def _count_inline_markers(text: str) -> dict[str, int]:
    """Count line-level suppression markers in a single source file."""
    return {
        "noqa": len(_RE_NOQA.findall(text)),
        "nosec": len(_RE_NOSEC.findall(text)),
        "ty_ignore": len(_RE_TY_IGNORE.findall(text)),
        "type_ignore": len(_RE_TYPE_IGNORE.findall(text)),
        "rust_allow": len(_RE_RUST_ALLOW.findall(text)),
    }


def _count_toml_ignore_entries(text: str) -> int:
    """Count list elements inside any ``ignore = [...]`` block in a TOML file.

    The scanner is line-oriented and tolerant of:
      - inline single-line lists:  ``ignore = ["RUSTSEC-2020-0071"]``
      - multi-line lists spanning until the matching ``]``
      - commented elements ``# "RUSTSEC-…"`` (which are NOT counted)
      - trailing comments after the closing bracket

    Comments are stripped per-line before list-element matching so that
    a commented-out ignore is excluded. Strings remain conservative —
    we only count fully-quoted entries and inline tables.
    """
    total = 0
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _RE_TOML_IGNORE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        # Accumulate the block text from the opening bracket onward.
        buf: list[str] = []
        rest = m.group("rest")
        # Strip ``#`` comments from each line to skip out-commented items.
        buf.append(_strip_toml_comment(rest))
        # Close on the same line?
        if "]" in rest:
            block = "".join(buf)
            total += _count_list_items_in_block(block)
            i += 1
            continue
        # Multi-line: consume until we see ``]``.
        i += 1
        while i < len(lines):
            line = _strip_toml_comment(lines[i])
            buf.append("\n")
            buf.append(line)
            if "]" in line:
                i += 1
                break
            i += 1
        block = "".join(buf)
        total += _count_list_items_in_block(block)
    return total


def _strip_toml_comment(line: str) -> str:
    """Remove TOML ``#`` line-comments while respecting quoted strings."""
    out = []
    in_str: str | None = None
    j = 0
    while j < len(line):
        c = line[j]
        if in_str is not None:
            out.append(c)
            if c == "\\" and j + 1 < len(line):
                out.append(line[j + 1])
                j += 2
                continue
            if c == in_str:
                in_str = None
            j += 1
            continue
        if c in ("'", '"'):
            in_str = c
            out.append(c)
            j += 1
            continue
        if c == "#":
            break
        out.append(c)
        j += 1
    return "".join(out)


def _count_list_items_in_block(block: str) -> int:
    """Count list elements between the first ``[`` and matching ``]``."""
    start = block.find("[")
    if start < 0:
        return 0
    # Trim everything past the last ``]``.
    end = block.rfind("]")
    inside = block[start + 1 : end if end > start else len(block)]
    return len(_RE_TOML_LIST_ITEM.findall(inside))


def _count_bandit_skips(text: str) -> int:
    """Count entries in a ``.bandit`` config's ``skips:`` list.

    Bandit's config is YAML-ish; supports both flow ``skips: [B101,B102]``
    and block ``skips:\\n  - B101\\n  - B102`` styles. Comments are
    ignored.
    """
    total = 0
    m = _RE_BANDIT_SKIPS.search(text)
    if not m:
        return 0
    rest = m.group("rest").strip()
    if rest.startswith("["):
        # Flow style: split on commas, count non-empty.
        inner = rest.strip("[]")
        items = [x.strip().strip("'\"") for x in inner.split(",")]
        return len([x for x in items if x])
    # Block style: count successive ``- foo`` lines after the marker.
    start = m.end()
    for line in text[start:].splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("- "):
            total += 1
            continue
        # Any other non-comment, non-list line ends the block.
        break
    return total


def collect(repo_dir: Path | None) -> dict[str, Any]:
    """Walk ``repo_dir`` and tally suppressions of each kind.

    Returns a dict matching the shape documented at the module head.
    """
    errors: list[str] = []
    if repo_dir is None or not repo_dir.is_dir():
        return {
            "noqa": None,
            "nosec": None,
            "ty_ignore": None,
            "type_ignore": None,
            "rust_allow": None,
            "cargo_deny_ignore": None,
            "bandit_skips": None,
            "total": None,
            "errors": ["sibling clone not present at expected path"]
            if repo_dir is not None
            else ["no repo_dir passed"],
        }

    counts = {
        "noqa": 0,
        "nosec": 0,
        "ty_ignore": 0,
        "type_ignore": 0,
        "rust_allow": 0,
        "cargo_deny_ignore": 0,
        "bandit_skips": 0,
    }
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        if _is_excluded(p.parts):
            continue
        if p.name in _LOCKFILES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.append(f"{p}: {type(exc).__name__}: {exc}")
            continue
        if p.suffix == ".py":
            sub = _count_inline_markers(text)
            counts["noqa"] += sub["noqa"]
            counts["nosec"] += sub["nosec"]
            counts["ty_ignore"] += sub["ty_ignore"]
            counts["type_ignore"] += sub["type_ignore"]
            continue
        if p.suffix == ".rs":
            sub = _count_inline_markers(text)
            counts["rust_allow"] += sub["rust_allow"]
            continue
        if p.name in ("deny.toml", "Cargo.toml") or p.suffix == ".toml":
            try:
                counts["cargo_deny_ignore"] += _count_toml_ignore_entries(text)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{p}: {type(exc).__name__}: {exc}")
            continue
        if p.name == ".bandit" or p.name.endswith("/.bandit"):
            try:
                counts["bandit_skips"] += _count_bandit_skips(text)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{p}: {type(exc).__name__}: {exc}")
            continue

    counts["total"] = sum(counts.values())  # type: ignore[assignment]
    counts["errors"] = errors  # type: ignore[assignment]
    return counts


def collect_for_org(
    repo_names: list[str],
    *,
    sibling_root: Path = Path("/home/mjbommar/projects/273v"),
) -> dict[str, Any]:
    """Walk every sibling repo and return per-repo + org-wide totals.

    ``repo_names`` is the list of public 273v/kaos-* repos the dashboard
    tracks (e.g. ``[m["name"] for m in snapshot["modules"]]``). Repos
    whose sibling clone is missing report ``None`` for every count; they
    do not contribute to the org-wide total.
    """
    per_repo: dict[str, dict[str, Any]] = {}
    org_total = 0
    org_known = False
    for name in repo_names:
        path = sibling_root / name
        result = collect(path if path.is_dir() else None)
        per_repo[name] = result
        if isinstance(result.get("total"), int):
            org_total += result["total"]
            org_known = True
    return {
        "per_repo": per_repo,
        "org_total": org_total if org_known else None,
        "repos_inspected": sum(
            1 for r in per_repo.values() if isinstance(r.get("total"), int)
        ),
        "repos_total": len(repo_names),
    }
