"""Codebase surface-area signals: lines of code + file counts.

This collector reads the on-disk sibling clone of each public 273v/kaos-*
repo and counts hand-written Python + Rust source. It is deliberately
separate from the supply-chain (transitive deps) and governance (process
discipline) signals — the question "how much code did *we* write" is its
own axis on the dashboard.

Definitions
-----------
* sloc:  source-lines-of-code, excluding blank lines, line-comments, and
  triple-quoted Python docstrings. (Crude but consistent across files.)
* src vs tests: any path whose parts contain ``tests``, ``test``, or
  ``benches`` counts as tests; everything else is src.
* generated / vendored exclusions: ``.venv``, ``venv``, ``target``,
  ``dist``, ``build``, ``__pycache__``, ``_site``, ``site-packages``,
  ``.pytest_cache``, ``.ruff_cache``, ``.ty_cache``, ``.mypy_cache``.
  Lockfiles (``uv.lock``, ``Cargo.lock``, ``poetry.lock``) are skipped.

Returned shape
--------------
The :func:`collect` function returns a flat dict that the renderer can
consume directly. Numbers are honest ints; ``None`` means "we couldn't
inspect the repo" (sibling clone missing) — never a silent zero.

::

    {
        "python": {
            "src_loc": int | None,
            "tests_loc": int | None,
            "src_files": int | None,
            "tests_files": int | None,
        },
        "rust": {
            "src_loc": int | None,
            "tests_loc": int | None,
            "src_files": int | None,
            "tests_files": int | None,
        },
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

_TEST_DIR_NAMES: frozenset[str] = frozenset({"tests", "test", "benches"})

_PY_LINE_COMMENT = re.compile(r"^\s*#")
_RS_LINE_COMMENT = re.compile(r"^\s*(//|/\*|\*/?)")
_BLANK = re.compile(r"^\s*$")


def _is_test_path(parts: tuple[str, ...]) -> bool:
    return any(p in _TEST_DIR_NAMES for p in parts)


def _count_sloc(path: Path, lang: str) -> int:
    """Count source-lines-of-code in a single file."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    n = 0
    comment_re = _PY_LINE_COMMENT if lang == "py" else _RS_LINE_COMMENT
    in_block_comment = False  # Rust /* ... */
    in_docstring = False  # Python triple-quoted
    docstring_quote = ""
    for line in text.splitlines():
        if _BLANK.match(line):
            continue
        s = line.strip()
        if lang == "rs":
            if in_block_comment:
                if "*/" in s:
                    in_block_comment = False
                continue
            if s.startswith("/*"):
                if "*/" not in s:
                    in_block_comment = True
                continue
            if comment_re.match(line):
                continue
            n += 1
            continue
        # Python: skip line-comments and triple-quoted docstrings
        if in_docstring:
            if docstring_quote in s:
                in_docstring = False
            continue
        if comment_re.match(line):
            continue
        # Detect docstring start; multi-quote handling for """...""" on
        # one line vs spanning multiple is intentionally light-touch.
        opens_doc = False
        for q in ('"""', "'''"):
            if s.startswith(q):
                opens_doc = True
                if s.count(q) == 1:
                    in_docstring = True
                    docstring_quote = q
                break
        if opens_doc:
            continue
        n += 1
    return n


def collect(repo_dir: Path | None) -> dict[str, Any]:
    """Walk ``repo_dir`` and count Python + Rust SLOC and file counts.

    Returns a dict matching the shape documented at the module head.
    """
    errors: list[str] = []
    if repo_dir is None or not repo_dir.is_dir():
        return {
            "python": {
                "src_loc": None,
                "tests_loc": None,
                "src_files": None,
                "tests_files": None,
            },
            "rust": {
                "src_loc": None,
                "tests_loc": None,
                "src_files": None,
                "tests_files": None,
            },
            "errors": ["sibling clone not present at expected path"]
            if repo_dir is not None
            else ["no repo_dir passed"],
        }

    py = {"src_loc": 0, "tests_loc": 0, "src_files": 0, "tests_files": 0}
    rs = {"src_loc": 0, "tests_loc": 0, "src_files": 0, "tests_files": 0}

    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.name in ("uv.lock", "Cargo.lock", "poetry.lock"):
            continue
        try:
            rel_parts = p.relative_to(repo_dir).parts
        except ValueError:
            continue
        is_test = _is_test_path(rel_parts)
        try:
            if p.suffix == ".py":
                py["tests_files" if is_test else "src_files"] += 1
                py["tests_loc" if is_test else "src_loc"] += _count_sloc(p, "py")
            elif p.suffix == ".rs":
                rs["tests_files" if is_test else "src_files"] += 1
                rs["tests_loc" if is_test else "src_loc"] += _count_sloc(p, "rs")
        except Exception as exc:
            errors.append(f"{p}: {type(exc).__name__}: {exc}")

    return {"python": py, "rust": rs, "errors": errors}
