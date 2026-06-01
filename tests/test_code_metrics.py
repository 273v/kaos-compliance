"""Tests for collector.code_metrics — focused on the test-function counter
(``tests_count``), the cardinality signal behind the dashboard "Tests" tile.

The counter is a static, dependency-free lower bound on test *cases*:
parametrized rows are counted once (we never run the suites).
"""

from __future__ import annotations

from pathlib import Path

from collector import code_metrics


def test_counts_python_test_functions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "tests" / "test_a.py").write_text(
        "import pytest\n\n"
        "def test_one():\n    assert True\n\n"
        "async def test_two():\n    assert True\n\n"
        "@pytest.mark.parametrize('x', [1, 2, 3])\n"
        "def test_param(x):\n    assert x  # parametrize counted ONCE\n\n"
        "def helper():\n    return 1  # not a test\n",
        encoding="utf-8",
    )
    # A root-level test_*.py is in pytest's default collection scope even
    # though it is not under a tests/ directory.
    (repo / "test_root.py").write_text("def test_root_case():\n    assert 1\n", encoding="utf-8")
    # A src module that merely contains a test_-looking def is NOT a test
    # file, so its function must not be counted.
    (repo / "src" / "module.py").write_text(
        "def test_like_but_src():\n    return 0\n", encoding="utf-8"
    )

    out = code_metrics.collect(repo)
    # test_a.py → test_one, test_two, test_param (3); test_root.py → 1.
    assert out["python"]["tests_count"] == 4


def test_counts_rust_test_attributes_inline_in_src(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "lib.rs").write_text(
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\n"
        "#[cfg(test)]\nmod tests {\n"
        "    #[test]\n    fn t1() {}\n\n"
        "    #[tokio::test]\n    async fn t2() {}\n"
        "}\n",
        encoding="utf-8",
    )
    out = code_metrics.collect(repo)
    # Inline #[test] + #[tokio::test] both counted.
    assert out["rust"]["tests_count"] == 2


def test_missing_clone_reports_none_not_zero(tmp_path: Path) -> None:
    out = code_metrics.collect(tmp_path / "does-not-exist")
    assert out["python"]["tests_count"] is None
    assert out["rust"]["tests_count"] is None
