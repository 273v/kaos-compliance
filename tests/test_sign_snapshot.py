"""Tests for ``scripts/_ci/sign-snapshot.sh`` (R4: keyless snapshot signing).

Cosign is not on the CI runner during pytest (and we don't want to
network-sign during tests anyway). These tests cover the contract the
script promises to its caller:

  * If cosign is missing → exit 0 with a WARNING, no bundle produced.
  * If the input snapshot is missing → exit 0 with a WARNING.
  * If cosign succeeds (stub) → produce both the bundle path AND the
    meta sidecar with the expected identity assembled from $GITHUB_*.
  * If cosign fails (stub) → exit 0, remove the partial bundle, no
    meta written.

The tests use a PATH-shimmed cosign stub so we exercise the script
end-to-end without sigstore network calls.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "_ci" / "sign-snapshot.sh"


@pytest.fixture
def snapshot_file(tmp_path: Path) -> Path:
    p = tmp_path / "snapshot.json"
    p.write_text('{"schema_version":"1.0","generated_at":"2026-05-11T00:00:00Z"}', encoding="utf-8")
    return p


def _run(
    args: list[str],
    *,
    env_extra: dict[str, str] | None = None,
    path_prefix: Path | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # Strip any inherited Actions vars so the local-run guard is
    # exercised deterministically per test.
    for k in (
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "COSIGN_EXPERIMENTAL",
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
    ):
        env.pop(k, None)
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_missing_snapshot_is_soft_failure(tmp_path: Path) -> None:
    bundle = tmp_path / "out.sig"
    cp = _run([str(tmp_path / "nonexistent.json"), str(bundle)])
    assert cp.returncode == 0
    assert "WARNING(sign-snapshot)" in cp.stderr
    assert not bundle.exists()


def test_cosign_absent_is_soft_failure(snapshot_file: Path, tmp_path: Path) -> None:
    """When cosign is not on PATH, the script logs and exits 0."""
    bundle = tmp_path / "out.sig"
    # Resolve bash before stripping PATH; otherwise the subprocess
    # can't even find /bin/bash on a minimal-PATH runner.
    bash_path = shutil.which("bash") or "/bin/bash"
    # Shadow PATH with an empty dir so `command -v cosign` finds nothing
    # and the OIDC guard is irrelevant.
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    env = {**os.environ, "PATH": str(empty_bin)}
    # Strip OIDC + Actions vars too — the cosign-missing branch should
    # short-circuit before the guard.
    for k in ("ACTIONS_ID_TOKEN_REQUEST_URL", "COSIGN_EXPERIMENTAL"):
        env.pop(k, None)
    cp = subprocess.run(
        [bash_path, str(SCRIPT), str(snapshot_file), str(bundle)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    assert "cosign not on PATH" in cp.stderr
    assert not bundle.exists()


def test_local_run_without_oidc_is_soft_failure(snapshot_file: Path, tmp_path: Path) -> None:
    """Even with cosign installed, a local run (no OIDC token) skips signing.

    Tests must not depend on the host's cosign install — but they DO
    need PATH to find *something* named cosign so we can verify the
    OIDC guard kicks in before cosign is invoked.
    """
    bundle = tmp_path / "out.sig"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "cosign").write_text("#!/usr/bin/env bash\nexit 99\n")
    (fake_bin / "cosign").chmod(0o755)
    cp = _run([str(snapshot_file), str(bundle)], path_prefix=fake_bin)
    assert cp.returncode == 0, cp.stderr
    assert "no OIDC token available" in cp.stderr
    assert not bundle.exists()


def test_successful_signing_writes_bundle_and_meta(snapshot_file: Path, tmp_path: Path) -> None:
    """Stub cosign that 'signs' by writing fixed bytes; assert the script
    produces the bundle AND the metadata sidecar with the expected GitHub
    identity reconstructed from env."""
    bundle = tmp_path / "out.sig"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    # The stub writes the value of --bundle as a dummy bundle; this
    # mirrors the calling convention without actually doing crypto.
    stub = fake_bin / "cosign"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'bundle=""\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    --bundle) bundle="$2"; shift 2;;\n'
        "    *) shift;;\n"
        "  esac\n"
        "done\n"
        "echo 'dGVzdC1ic25kbGU=' > \"$bundle\"\n"
        "echo 'cosign stub: signed' >&2\n"
        "exit 0\n"
    )
    stub.chmod(0o755)

    env = {
        # Trip the OIDC guard so the script proceeds to invoke the stub.
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://stub",
        "GITHUB_REPOSITORY": "273v/kaos-compliance",
        "GITHUB_RUN_ID": "424242",
        "GITHUB_SHA": "deadbeef" * 5,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": "273v/kaos-compliance/.github/workflows/sweep.yml@refs/heads/main",
    }
    cp = _run([str(snapshot_file), str(bundle)], env_extra=env, path_prefix=fake_bin)
    assert cp.returncode == 0, cp.stderr
    assert bundle.is_file(), "bundle must be produced when cosign succeeds"

    meta_path = tmp_path / "out.sig.meta.json"
    assert meta_path.is_file(), "metadata sidecar must be produced alongside the bundle"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["scheme"] == "sigstore-cosign-keyless"
    assert meta["bundle_format"] == "dsse-base64-bundle"
    assert meta["bundle_path"] == "out.sig"
    assert meta["github_run_id"] == "424242"
    assert meta["expected_issuer"] == "https://token.actions.githubusercontent.com"
    # The expected_identity should reference the workflow file.
    assert "sweep.yml" in meta["expected_identity"]
    assert "273v/kaos-compliance" in meta["expected_identity"]


def test_failed_signing_removes_partial_bundle(snapshot_file: Path, tmp_path: Path) -> None:
    """When cosign exits non-zero, the script must not leave a partial
    bundle behind that the renderer would mistake for a real signature."""
    bundle = tmp_path / "out.sig"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    stub = fake_bin / "cosign"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'bundle=""\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    --bundle) bundle="$2"; shift 2;;\n'
        "    *) shift;;\n"
        "  esac\n"
        "done\n"
        # Touch a partial then fail — simulates a network drop after
        # cosign starts writing.
        'touch "$bundle"\n'
        "echo 'cosign stub: simulated failure' >&2\n"
        "exit 7\n"
    )
    stub.chmod(0o755)

    env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://stub"}
    cp = _run([str(snapshot_file), str(bundle)], env_extra=env, path_prefix=fake_bin)
    assert cp.returncode == 0, cp.stderr
    assert "cosign sign-blob failed" in cp.stderr
    assert not bundle.exists(), "partial bundle must be removed on cosign failure"


def test_script_is_executable() -> None:
    """The script must be executable so the workflow's `bash` invocation
    inherits sensible defaults. (We invoke through `bash` everywhere
    anyway, but a non-executable file in scripts/_ci/ is a smell.)"""
    assert SCRIPT.is_file()
    # On POSIX the +x bit should be set by the commit.
    mode = SCRIPT.stat().st_mode
    assert mode & 0o100, f"sign-snapshot.sh is not user-executable: mode={oct(mode)}"
