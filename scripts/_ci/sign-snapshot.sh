#!/usr/bin/env bash
# Keyless sigstore signing for the kaos-compliance snapshot.
#
# Why
# ---
# The dashboard's claims rest on api/v1/snapshot.json. If an attacker
# compromises the runner they can rewrite the JSON and every page
# downstream. A keyless signature with cosign + GitHub OIDC ties each
# published snapshot to a specific workflow invocation; consumers can
# verify with `cosign verify-blob --bundle ...` and assert the bundle
# was minted by THIS workflow on THIS repo, before trusting the data.
#
# Required environment (set by the GitHub Actions runner):
#   - COSIGN_EXPERIMENTAL / cosign v2+ semantics; identity is auto-pulled
#     from $ACTIONS_ID_TOKEN_REQUEST_TOKEN and the Fulcio issuer.
#
# Args
# ----
#   $1 — path to the snapshot JSON to sign  (input, not modified)
#   $2 — path to write the DSSE bundle to   (output, single-file base64
#        bundle as emitted by `cosign sign-blob --bundle`)
#
# Behavior
# --------
# On any failure (cosign missing, OIDC not present, network flake), the
# script prints a single-line WARNING to stderr and exits 0. The render
# step continues; the renderer detects the absent bundle and falls back
# to gray for the signature pill. We do this so a transient cosign
# outage cannot block a publish — the worst case is "no signature this
# cycle", not "no dashboard at all".
#
# A hard failure to publish a signed snapshot would defeat the very
# point of the integrity check (an attacker who can suppress the
# bundle could force a deploy-with-no-signature anyway). We accept
# that this trades availability for one cycle against alert clarity.
# The next cycle's signed bundle re-asserts the chain.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: sign-snapshot.sh <snapshot.json> <output.sig>" >&2
  exit 2
fi

snapshot_path="$1"
bundle_path="$2"

if [[ ! -f "${snapshot_path}" ]]; then
  echo "WARNING(sign-snapshot): snapshot not found at ${snapshot_path}; skipping" >&2
  exit 0
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "WARNING(sign-snapshot): cosign not on PATH; skipping signature" >&2
  exit 0
fi

# Local-run guard: keyless requires an OIDC token. When run outside
# Actions (no $ACTIONS_ID_TOKEN_REQUEST_URL) we skip rather than
# prompting the developer to authenticate against the public Fulcio.
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -z "${COSIGN_EXPERIMENTAL:-}" ]]; then
  echo "WARNING(sign-snapshot): no OIDC token available (not in Actions); skipping" >&2
  exit 0
fi

# `--yes` accepts the public-good-instance TOS prompt non-interactively.
# `--bundle` emits a single-file DSSE bundle which is what consumers
# verify against with `cosign verify-blob --bundle`. We do NOT emit the
# separate .sig + .pem pair because the dashboard publishes one file
# next to snapshot.json and the bundle is self-contained.
echo "sign-snapshot: signing ${snapshot_path} → ${bundle_path}" >&2
if ! cosign sign-blob \
    --yes \
    --bundle "${bundle_path}" \
    "${snapshot_path}"; then
  echo "WARNING(sign-snapshot): cosign sign-blob failed; deploying without signature" >&2
  # Remove a partial bundle so the renderer doesn't pick up garbage.
  rm -f "${bundle_path}"
  exit 0
fi

# Emit a small metadata file the renderer reads to display the
# verification pill. Storing this next to the bundle keeps verification
# parameters discoverable without scraping the workflow YAML.
meta_path="${bundle_path%.sig}.sig.meta.json"
python3 - "$meta_path" <<PY
import json
import os
import sys
from pathlib import Path

meta = {
    "scheme": "sigstore-cosign-keyless",
    "bundle_format": "dsse-base64-bundle",
    "bundle_path": "${bundle_path##*/}",
    "expected_identity": (
        f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '273v/kaos-compliance')}/"
        f".github/workflows/{os.environ.get('GITHUB_WORKFLOW_REF', 'sweep.yml').split('@')[0].split('/')[-1]}"
        f"@{os.environ.get('GITHUB_REF', 'refs/heads/main')}"
    ),
    "expected_issuer": "https://token.actions.githubusercontent.com",
    "github_run_id": os.environ.get("GITHUB_RUN_ID"),
    "github_sha": os.environ.get("GITHUB_SHA"),
    "github_workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
}
Path(sys.argv[1]).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
PY
echo "sign-snapshot: signed → ${bundle_path}" >&2
echo "sign-snapshot: metadata → ${meta_path}" >&2
