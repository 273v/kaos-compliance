#!/usr/bin/env bash
# Augment a renderer-written heartbeat.json with the cron schedule label
# and the git sha that produced it. Pure infra — not part of the public
# collector / renderer API.
#
# Required env:
#   SCHEDULE_LABEL — "1h" | "4h" | "24h"
#   GIT_SHA        — full commit sha (typically ${{ github.sha }})
#
# Args:
#   $1 — path to the heartbeat.json file the renderer just wrote.
#
# The file is rewritten in-place. We use Python (stdlib only) rather
# than `jq` so the script has zero external dependencies on the runner.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: tag-heartbeat.sh <path-to-heartbeat.json>" >&2
  exit 2
fi

heartbeat_path="$1"

if [[ -z "${SCHEDULE_LABEL:-}" || -z "${GIT_SHA:-}" ]]; then
  echo "tag-heartbeat.sh: SCHEDULE_LABEL and GIT_SHA must be set" >&2
  exit 2
fi

if [[ ! -f "${heartbeat_path}" ]]; then
  echo "tag-heartbeat.sh: heartbeat file not found: ${heartbeat_path}" >&2
  exit 1
fi

python3 - "$heartbeat_path" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["schedule"] = os.environ["SCHEDULE_LABEL"]
data["git_sha"] = os.environ["GIT_SHA"]
# generated_at is already set by the renderer; we do not overwrite it
# so the heartbeat continues to reflect the snapshot's authored time
# rather than the workflow's wall-clock.
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
