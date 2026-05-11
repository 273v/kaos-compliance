#!/usr/bin/env bash
# Local cron backup for the kaos-compliance dashboard.
#
# Runs the full sweep (snapshot + render + optional LLM diary) on the
# developer machine and force-with-lease-pushes the result to the
# `gh-pages` branch. Designed to be idempotent with the GitHub Actions
# sweep — `--force-with-lease` refuses to clobber a remote tip we did
# not observe, so a GHA push that landed first will cause this script
# to bail and try again next tick rather than silently rewinding.
#
# Run via systemd-user-timer or `crontab -e`. The companion
# `scripts/install-cron.sh` wires either one.
#
# Safety contract:
#   - Refuses to run if `main` is dirty.
#   - Refuses to run if `main` is behind origin (force-pull is the
#     developer's call, not the cron's).
#   - Uses a per-PID temp worktree so the developer's main worktree
#     never sees the gh-pages branch. Cleans stale worktrees from
#     previous runs.
#   - Does not delete the snapshot JSON; the JSON history is part of
#     the audit trail.
#
# Exit codes:
#   0  — success (deployed or no-op)
#   1  — refused to run (dirty / behind / stale worktree wedged)
#   2  — sweep failed
#   3  — push failed (lease lost or network)

set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────────────
REPO_ROOT="/home/mjbommar/projects/273v/kaos-compliance"
GH_PAGES_BRANCH="gh-pages"
REMOTE="origin"
MAIN_BRANCH="main"
WORKTREE_PARENT="${TMPDIR:-/tmp}"
WORKTREE_PREFIX="kaos-compliance-ghpages"
PYPROJECT_STAMP="${REPO_ROOT}/.cache/local-cron.pyproject.sha256"
LOG_PREFIX="[local-cron]"

log()  { printf '%s %s\n'    "${LOG_PREFIX}" "$*" >&2; }
die()  { printf '%s ERROR: %s\n' "${LOG_PREFIX}" "$*" >&2; exit "${2:-1}"; }

# ─── Preflight ─────────────────────────────────────────────────────────
[[ -d "${REPO_ROOT}/.git" ]] || die "repo not found at ${REPO_ROOT}" 1
cd "${REPO_ROOT}"

# Require a clean working tree on main.
current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${current_branch}" != "${MAIN_BRANCH}" ]]; then
  die "expected branch ${MAIN_BRANCH}, found ${current_branch}; refusing." 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  die "working tree dirty; refusing to run." 1
fi

# Fetch + fast-forward only. Never resolve.
log "fetching ${REMOTE}…"
git fetch --prune --quiet "${REMOTE}"
if ! git merge-base --is-ancestor "${MAIN_BRANCH}" "${REMOTE}/${MAIN_BRANCH}"; then
  die "${MAIN_BRANCH} has diverged from ${REMOTE}/${MAIN_BRANCH}; refusing." 1
fi
git pull --ff-only --quiet "${REMOTE}" "${MAIN_BRANCH}" \
  || die "git pull --ff-only failed; refusing." 1

# ─── uv sync — only when pyproject.toml or uv.lock changed ─────────────
mkdir -p "$(dirname "${PYPROJECT_STAMP}")"
new_sha="$(sha256sum pyproject.toml uv.lock 2>/dev/null | sha256sum | awk '{print $1}')"
old_sha=""
if [[ -f "${PYPROJECT_STAMP}" ]]; then
  old_sha="$(cat "${PYPROJECT_STAMP}")"
fi
if [[ "${new_sha}" != "${old_sha}" ]]; then
  log "pyproject/lock changed → uv sync --group dev"
  uv sync --group dev
  printf '%s\n' "${new_sha}" > "${PYPROJECT_STAMP}"
else
  log "pyproject/lock unchanged → skipping uv sync"
fi

# ─── Stale-worktree GC ─────────────────────────────────────────────────
# A previous run that died between `git worktree add` and `git worktree
# remove` will leave a directory + a git/worktrees/<name> registration.
# Prune them both before adding a fresh one.
git worktree prune
for stale in "${WORKTREE_PARENT}/${WORKTREE_PREFIX}-"*; do
  [[ -e "${stale}" ]] || continue
  log "removing stale worktree ${stale}"
  git worktree remove --force "${stale}" 2>/dev/null || true
  rm -rf -- "${stale}"
done

# ─── Sweep ─────────────────────────────────────────────────────────────
log "running snapshot collector…"
mkdir -p data/snapshots _site
if ! uv run python -m collector.snapshot \
      --output data/snapshots/latest.json \
      --pretty; then
  die "collector.snapshot failed" 2
fi

# Optional LLM diary — best-effort. Skipped quietly when not wired.
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  log "ANTHROPIC_API_KEY present — attempting LLM diary…"
  mkdir -p data/diary
  if uv run python -c "import importlib; importlib.import_module('collector.diary')" 2>/dev/null; then
    today="$(date -u +%Y-%m-%d)"
    uv run python -m collector.diary --output "data/diary/${today}.json" \
      || log "diary failed; continuing without it."
  else
    log "collector.diary not yet wired — skipping."
  fi
fi

log "rendering dashboard…"
if ! uv run python -m render \
      --snapshot data/snapshots/latest.json \
      --output _site \
      --clean; then
  die "render failed" 2
fi

# Tag the heartbeat so dashboards can distinguish a local-cron push
# from a GHA push. Reuses the CI helper to stay consistent.
SCHEDULE_LABEL="local-24h" \
GIT_SHA="$(git rev-parse HEAD)" \
  bash "${REPO_ROOT}/scripts/_ci/tag-heartbeat.sh" _site/heartbeat.json

# ─── Stage the deploy via a temporary worktree ─────────────────────────
worktree_dir="${WORKTREE_PARENT}/${WORKTREE_PREFIX}-$$"
log "creating worktree ${worktree_dir}"
# `--detach` keeps the worktree untracked by a branch; we set the
# orphan/branch state inside it explicitly.
git worktree add --detach "${worktree_dir}" >/dev/null
trap 'git worktree remove --force "${worktree_dir}" 2>/dev/null || true; rm -rf -- "${worktree_dir}"' EXIT

# Reset the worktree to the remote gh-pages tip so the lease we hold
# matches what GHA last published.
if git ls-remote --exit-code --heads "${REMOTE}" "${GH_PAGES_BRANCH}" >/dev/null 2>&1; then
  log "checking out remote ${GH_PAGES_BRANCH}…"
  (
    cd "${worktree_dir}"
    git fetch --quiet "${REMOTE}" "${GH_PAGES_BRANCH}"
    git checkout -B "${GH_PAGES_BRANCH}" "${REMOTE}/${GH_PAGES_BRANCH}"
  )
else
  log "remote ${GH_PAGES_BRANCH} not found — creating fresh orphan"
  (
    cd "${worktree_dir}"
    git checkout --orphan "${GH_PAGES_BRANCH}"
    git rm -rf --quiet . 2>/dev/null || true
  )
fi

# Replace contents with the freshly rendered _site.
log "syncing _site → worktree"
# Remove everything except .git inside the worktree.
find "${worktree_dir}" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
# Copy renderer output. `cp -a` preserves timestamps; we then rely on
# git to detect actual content changes.
cp -a _site/. "${worktree_dir}/"

# ─── Commit + push with lease ──────────────────────────────────────────
commit_sha="$(git rev-parse HEAD)"
(
  cd "${worktree_dir}"
  git add -A
  if git diff --cached --quiet; then
    log "no changes versus current gh-pages — skipping push."
    exit 0
  fi
  # Authored as the local-cron bot identity. Configure once via
  # `git config user.*` if a different signature is required.
  GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-kaos-compliance-local}" \
  GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-kaos-compliance-local@localhost}" \
  GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-kaos-compliance-local}" \
  GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-kaos-compliance-local@localhost}" \
    git commit --quiet -m "sweep(local-24h): ${commit_sha}"
  log "pushing gh-pages with --force-with-lease…"
)
push_rc=0
git -C "${worktree_dir}" push --force-with-lease "${REMOTE}" "${GH_PAGES_BRANCH}" \
  || push_rc=$?
if [[ "${push_rc}" -ne 0 ]]; then
  log "push failed (rc=${push_rc}); a remote update likely raced us — will retry next tick."
  exit 3
fi
log "deploy ok."
exit 0
