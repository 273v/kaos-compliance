#!/usr/bin/env bash
# Install the local kaos-compliance sweep on a 24h schedule.
#
# Prefers systemd user units (preferred on a workstation that is
# routinely awake) and falls back to crontab(1) when systemd-user is
# unavailable. Idempotent — re-running this script overwrites the unit
# files or replaces the existing crontab line without duplicating it.
#
# Usage:
#   scripts/install-cron.sh                # auto-detect
#   scripts/install-cron.sh --backend systemd|cron
#   scripts/install-cron.sh --uninstall
#
# The script is intentionally chatty about what it did so a sysadmin
# can audit the change after the fact.

set -euo pipefail

REPO_ROOT="/home/mjbommar/projects/273v/kaos-compliance"
SERVICE_NAME="kaos-compliance"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
SERVICE_PATH="${SYSTEMD_USER_DIR}/${SERVICE_NAME}.service"
TIMER_PATH="${SYSTEMD_USER_DIR}/${SERVICE_NAME}.timer"
CRON_MARKER="# kaos-compliance local-cron (managed by install-cron.sh)"
LOG_PREFIX="[install-cron]"

log()  { printf '%s %s\n' "${LOG_PREFIX}" "$*"; }
die()  { printf '%s ERROR: %s\n' "${LOG_PREFIX}" "$*" >&2; exit 1; }

BACKEND=""
ACTION="install"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -x "${REPO_ROOT}/scripts/local-cron.sh" ]] \
  || die "${REPO_ROOT}/scripts/local-cron.sh not found or not executable"

detect_backend() {
  if command -v systemctl >/dev/null 2>&1 \
     && systemctl --user status >/dev/null 2>&1; then
    printf 'systemd\n'
  elif command -v crontab >/dev/null 2>&1; then
    printf 'cron\n'
  else
    printf 'none\n'
  fi
}

if [[ -z "${BACKEND}" ]]; then
  BACKEND="$(detect_backend)"
  [[ "${BACKEND}" = "none" ]] && die "neither systemd-user nor crontab is available"
  log "auto-detected backend: ${BACKEND}"
fi

# ─── systemd backend ──────────────────────────────────────────────────
install_systemd() {
  mkdir -p "${SYSTEMD_USER_DIR}"

  cat > "${SERVICE_PATH}" <<UNIT
[Unit]
Description=kaos-compliance local sweep
Documentation=https://273v.github.io/kaos-compliance/
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${REPO_ROOT}
ExecStart=${REPO_ROOT}/scripts/local-cron.sh
# Sweep should never run longer than 30 minutes locally.
TimeoutStartSec=1800
# Keep logs in the journal; failures alert via systemd's standard
# on-failure path if the operator wires one.
StandardOutput=journal
StandardError=journal
Nice=10
UNIT

  cat > "${TIMER_PATH}" <<UNIT
[Unit]
Description=kaos-compliance local sweep (24h)
Documentation=https://273v.github.io/kaos-compliance/

[Timer]
# Daily at 04:17 local time. Offset from UTC midnight (when the GHA
# full sweep runs) so we don't race the runner; close enough to give
# the next morning a fresh page even if GHA missed its slot.
OnCalendar=*-*-* 04:17:00
# Catch up after laptop sleep / reboot windows.
Persistent=true
RandomizedDelaySec=600
Unit=${SERVICE_NAME}.service

[Install]
WantedBy=timers.target
UNIT

  systemctl --user daemon-reload
  systemctl --user enable --now "${SERVICE_NAME}.timer"
  log "installed ${TIMER_PATH}"
  log "installed ${SERVICE_PATH}"
  log "timer enabled. Inspect with:"
  log "  systemctl --user list-timers ${SERVICE_NAME}.timer"
  log "  journalctl --user -u ${SERVICE_NAME}.service -n 100"
}

uninstall_systemd() {
  systemctl --user disable --now "${SERVICE_NAME}.timer" 2>/dev/null || true
  rm -f -- "${TIMER_PATH}" "${SERVICE_PATH}"
  systemctl --user daemon-reload 2>/dev/null || true
  log "removed systemd user unit + timer."
}

# ─── cron backend ─────────────────────────────────────────────────────
# Crontab format: minute hour day-of-month month day-of-week command
CRON_LINE="17 4 * * * cd ${REPO_ROOT} && ${REPO_ROOT}/scripts/local-cron.sh >> \${HOME}/.cache/kaos-compliance-local-cron.log 2>&1 ${CRON_MARKER}"

install_cron() {
  local existing new
  existing="$(crontab -l 2>/dev/null || true)"
  # Strip any prior managed line, then append the fresh one.
  new="$(printf '%s\n' "${existing}" | grep -v -F "${CRON_MARKER}" || true)"
  if [[ -n "${new}" && "${new: -1}" != $'\n' ]]; then
    new="${new}"$'\n'
  fi
  new="${new}${CRON_LINE}"$'\n'
  printf '%s' "${new}" | crontab -
  log "crontab updated. Inspect with: crontab -l"
}

uninstall_cron() {
  local existing new
  existing="$(crontab -l 2>/dev/null || true)"
  new="$(printf '%s\n' "${existing}" | grep -v -F "${CRON_MARKER}" || true)"
  printf '%s' "${new}" | crontab -
  log "removed managed crontab line."
}

# ─── Dispatch ─────────────────────────────────────────────────────────
case "${BACKEND}:${ACTION}" in
  systemd:install)   install_systemd ;;
  systemd:uninstall) uninstall_systemd ;;
  cron:install)      install_cron ;;
  cron:uninstall)    uninstall_cron ;;
  *) die "unsupported backend/action: ${BACKEND}/${ACTION}" ;;
esac

log "done."
