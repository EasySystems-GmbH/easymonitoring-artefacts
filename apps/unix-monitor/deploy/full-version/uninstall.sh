#!/bin/bash

set -euo pipefail

KNOWN_INSTALL_DIRS="/opt/unix-monitor /opt/unix-rollout-agent"
EASYSMONITOR_BIN="/usr/local/bin/easymonitor"
CRON_MARKER="unix-monitor.py - do not edit this line manually"

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN='' YELLOW='' RED='' BOLD='' NC=''
fi

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }

read_input() {
    read -r "$@" </dev/tty
}

dir_has_installation() {
    local dir="$1"
    [ -f "${dir}/unix-monitor.py" ] || [ -f "${dir}/unix-monitor-agent.py" ] || [ -f "${dir}/unix-monitor.json" ]
}

cleanup_all_edition_systemd_units() {
    local prefixes="unix-monitor unix-rollout-agent"
    local suffixes="ui.service scheduler.service scheduler.timer smart-helper.service smart-helper.timer backup-helper.service backup-helper.timer system-log-helper.service system-log-helper.timer"
    local prefix suffix unit
    for prefix in ${prefixes}; do
        for suffix in ${suffixes}; do
            unit="${prefix}-${suffix}"
            systemctl disable --now "${unit}" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${unit}"
        done
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
}

safe_rm_rf() {
    local target="$1"
    if [ -z "${target}" ] || [ "${target}" = "/" ]; then
        err "Refusing to remove unsafe path: '${target}'"
        return 1
    fi
    rm -rf "${target}"
}

echo ""
echo -e "${BOLD}Unix Monitor — Uninstaller${NC}"
echo "-------------------------------------"
echo ""

if [ "${EUID}" -ne 0 ]; then
    err "Please run as root (sudo)."
    exit 1
fi

FOUND_DIRS=""
for dir in ${KNOWN_INSTALL_DIRS}; do
    if dir_has_installation "${dir}"; then
        FOUND_DIRS="${FOUND_DIRS} ${dir}"
    fi
done
FOUND_DIRS="${FOUND_DIRS# }"

if [ -z "${FOUND_DIRS}" ]; then
    warn "No unix-monitor or rollout-agent installation detected under:"
    for dir in ${KNOWN_INSTALL_DIRS}; do
        echo "  - ${dir}"
    done
    echo -n "Custom install directory to remove (empty to abort): "
    read_input CUSTOM_DIR || true
    if [ -z "${CUSTOM_DIR:-}" ]; then
        echo "Aborted."
        exit 0
    fi
    FOUND_DIRS="${CUSTOM_DIR}"
fi

echo "Detected installation(s):"
for dir in ${FOUND_DIRS}; do
    echo "  - ${dir}"
done
echo ""
warn "This removes services/timers, install files, runtime state, cron entries, and easymonitor CLI."
echo -n "Continue? (y/N): "
read_input CONFIRM || true
if [[ ! "${CONFIRM:-n}" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

cleanup_all_edition_systemd_units
info "Stopped and removed systemd units for all editions."

for dir in ${FOUND_DIRS}; do
    if [ -d "${dir}" ]; then
        safe_rm_rf "${dir}"
        info "Removed install directory: ${dir}"
    else
        warn "Install directory not found: ${dir}"
    fi
done

if [ -d "/var/lib/unix-monitor" ]; then
    safe_rm_rf "/var/lib/unix-monitor"
    info "Removed runtime state: /var/lib/unix-monitor"
fi

if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
    if [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}/.config/unix-monitor" ]; then
        safe_rm_rf "${USER_HOME}/.config/unix-monitor"
        info "Removed user config: ${USER_HOME}/.config/unix-monitor"
    fi
fi

if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "/${CRON_MARKER//\//\\/}/d" | crontab - || true
    info "Removed cron entries with unix-monitor marker."
fi

if [ -f "${EASYSMONITOR_BIN}" ]; then
    rm -f "${EASYSMONITOR_BIN}"
    info "Removed ${EASYSMONITOR_BIN}"
fi

echo ""
info "Uninstall complete."
echo "-------------------------------------"
