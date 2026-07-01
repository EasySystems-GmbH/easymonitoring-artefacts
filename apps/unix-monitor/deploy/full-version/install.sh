#!/bin/bash

set -euo pipefail

PUBLIC_REPO="${PUBLIC_REPO:-EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts}"
BRANCH="main"
UPDATE_CHANNEL="${UNIX_MONITOR_UPDATE_CHANNEL:-}"
if [ "${UNIX_MONITOR_USE_MAIN:-0}" = "1" ]; then
    UPDATE_CHANNEL="main"
fi
if [ "${UPDATE_CHANNEL}" != "main" ] && [ "${UPDATE_CHANNEL}" != "latest" ]; then
    UPDATE_CHANNEL=""
fi
REF="${BRANCH}"

SCRIPT_NAME="unix-monitor.py"
SCRIPT_REMOTE_PATH="apps/unix-monitor/${SCRIPT_NAME}"
SCRIPT_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${SCRIPT_REMOTE_PATH}"
UNINSTALL_NAME="uninstall.sh"
UNINSTALL_REMOTE_PATH="apps/unix-monitor/${UNINSTALL_NAME}"
UNINSTALL_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${UNINSTALL_REMOTE_PATH}"
UPDATE_HELPER_NAME="update-helper.sh"
UPDATE_HELPER_REMOTE_PATH="apps/unix-monitor/${UPDATE_HELPER_NAME}"
UPDATE_HELPER_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${UPDATE_HELPER_REMOTE_PATH}"
SCRIPT_VERSION_REMOTE_PATH="apps/unix-monitor/unix-monitor.py"
DEFAULT_INSTALL_DIR="/opt/unix-monitor"
# Rollout agent edition: set UNIX_MONITOR_ROLLOUT_AGENT=1 (deploy/agent-installation/install.sh).
ROLLOUT_AGENT=0
if [ "${UNIX_MONITOR_ROLLOUT_AGENT:-0}" = "1" ]; then
    ROLLOUT_AGENT=1
    SCRIPT_NAME="${SCRIPT_NAME:-unix-monitor-agent.py}"
    DEFAULT_INSTALL_DIR="${DEFAULT_INSTALL_DIR:-/opt/unix-rollout-agent}"
    SCRIPT_REMOTE_PATH="${SCRIPT_REMOTE_PATH:-apps/unix-monitor/deploy/agent-installation/${SCRIPT_NAME}}"
    SCRIPT_VERSION_REMOTE_PATH="${SCRIPT_REMOTE_PATH}"
    SYSTEMD_PREFIX="unix-rollout-agent"
else
    SYSTEMD_PREFIX="unix-monitor"
fi
SYSTEMD_SERVICE_UI="${SYSTEMD_PREFIX}-ui.service"
SYSTEMD_SERVICE_SCHED="${SYSTEMD_PREFIX}-scheduler.service"
SYSTEMD_TIMER_SCHED="${SYSTEMD_PREFIX}-scheduler.timer"
SYSTEMD_SERVICE_SMART_HELPER="${SYSTEMD_PREFIX}-smart-helper.service"
SYSTEMD_TIMER_SMART_HELPER="${SYSTEMD_PREFIX}-smart-helper.timer"
SYSTEMD_SERVICE_BACKUP_HELPER="${SYSTEMD_PREFIX}-backup-helper.service"
SYSTEMD_TIMER_BACKUP_HELPER="${SYSTEMD_PREFIX}-backup-helper.timer"
SYSTEMD_SERVICE_SYSLOG_HELPER="${SYSTEMD_PREFIX}-system-log-helper.service"
SYSTEMD_TIMER_SYSLOG_HELPER="${SYSTEMD_PREFIX}-system-log-helper.timer"
KNOWN_INSTALL_DIRS="/opt/unix-monitor /opt/unix-rollout-agent"
EASYSMONITOR_BIN="/usr/local/bin/easymonitor"
RUN_DIAGNOSTICS=0

for arg in "$@"; do
    case "${arg}" in
        --diagnose|--diagnostics|--doctor|-d)
            RUN_DIAGNOSTICS=1
            ;;
        --help|-h)
            echo "Usage: bash install.sh [--diagnose]"
            echo "  --diagnose   Run installer diagnostics only (no install changes)"
            exit 0
            ;;
    esac
done

read_input() {
    read -r "$@" </dev/tty
}

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

normalize_master_base_url() {
    local raw="$1"
    raw="${raw%/}"
    if [[ "${raw}" != *://* ]]; then
        raw="http://${raw}"
    fi
    printf '%s' "${raw}"
}

test_master_connectivity() {
    local master_url="$1"
    local token="$2"
    local base code
    if ! command -v curl >/dev/null 2>&1; then
        warn "curl not available; skipping master connectivity check."
        return 0
    fi
    base="$(normalize_master_base_url "${master_url}")"
    info "Testing master connectivity (${base})..."
    code="$(curl -sS -m 10 -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${token}" \
        "${base}/api/peer/health" 2>/dev/null || echo "000")"
    if [ "${code}" = "200" ] || [ "${code}" = "204" ]; then
        info "Master connectivity OK (HTTP ${code})."
        return 0
    fi
    warn "Master connectivity check failed (HTTP ${code}). Verify master URL, port, and peering token."
    return 1
}

SYSTEM_LABEL="$(uname -s 2>/dev/null || echo Unix)"
APP_LABEL="${SYSTEM_LABEL} Kuma Monitor Addon"

run_diagnostics_session() {
    local install_dir="${UNIX_MONITOR_INSTALL_DIR:-${DEFAULT_INSTALL_DIR}}"
    local runtime_dir="/var/lib/unix-monitor"
    local config_path="${install_dir}/unix-monitor.json"
    local ts
    ts="$(date -u +%Y%m%d-%H%M%S)"
    local out_dir="${runtime_dir}/diagnostics"
    local report_file="${out_dir}/installer-diagnostics-${ts}.txt"
    local tmp_report
    tmp_report="$(mktemp)"

    log() {
        echo "$*" | tee -a "${tmp_report}"
    }

    log "=== ${APP_LABEL} installer diagnostics ==="
    log "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    log "host: $(hostname 2>/dev/null || echo unknown)"
    log "kernel: $(uname -a 2>/dev/null || echo unknown)"
    log "user: $(id -un 2>/dev/null || echo unknown) uid=$(id -u 2>/dev/null || echo unknown)"
    log ""

    log "[os-release]"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release 2>/dev/null | tee -a "${tmp_report}" >/dev/null
    else
        log "no /etc/os-release"
    fi
    log ""

    log "[python]"
    if command -v python3 >/dev/null 2>&1; then
        log "python3: $(command -v python3)"
        log "python3_version: $(python3 --version 2>&1)"
    else
        log "python3: not found"
    fi
    log ""

    log "[paths]"
    log "install_dir: ${install_dir} (exists=$([ -d "${install_dir}" ] && echo yes || echo no))"
    log "runtime_dir: ${runtime_dir} (exists=$([ -d "${runtime_dir}" ] && echo yes || echo no))"
    log "config_path: ${config_path} (exists=$([ -f "${config_path}" ] && echo yes || echo no))"
    log ""

    local ui_host="127.0.0.1"
    local ui_port="8787"
    local web_enabled="true"

    log "[config]"
    if [ -f "${config_path}" ]; then
        cat "${config_path}" 2>/dev/null | tee -a "${tmp_report}" >/dev/null || log "unable to read config"
        if command -v python3 >/dev/null 2>&1; then
            local cfg_triplet
            cfg_triplet="$(python3 - <<'PY' "${config_path}" 2>/dev/null || true
import json, sys
path = sys.argv[1]
host, port, web = "127.0.0.1", "8787", "true"
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    host = str(data.get("ui_host", host) or host)
    port = str(int(data.get("ui_port", int(port))))
    web = "true" if bool(data.get("web_enabled", True)) else "false"
except Exception:
    pass
print(f"{host}|{port}|{web}")
PY
)"
            if [ -n "${cfg_triplet}" ]; then
                IFS='|' read -r ui_host ui_port web_enabled <<EOF
${cfg_triplet}
EOF
            fi
        fi
    else
        log "no config file found"
    fi
    log "effective_ui_host: ${ui_host}"
    log "effective_ui_port: ${ui_port}"
    log "effective_web_enabled: ${web_enabled}"
    log ""

    if command -v systemctl >/dev/null 2>&1; then
        log "[systemd units]"
        local units=(
            "${SYSTEMD_SERVICE_UI}"
            "${SYSTEMD_SERVICE_SCHED}"
            "${SYSTEMD_TIMER_SCHED}"
            "${SYSTEMD_SERVICE_SMART_HELPER}"
            "${SYSTEMD_TIMER_SMART_HELPER}"
            "${SYSTEMD_SERVICE_BACKUP_HELPER}"
            "${SYSTEMD_TIMER_BACKUP_HELPER}"
            "${SYSTEMD_SERVICE_SYSLOG_HELPER}"
            "${SYSTEMD_TIMER_SYSLOG_HELPER}"
        )
        local unit
        for unit in "${units[@]}"; do
            local enabled active
            enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
            active="$(systemctl is-active "${unit}" 2>/dev/null || true)"
            [ -z "${enabled}" ] && enabled="unknown"
            [ -z "${active}" ] && active="unknown"
            log "${unit}: enabled=${enabled} active=${active}"
        done
        log ""
    else
        log "[systemd units]"
        log "systemctl not found"
        log ""
    fi

    log "[listeners:${ui_port}]"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn "sport = :${ui_port}" 2>/dev/null | tee -a "${tmp_report}" >/dev/null || log "ss probe failed"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk '$4 ~ /:'"${ui_port}"'$/ {print}' | tee -a "${tmp_report}" >/dev/null || log "netstat probe failed"
    else
        log "no ss/netstat available"
    fi
    log ""

    log "[http probes]"
    if command -v curl >/dev/null 2>&1; then
        local probe_urls=(
            "http://127.0.0.1:${ui_port}/health"
            "http://localhost:${ui_port}/health"
            "http://${ui_host}:${ui_port}/health"
            "http://127.0.0.1:${ui_port}/"
            "http://localhost:${ui_port}/"
            "http://${ui_host}:${ui_port}/"
        )
        local seen=""
        local url
        for url in "${probe_urls[@]}"; do
            if printf '%s\n' "${seen}" | awk -v u="${url}" '$0==u{found=1} END{exit(found?0:1)}'; then
                continue
            fi
            seen="${seen}
${url}"
            local code
            code="$(curl -sS -m 4 -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || echo "ERR")"
            log "${url} -> ${code}"
        done
    else
        log "curl not available"
    fi
    log ""

    log "[recent logs]"
    local log_files=(
        "${runtime_dir}/unix-monitor-ui.log"
        "${runtime_dir}/monitor-scheduler.log"
        "${runtime_dir}/smart-helper.log"
        "${runtime_dir}/backup-helper.log"
    )
    local lf
    for lf in "${log_files[@]}"; do
        if [ -f "${lf}" ]; then
            log "--- tail ${lf} ---"
            tail -n 20 "${lf}" 2>/dev/null | tee -a "${tmp_report}" >/dev/null || log "could not tail ${lf}"
        else
            log "--- missing ${lf} ---"
        fi
    done
    log ""

    if mkdir -p "${out_dir}" 2>/dev/null && cp "${tmp_report}" "${report_file}" 2>/dev/null; then
        info "Diagnostics report saved: ${report_file}"
    elif sudo mkdir -p "${out_dir}" 2>/dev/null && sudo cp "${tmp_report}" "${report_file}" 2>/dev/null; then
        info "Diagnostics report saved: ${report_file}"
    else
        local fallback="/tmp/unix-monitor-installer-diagnostics-${ts}.txt"
        cp "${tmp_report}" "${fallback}" 2>/dev/null || true
        warn "Could not write report under ${out_dir}; fallback: ${fallback}"
    fi

    rm -f "${tmp_report}" 2>/dev/null || true
    info "Diagnostics session complete."
}

prompt_diagnostics_next_action() {
    if [ ! -r /dev/tty ]; then
        echo "exit"
        return
    fi
    echo ""
    echo "Next step:"
    echo "  1) Rerun diagnostics"
    echo "  2) Continue with installer flow"
    echo "  3) Exit"
    echo -e "Choose next step [3]: \c"
    local choice
    read_input choice || true
    case "${choice:-3}" in
        1) echo "rerun" ;;
        2) echo "continue" ;;
        *) echo "exit" ;;
    esac
}

install_python() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                refresh_apt_index "for Python runtime"
                sudo apt-get install -y -qq python3
                ;;
            *) return 1 ;;
        esac
    else
        return 1
    fi
}

apt_pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"
}

apt_pkg_version() {
    local pkg="$1"
    dpkg-query -W -f='${Version}' "${pkg}" 2>/dev/null || echo "unknown"
}

APT_UPDATE_TIMEOUT_SEC=10

refresh_apt_index() {
    local reason="${1:-}"
    if [ -n "${reason}" ]; then
        info "Refreshing apt package index ${reason}..."
    else
        info "Refreshing apt package index..."
    fi
    if command -v timeout >/dev/null 2>&1; then
        if timeout "${APT_UPDATE_TIMEOUT_SEC}s" sudo apt-get update -qq >/dev/null 2>&1; then
            return 0
        fi
        local rc=$?
        if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
            warn "apt package index refresh exceeded ${APT_UPDATE_TIMEOUT_SEC}s; skipping refresh."
            return 0
        fi
        warn "apt package index refresh failed (exit ${rc}); continuing."
        return 0
    fi
    sudo apt-get update -qq >/dev/null 2>&1 || warn "apt package index refresh failed; continuing."
}

install_apt_packages() {
    local failed=0
    local pkg
    for pkg in "$@"; do
        if apt_pkg_installed "${pkg}"; then
            info "${pkg}: already installed ($(apt_pkg_version "${pkg}"))"
            continue
        fi
        warn "${pkg}: installing..."
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" >/dev/null; then
            info "${pkg}: installed ($(apt_pkg_version "${pkg}"))"
        else
            err "${pkg}: install failed"
            failed=1
        fi
    done
    return "${failed}"
}

install_smartmontools() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                refresh_apt_index
                install_apt_packages smartmontools
                ;;
            *) return 1 ;;
        esac
    else
        return 1
    fi
}

install_python_deps() {
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi

    deps_ok() {
        python3 - <<'PY' >/dev/null 2>&1
import importlib.util, sys
mods = ["pyotp", "qrcode", "werkzeug", "cryptography", "PIL"]
missing = [m for m in mods if importlib.util.find_spec(m) is None]
sys.exit(0 if not missing else 1)
PY
    }

    if deps_ok; then
        return 0
    fi

    # 1) Prefer distro packages on Debian/Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*)
                refresh_apt_index "for Python dependencies"
                local apt_pkgs=(
                    python3-pyotp
                    python3-qrcode
                    python3-pil
                    python3-werkzeug
                    python3-cryptography
                    python3-pip
                )
                install_apt_packages "${apt_pkgs[@]}" || true
                if deps_ok; then
                    info "Python UI/auth dependency check: OK (apt path)"
                    return 0
                fi
                ;;
        esac
    fi

    # 2) Fallback to pip (system-wide), including externally-managed Python setups
    if ! python3 -m pip --version >/dev/null 2>&1; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}${ID_LIKE:-}" in
                *debian*|*ubuntu*) sudo apt-get install -y -qq python3-pip >/dev/null 2>&1 || true ;;
            esac
        fi
    fi

    # Try with --break-system-packages first; fallback without for older pip.
    warn "Falling back to pip for missing Python dependencies..."
    sudo python3 -m pip install --upgrade pip --break-system-packages >/dev/null 2>&1 || sudo python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    sudo python3 -m pip install pyotp qrcode pillow werkzeug cryptography --break-system-packages >/dev/null 2>&1 || sudo python3 -m pip install pyotp qrcode pillow werkzeug cryptography >/dev/null 2>&1 || true

    if deps_ok; then
        info "Python UI/auth dependency check: OK (pip fallback path)"
        return 0
    fi
    return 1
}

cleanup_systemd_units() {
    local units=(
        "${SYSTEMD_SERVICE_UI}"
        "${SYSTEMD_SERVICE_SCHED}"
        "${SYSTEMD_TIMER_SCHED}"
        "${SYSTEMD_SERVICE_SMART_HELPER}"
        "${SYSTEMD_TIMER_SMART_HELPER}"
        "${SYSTEMD_SERVICE_BACKUP_HELPER}"
        "${SYSTEMD_TIMER_BACKUP_HELPER}"
        "${SYSTEMD_SERVICE_SYSLOG_HELPER}"
        "${SYSTEMD_TIMER_SYSLOG_HELPER}"
    )
    local unit
    for unit in "${units[@]}"; do
        sudo systemctl disable --now "${unit}" >/dev/null 2>&1 || true
        sudo rm -f "/etc/systemd/system/${unit}"
    done
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
}

cleanup_all_edition_systemd_units() {
    local prefixes="unix-monitor unix-rollout-agent"
    local suffixes="ui.service scheduler.service scheduler.timer smart-helper.service smart-helper.timer backup-helper.service backup-helper.timer system-log-helper.service system-log-helper.timer"
    local prefix suffix unit
    for prefix in ${prefixes}; do
        for suffix in ${suffixes}; do
            unit="${prefix}-${suffix}"
            sudo systemctl disable --now "${unit}" >/dev/null 2>&1 || true
            sudo rm -f "/etc/systemd/system/${unit}"
        done
    done
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
}

dir_has_installation() {
    local dir="$1"
    [ -f "${dir}/unix-monitor.py" ] || [ -f "${dir}/unix-monitor-agent.py" ] || [ -f "${dir}/unix-monitor.json" ]
}

discover_installation_dirs() {
    local found=""
    local dir
    for dir in ${KNOWN_INSTALL_DIRS}; do
        if dir_has_installation "${dir}"; then
            found="${found} ${dir}"
        fi
    done
    printf '%s' "${found# }"
}

uninstall_installation_at() {
    local target_dir="$1"
    if [ -z "${target_dir}" ] || [ "${target_dir}" = "/" ]; then
        err "Refusing to uninstall unsafe path: '${target_dir}'"
        return 1
    fi
    warn "Removing installation at ${target_dir}..."
    cleanup_all_edition_systemd_units
    safe_rm_rf "${target_dir}" || return 1
    safe_rm_rf "/var/lib/unix-monitor" || true
    if [ -n "${SUDO_USER:-}" ]; then
        USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
        if [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}/.config/unix-monitor" ]; then
            safe_rm_rf "${USER_HOME}/.config/unix-monitor" || true
        fi
    fi
    if crontab -l >/dev/null 2>&1; then
        crontab -l | sed "/unix-monitor.py - do not edit this line manually/d" | crontab - || true
    fi
    if [ -f "${EASYSMONITOR_BIN}" ]; then
        rm -f "${EASYSMONITOR_BIN}" 2>/dev/null || true
    fi
    info "Removed ${target_dir} and related services/state."
}

prompt_agent_peering() {
    MASTER_URL="${ESYS_MASTER_URL:-${UNIX_MONITOR_MASTER_URL:-${MASTER_URL:-}}}"
    PEER_TOKEN="${ESYS_PEERING_TOKEN:-${UNIX_MONITOR_PEERING_TOKEN:-${PEER_TOKEN:-}}}"
    if [ -z "${MASTER_URL}" ] || [ -z "${PEER_TOKEN}" ]; then
        echo -e "Hosted master URL (e.g. http://master-host:8080): \c"
        read_input MASTER_URL || true
        echo -e "Peering token (from master Settings): \c"
        read_input PEER_TOKEN || true
    else
        info "Using master URL and peering token from environment."
    fi
    if [ -z "${MASTER_URL}" ] || [ -z "${PEER_TOKEN}" ]; then
        err "Master URL and peering token are required for agent install."
        exit 1
    fi
    test_master_connectivity "${MASTER_URL}" "${PEER_TOKEN}" || true
}

prompt_rollout_webserver_mode() {
    local default_choice="${1:-1}"
    echo ""
    echo "Webserver mode (rollout agent):"
    echo "  1) Webserver + UI (local management + TOTP on first visit)"
    echo "  2) No-webserver (agent-only; use easymonitor CLI; peering required)"
    echo -e "Choose mode [${default_choice}]: \c"
    read_input MODE_CHOICE || true
    MODE_CHOICE="${MODE_CHOICE:-${default_choice}}"
    if [ "${MODE_CHOICE}" = "2" ]; then
        WEB_ENABLED="false"
        warn "NO-WEBSERVER MODE: UI and TOTP setup are skipped. Use 'easymonitor' for management."
        prompt_agent_peering
        return
    fi
    WEB_ENABLED="true"
    prompt_agent_peering
}

install_easymonitor_cli() {
    local install_dir="$1"
    local script_name="$2"
    local target_script="${install_dir}/${script_name}"
    if [ ! -f "${target_script}" ]; then
        warn "Skipping easymonitor CLI (script missing: ${target_script})"
        return 0
    fi
    sudo tee "${EASYSMONITOR_BIN}" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec python3 "${target_script}" --manage "\$@"
EOF
    sudo chmod 755 "${EASYSMONITOR_BIN}"
    info "Installed management CLI: ${EASYSMONITOR_BIN}"
}

safe_rm_rf() {
    local target="$1"
    if [ -z "${target}" ] || [ "${target}" = "/" ]; then
        err "Refusing to remove unsafe path: '${target}'"
        return 1
    fi
    sudo rm -rf "${target}"
}

json_get() {
    local file="$1"
    local key="$2"
    local default="$3"
    python3 - <<'PY' "${file}" "${key}" "${default}"
import json, sys
path, key, default = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    val = data.get(key, default)
except Exception:
    val = default
if isinstance(val, bool):
    print("true" if val else "false")
else:
    print(str(val))
PY
}

json_set_number() {
    local file="$1"
    local key="$2"
    local value="$3"
    python3 - <<'PY' "${file}" "${key}" "${value}"
import json, sys
path, key, value = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, encoding='utf-8') as f:
    data = json.load(f)
data[key] = value
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
PY
}

json_apply_install_settings() {
    local file="$1"
    python3 - <<'PY' "${file}" "${WEB_ENABLED}" "${PEER_ROLE}" "${MASTER_URL}" "${PEER_TOKEN}" "${SCHED_BACKEND}" "${SCHED_INTERVAL_MIN}"
import json, sys
path, web_enabled, peer_role, master_url, peer_token, sched_backend, sched_interval = sys.argv[1:8]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
data["web_enabled"] = web_enabled == "true"
data["peer_role"] = peer_role
data["peer_master_url"] = master_url
if peer_token:
    data["peering_token"] = peer_token
data["scheduler_backend"] = sched_backend
data["cron_interval_minutes"] = int(sched_interval)
data["agent_only_notice_ack"] = True
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY
}

print_install_summary() {
    local config_path="$1"
    local install_dir="$2"
    local script_name="$3"
    local target="$4"
    local uninstall_target="$5"
    python3 - <<'PY' "${config_path}" "${install_dir}" "${script_name}" "${target}" "${uninstall_target}"
import json, re, socket, sys, uuid
from urllib.parse import urlparse

config_path, install_dir, script_name, target, uninstall = sys.argv[1:6]
PEER_DEFAULT_PORT = 8787


def normalize_peer_port(raw, default=PEER_DEFAULT_PORT):
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def peer_master_port(cfg):
    legacy = normalize_peer_port(cfg.get("peer_port", PEER_DEFAULT_PORT))
    return normalize_peer_port(cfg.get("peer_master_port", legacy), legacy)


def peer_agent_port(cfg):
    legacy = normalize_peer_port(cfg.get("peer_port", PEER_DEFAULT_PORT))
    return normalize_peer_port(cfg.get("peer_agent_port", legacy), legacy)


def parse_peer_host_port(url_or_host, default_port=PEER_DEFAULT_PORT):
    s = str(url_or_host or "").strip().rstrip("/")
    if not s:
        return ("", default_port)
    parsed = urlparse(s if "://" in s else f"http://{s}")
    host = (parsed.hostname or parsed.path or s).strip()
    if not host:
        return ("", default_port)
    port = parsed.port if parsed.port is not None else default_port
    return (host, port)


def display_instance_id(instance_id):
    iid = str(instance_id or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", iid):
        lower = iid.lower()
        return f"{lower[0:8]}-{lower[8:12]}-{lower[12:16]}-{lower[16:20]}-{lower[20:32]}"
    return iid


try:
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)
except Exception:
    cfg = {}

if not str(cfg.get("instance_id", "") or "").strip():
    cfg["instance_id"] = str(uuid.uuid4())
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

instance_id = display_instance_id(cfg.get("instance_id", ""))
instance_name = str(cfg.get("instance_name", "") or socket.gethostname())
web_enabled = bool(cfg.get("web_enabled", True))
role = str(cfg.get("peer_role", "standalone") or "standalone").lower()
sched_backend = str(cfg.get("scheduler_backend", "systemd") or "systemd")
sched_interval = int(cfg.get("cron_interval_minutes", 1) or 1)
ui_port = int(cfg.get("ui_port", PEER_DEFAULT_PORT) or PEER_DEFAULT_PORT)
master_host, _ = parse_peer_host_port(cfg.get("peer_master_url", ""), peer_master_port(cfg))
master_port = peer_master_port(cfg)
cb_host, _ = parse_peer_host_port(cfg.get("agent_callback_url", ""), peer_agent_port(cfg))
agent_port = peer_agent_port(cfg)
if not cb_host:
    cb_host = socket.gethostname()
token = str(cfg.get("peering_token", "") or "").strip()
token_status = "configured" if token else "not set"

print("")
print("Configured:")
print(f"  Instance name:     {instance_name}")
print(f"  Config file:       {config_path}")
print(f"  Install directory: {install_dir}")
print(f"  Webserver mode:    {'enabled' if web_enabled else 'disabled (agent-only)'}")
if web_enabled:
    print(f"  Local UI port:     {ui_port}")
print(f"  Scheduler:         {sched_backend}, every {sched_interval} minute(s)")
print("")
print("Peering (for master registration):")
print(f"  Peering ID:        {instance_id}")
print("  (Use on hosted master: Settings -> Agents -> Add agent -> Peering ID)")
print(f"  Role:              {role}")
print(f"  Master host:       {master_host or '(not set — configure in Settings -> Peering)'}")
print(f"  Master port:       {master_port}")
print(f"  Agent callback:    {cb_host}:{agent_port}")
print(f"  Peering token:     {token_status}")

if role == "agent":
    if master_host and token:
        print("")
        print("Next steps on master:")
        print("  1. Add pending agent with Peering ID above")
        print("  2. Set fleet tags if needed")
        print("  3. Approve pairing — agent sync starts automatically")
    else:
        print("")
        print("Next steps:")
        print("  1. Set master host, ports, and peering token in Settings -> Peering")
        print("  2. Register Peering ID on the hosted master and approve pairing")
elif role == "standalone":
    print("")
    print("Peering note:")
    print("  Standalone mode — switch to agent role in Settings -> Peering when connecting to a master.")
    print("  Use Peering ID above when adding this host on the master.")
else:
    print("")
    print("Peering note:")
    print("  Master role — other agents connect to this host using their own Peering IDs.")

print("")
if web_enabled:
    print("Webserver mode:")
    print(f"  UI command: cd {install_dir} && python3 {script_name} --ui --host 0.0.0.0 --port {ui_port}")
    print(f"  Open:       http://<{cb_host}>:{ui_port}")
    print("  Peering role and endpoints can be changed in the UI or config.")
else:
    print("No-webserver mode:")
    print("  Agent-only menu: cd {install_dir} && python3 {script_name} --agent-menu")
    print("  A master connection is mandatory.")

print("")
print(f"Manual one-shot check: python3 {target} --run-scheduled")
print(f"Uninstall later:       sudo {uninstall}")
PY
}

prompt_webserver_mode() {
    local default_choice="${1:-1}"
    echo ""
    echo "Webserver mode:"
    echo "  1) Webserver mode (UI + local management, master/agent capable)"
    echo "  2) No-webserver mode (agent-only menu; master connection required)"
    echo -e "Choose mode [${default_choice}]: \c"
    read_input MODE_CHOICE || true
    MODE_CHOICE="${MODE_CHOICE:-${default_choice}}"

    if [ "${MODE_CHOICE}" = "2" ]; then
        WEB_ENABLED="false"
        PEER_ROLE="agent"
        echo ""
        warn "NO-WEBSERVER MODE SELECTED"
        warn "Functionality is reduced to menu-based monitor creation in agent mode only."
        warn "A master connection is required. Local UI is disabled."
        if [ -z "${MASTER_URL}" ] || [ -z "${PEER_TOKEN}" ]; then
            echo -e "Master URL (e.g. http://master-host:8787): \c"
            read_input MASTER_URL || true
            echo -e "Shared peering token: \c"
            read_input PEER_TOKEN || true
        else
            info "Keeping configured master URL and peering token."
        fi
        if [ -z "${MASTER_URL}" ] || [ -z "${PEER_TOKEN}" ]; then
            err "Master URL and peering token are required in no-webserver mode."
            exit 1
        fi
        test_master_connectivity "${MASTER_URL}" "${PEER_TOKEN}" || true
        return
    fi

    WEB_ENABLED="true"
    if [ "${PEER_ROLE}" = "agent" ] && [ -z "${MASTER_URL}" ] && [ -z "${PEER_TOKEN}" ]; then
        PEER_ROLE="standalone"
    fi
}

prompt_scheduler_settings() {
    if [ -n "${MIGRATE_FROM_LEGACY:-}" ]; then
        return
    fi
    echo ""
    echo "Scheduler backend:"
    echo "  1) systemd (recommended)"
    echo "  2) cron fallback"
    local sched_default="1"
    if [ "${SCHED_BACKEND}" = "cron" ]; then
        sched_default="2"
    fi
    echo -e "Choose scheduler [${sched_default}]: \c"
    read_input SCHED_CHOICE || true
    SCHED_CHOICE="${SCHED_CHOICE:-${sched_default}}"
    if [ "${SCHED_CHOICE}" = "2" ]; then
        SCHED_BACKEND="cron"
        SCHED_INTERVAL_MIN="5"
    else
        SCHED_BACKEND="systemd"
    fi
    echo -e "Scheduler interval in minutes [${SCHED_INTERVAL_MIN}]: \c"
    read_input SCHED_INTERVAL_INPUT || true
    if [ -n "${SCHED_INTERVAL_INPUT:-}" ]; then
        SCHED_INTERVAL_MIN="$(normalize_interval "${SCHED_INTERVAL_INPUT}")"
    fi
}

normalize_interval() {
    local raw="${1:-}"
    if ! [[ "${raw}" =~ ^[0-9]+$ ]]; then
        echo "1"
        return
    fi
    if [ "${raw}" -lt 1 ]; then
        echo "1"
        return
    fi
    if [ "${raw}" -gt 1440 ]; then
        echo "1440"
        return
    fi
    echo "${raw}"
}

resolve_ref_from_channel() {
    REF="${BRANCH}"
    if [ "${UPDATE_CHANNEL}" = "main" ]; then
        return 0
    fi
    local tag=""
    if command -v curl >/dev/null 2>&1; then
        tag=$(curl -sfL "https://api.github.com/repos/${PUBLIC_REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name":[[:space:]]*"[^"]*"' | sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/' | head -n 1)
    elif command -v wget >/dev/null 2>&1; then
        tag=$(wget -qO- "https://api.github.com/repos/${PUBLIC_REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name":[[:space:]]*"[^"]*"' | sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/' | head -n 1)
    fi
    [ -n "${tag}" ] && REF="${tag}"
}

refresh_download_urls() {
    SCRIPT_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${SCRIPT_REMOTE_PATH}"
    UNINSTALL_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${UNINSTALL_REMOTE_PATH}"
    UPDATE_HELPER_RAW_URL="https://raw.githubusercontent.com/${PUBLIC_REPO}/${REF}/${UPDATE_HELPER_REMOTE_PATH}"
}

install_support_dirs_from_local() {
    local src_root="$1"
    local dest_dir="$2"
    local name
    for name in src web; do
        if [ ! -d "${src_root}/${name}" ]; then
            err "Local support directory missing: ${src_root}/${name}"
            return 1
        fi
        rm -rf "${dest_dir:?}/${name}"
        cp -a "${src_root}/${name}" "${dest_dir}/${name}"
    done
    return 0
}

resolve_local_app_root() {
    if [ -n "${UNIX_MONITOR_LOCAL_APP_ROOT:-}" ] && [ -d "${UNIX_MONITOR_LOCAL_APP_ROOT}" ]; then
        printf '%s' "${UNIX_MONITOR_LOCAL_APP_ROOT}"
        return 0
    fi
    local installer_dir candidate
    installer_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ "${ROLLOUT_AGENT}" -eq 1 ]; then
        candidate="$(cd "${installer_dir}/.." && pwd)/dist"
        if [ -d "${candidate}/src" ] && [ -d "${candidate}/web" ]; then
            printf '%s' "${candidate}"
            return 0
        fi
    fi
    candidate="$(cd "${installer_dir}/../.." && pwd)"
    if [ -d "${candidate}/src" ] && [ -d "${candidate}/web" ]; then
        printf '%s' "${candidate}"
        return 0
    fi
    return 1
}

download_support_dirs() {
    local install_dir="$1"
    local remote_base="$2"
    local local_root=""
    if local_root="$(resolve_local_app_root)"; then
        if [ "${UNIX_MONITOR_FORCE_REMOTE:-0}" != "1" ]; then
            info "Installing src/ and web/ from local app tree (${local_root})..."
            install_support_dirs_from_local "${local_root}" "${install_dir}"
            return 0
        fi
    fi
    info "Downloading src/ and web/ support tree..."
    UNIX_MONITOR_INSTALL_DIR="${install_dir}" \
    UNIX_MONITOR_REMOTE_BASE="${remote_base}" \
    UNIX_MONITOR_PUBLIC_REPO="${PUBLIC_REPO}" \
    UNIX_MONITOR_REF="${REF}" \
    python3 <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

install_dir = Path(os.environ["UNIX_MONITOR_INSTALL_DIR"])
remote_base = os.environ["UNIX_MONITOR_REMOTE_BASE"].strip("/")
public_repo = os.environ["UNIX_MONITOR_PUBLIC_REPO"]
ref = os.environ["UNIX_MONITOR_REF"]

parts = public_repo.split("/")
if len(parts) < 2:
    print("ERROR: invalid PUBLIC_REPO", file=sys.stderr)
    sys.exit(1)
owner, repo = parts[0], parts[1]
repo_prefix = "/".join(parts[2:]) if len(parts) > 2 else ""


def api_list(path: str) -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "unix-monitor-installer"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    return data if isinstance(data, list) else [data]


def raw_url(rel: str) -> str:
    return f"https://raw.githubusercontent.com/{public_repo}/{ref}/{rel}"


def download_tree(api_path: str, rel_prefix: str) -> None:
    try:
        entries = api_list(api_path)
    except urllib.error.HTTPError as exc:
        print(f"ERROR: GitHub API {api_path}: {exc}", file=sys.stderr)
        sys.exit(1)
    for entry in entries:
        name = entry["name"]
        child_api = f"{api_path}/{name}"
        child_rel = f"{rel_prefix}/{name}"
        if entry.get("type") == "dir":
            download_tree(child_api, child_rel)
            continue
        dest = install_dir / child_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(raw_url(f"{remote_base}/{child_rel}"), timeout=60) as resp:
            dest.write_bytes(resp.read())


for support in ("src", "web"):
    api_path = f"{repo_prefix}/{remote_base}/{support}" if repo_prefix else f"{remote_base}/{support}"
    download_tree(api_path, support)
PY
}

validate_support_dirs() {
    local install_dir="$1"
    if [ ! -f "${install_dir}/src/core/auth/totp.py" ]; then
        err "Support tree incomplete: missing src/core/auth/totp.py"
        return 1
    fi
    if [ ! -d "${install_dir}/web" ]; then
        err "Support tree incomplete: missing web/"
        return 1
    fi
    return 0
}

install_support_payload() {
    local install_dir="$1"
    local remote_base="$2"
    if ! download_support_dirs "${install_dir}" "${remote_base}"; then
        return 1
    fi
    validate_support_dirs "${install_dir}"
}

detect_local_version() {
    local script_path="$1"
    if [ ! -f "${script_path}" ]; then
        echo ""
        return 0
    fi
    sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' "${script_path}" | head -n 1
}

fetch_public_version_for_ref() {
    local ref="$1"
    local url="https://raw.githubusercontent.com/${PUBLIC_REPO}/${ref}/${SCRIPT_VERSION_REMOTE_PATH}"
    local content=""
    local version=""
    if command -v curl >/dev/null 2>&1; then
        content="$(curl -fsSL "${url}" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        content="$(wget -qO- "${url}" 2>/dev/null || true)"
    fi
    version="$(printf '%s\n' "${content}" | sed -n 's/^VERSION = "\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -n "${version}" ]; then
        printf '%s\n' "${version}"
        return 0
    fi
    if [[ "${ref}" =~ ^v?[0-9]+(\.[0-9]+){1,3}([.-][0-9A-Za-z._-]+)?$ ]]; then
        printf '%s\n' "${ref#v}"
    fi
}

version_cmp() {
    local a="${1:-0}"
    local b="${2:-0}"
    python3 - "${a}" "${b}" <<'PY'
import re, sys
def to_parts(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")]
    return nums or [0]
a = to_parts(sys.argv[1])
b = to_parts(sys.argv[2])
n = max(len(a), len(b))
a += [0] * (n - len(a))
b += [0] * (n - len(b))
print(-1 if a < b else (1 if a > b else 0))
PY
}

echo ""
echo -e "${BOLD}${APP_LABEL} — Installer${NC}"
echo "mount + unix storage checks + peer master/agent mode"
echo "------------------------------------------------------"
echo ""

if [ "${RUN_DIAGNOSTICS}" = "1" ]; then
    while true; do
        run_diagnostics_session
        NEXT_ACTION="$(prompt_diagnostics_next_action)"
        case "${NEXT_ACTION}" in
            rerun)
                continue
                ;;
            continue)
                RUN_DIAGNOSTICS=0
                break
                ;;
            *)
                exit 0
                ;;
        esac
    done
fi

if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found."
    echo -e "Install python3 now? (y/N): \c"
    read_input INSTALL_PY || true
    if [[ "${INSTALL_PY:-n}" =~ ^[Yy]$ ]]; then
        if ! install_python; then
            err "Automatic python3 install failed."
            exit 1
        fi
    else
        err "python3 is required."
        exit 1
    fi
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "${PY_MAJOR}" -lt ${MIN_PYTHON_MAJOR} ] || { [ "${PY_MAJOR}" -eq ${MIN_PYTHON_MAJOR} ] && [ "${PY_MINOR}" -lt ${MIN_PYTHON_MINOR} ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required."
    exit 1
fi
info "Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') found"

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    err "curl or wget required."
    exit 1
fi

if [ -z "${MIGRATE_FROM_LEGACY:-}" ]; then
    if [ -n "${UNIX_MONITOR_INSTALL_DIR:-}" ]; then
        CUSTOM_DIR="${UNIX_MONITOR_INSTALL_DIR}"
        info "Install directory from UNIX_MONITOR_INSTALL_DIR: ${CUSTOM_DIR}"
    else
        echo -e "Install directory [${BOLD}${DEFAULT_INSTALL_DIR}${NC}]: \c"
        read_input CUSTOM_DIR || true
    fi
fi
INSTALL_DIR="${CUSTOM_DIR:-${DEFAULT_INSTALL_DIR}}"

if [ ! -d "${INSTALL_DIR}" ]; then
    warn "Directory ${INSTALL_DIR} does not exist."
    if [ -n "${MIGRATE_FROM_LEGACY:-}" ]; then
        sudo mkdir -p "${INSTALL_DIR}"
        sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"
        info "Created ${INSTALL_DIR}"
    else
        echo -e "Create it? (y/N): \c"
        read_input CREATE || true
        if [[ "${CREATE:-n}" =~ ^[Yy]$ ]]; then
            if [ -w "$(dirname "${INSTALL_DIR}")" ]; then
                mkdir -p "${INSTALL_DIR}"
            else
                sudo mkdir -p "${INSTALL_DIR}"
                sudo chown "$(id -u):$(id -g)" "${INSTALL_DIR}"
            fi
        else
            err "Aborted."
            exit 1
        fi
    fi
fi

if [ ! -w "${INSTALL_DIR}" ]; then
    err "No write permission to ${INSTALL_DIR}"
    exit 1
fi

REINSTALL_MODE="fresh"
EXISTING_INSTALL=0
if [ -f "${INSTALL_DIR}/${SCRIPT_NAME}" ] || [ -f "${INSTALL_DIR}/unix-monitor.json" ] || [ -d "/var/lib/unix-monitor" ]; then
    EXISTING_INSTALL=1
fi

if [ -z "${MIGRATE_FROM_LEGACY:-}" ]; then
    if [ ! -r /dev/tty ]; then
        err "Update source must be selected in the installer, but no interactive terminal (/dev/tty) is available."
        err "Use a real terminal (e.g. ssh -t user@host), or save the script and run: sudo bash install.sh"
        exit 1
    fi
    echo ""
    echo "Update source:"
    echo "  1) latest release"
    echo "  2) main branch (testing)"
    while :; do
        echo -e "Choose source (1 or 2): \c"
        read_input UPDATE_CHANNEL_CHOICE || true
        case "${UPDATE_CHANNEL_CHOICE:-}" in
            1) UPDATE_CHANNEL="latest"; break ;;
            2) UPDATE_CHANNEL="main"; break ;;
            *)
                warn "Selection required. Enter 1 (latest) or 2 (main)."
                ;;
        esac
    done
elif [ "${UPDATE_CHANNEL}" != "main" ] && [ "${UPDATE_CHANNEL}" != "latest" ]; then
    UPDATE_CHANNEL="latest"
fi
resolve_ref_from_channel
refresh_download_urls

LOCAL_VERSION="$(detect_local_version "${INSTALL_DIR}/${SCRIPT_NAME}")"
PUBLIC_VERSION="$(fetch_public_version_for_ref "${REF}")"
if [ -z "${PUBLIC_VERSION}" ] && [ "${REF}" != "main" ]; then
    warn "Selected ref ${REF} does not expose script VERSION metadata."
fi
echo ""
info "Selected update source: ${UPDATE_CHANNEL} (ref: ${REF})"
info "Local version: ${LOCAL_VERSION:-unknown}"
info "Public (${UPDATE_CHANNEL}) version: ${PUBLIC_VERSION:-unknown}"
if [ -n "${LOCAL_VERSION}" ] && [ -n "${PUBLIC_VERSION}" ]; then
    CMP_RESULT="$(version_cmp "${LOCAL_VERSION}" "${PUBLIC_VERSION}")"
    if [ "${CMP_RESULT}" -ge 0 ]; then
        info "Version check: local is up to date (or newer)."
    else
        warn "Version check: update available."
    fi
fi

if [ "${EXISTING_INSTALL}" -eq 1 ] && [ -z "${MIGRATE_FROM_LEGACY:-}" ]; then
    echo -e "Proceed with update/install from ${UPDATE_CHANNEL}? (Y/n): \c"
    read_input CONFIRM_UPDATE || true
    if [[ "${CONFIRM_UPDATE:-Y}" =~ ^[Nn]$ ]]; then
        err "Cancelled."
        exit 1
    fi
fi

if [ "${EXISTING_INSTALL}" -eq 1 ]; then
    echo ""
    warn "Existing installation detected."
    OTHER_INSTALLS="$(discover_installation_dirs)"
    if [ -n "${OTHER_INSTALLS}" ]; then
        info "Known install locations: ${OTHER_INSTALLS}"
    fi
    echo "  1) Reinstall and update, keep user data (recommended)"
    echo "  2) Full reinstall, keep nothing (delete config/state)"
    echo "  3) Uninstall all detected editions and exit"
    echo "  4) Cancel"
    echo -e "Choose reinstall mode [1]: \c"
    read_input REINSTALL_CHOICE || true
    REINSTALL_CHOICE="${REINSTALL_CHOICE:-1}"

    case "${REINSTALL_CHOICE}" in
        1)
            REINSTALL_MODE="preserve"
            info "Reinstall mode: keep user data + update binaries/services."
            ;;
        2)
            REINSTALL_MODE="fresh"
            warn "Reinstall mode: full reinstall, user data will be removed."
            ;;
        3)
            for other_dir in ${OTHER_INSTALLS}; do
                uninstall_installation_at "${other_dir}" || true
            done
            if [ -d "${INSTALL_DIR}" ] && dir_has_installation "${INSTALL_DIR}"; then
                uninstall_installation_at "${INSTALL_DIR}" || true
            fi
            info "Uninstall complete."
            exit 0
            ;;
        *)
            err "Cancelled by user."
            exit 1
            ;;
    esac

    info "Stopping/removing existing systemd units..."
    cleanup_all_edition_systemd_units

    if [ "${REINSTALL_MODE}" = "fresh" ]; then
        warn "Removing existing install directory and runtime state..."
        safe_rm_rf "${INSTALL_DIR}" || exit 1
        safe_rm_rf "/var/lib/unix-monitor" || exit 1
        if [ -n "${SUDO_USER:-}" ]; then
            USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
            if [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}" ]; then
                safe_rm_rf "${USER_HOME}/.config/unix-monitor" || true
            fi
        fi
        mkdir -p "${INSTALL_DIR}"
    fi
fi

TARGET="${INSTALL_DIR}/${SCRIPT_NAME}"
UNINSTALL_TARGET="${INSTALL_DIR}/${UNINSTALL_NAME}"
UPDATE_HELPER_TARGET="${INSTALL_DIR}/${UPDATE_HELPER_NAME}"
APP_REMOTE_BASE="$(dirname "${SCRIPT_REMOTE_PATH}")"

do_downloads() {
    info "Downloading ${SCRIPT_NAME}..."
    if [ "${DOWNLOADER}" = "curl" ]; then
        curl -fsSL "${SCRIPT_RAW_URL}" -o "${TARGET}"
    else
        wget -qO "${TARGET}" "${SCRIPT_RAW_URL}"
    fi

    info "Downloading ${UNINSTALL_NAME}..."
    if [ "${DOWNLOADER}" = "curl" ]; then
        curl -fsSL "${UNINSTALL_RAW_URL}" -o "${UNINSTALL_TARGET}"
    else
        wget -qO "${UNINSTALL_TARGET}" "${UNINSTALL_RAW_URL}"
    fi

    info "Downloading ${UPDATE_HELPER_NAME}..."
    if [ "${DOWNLOADER}" = "curl" ]; then
        curl -fsSL "${UPDATE_HELPER_RAW_URL}" -o "${UPDATE_HELPER_TARGET}"
    else
        wget -qO "${UPDATE_HELPER_TARGET}" "${UPDATE_HELPER_RAW_URL}"
    fi
}

if ! do_downloads; then
    if [ "${REF}" != "${BRANCH}" ]; then
        warn "Release ${REF} missing unix-monitor addon, falling back to main branch."
        REF="${BRANCH}"
        refresh_download_urls
        do_downloads
    else
        err "Download failed."
        exit 1
    fi
fi

if ! install_support_payload "${INSTALL_DIR}" "${APP_REMOTE_BASE}"; then
    if [ "${REF}" != "${BRANCH}" ]; then
        warn "Release ${REF} missing src/web support tree, falling back to main branch."
        REF="${BRANCH}"
        refresh_download_urls
        do_downloads || { err "Download failed."; exit 1; }
        install_support_payload "${INSTALL_DIR}" "${APP_REMOTE_BASE}" || { err "Support tree install failed."; exit 1; }
    else
        err "Support tree install failed."
        exit 1
    fi
fi

if [ ! -s "${TARGET}" ] || [ ! -s "${UNINSTALL_TARGET}" ] || [ ! -s "${UPDATE_HELPER_TARGET}" ]; then
    err "Download failed."
    exit 1
fi
UPDATE_HELPER_FIRST="$(sed -n '1p' "${UPDATE_HELPER_TARGET}")"
if [[ "${UPDATE_HELPER_FIRST}" != "#!/bin/bash"* ]]; then
    err "Downloaded update-helper is not the expected script."
    rm -f "${TARGET}" "${UNINSTALL_TARGET}" "${UPDATE_HELPER_TARGET}"
    exit 1
fi
chmod 700 "${UPDATE_HELPER_TARGET}"
FIRST_LINE="$(sed -n '1p' "${TARGET}")"
if [[ "${FIRST_LINE}" != "#!/usr/bin/env python3"* ]]; then
    err "Downloaded launcher is not the expected script."
    rm -f "${TARGET}" "${UNINSTALL_TARGET}" "${UPDATE_HELPER_TARGET}"
    exit 1
fi
UNINSTALL_FIRST_LINE="$(sed -n '1p' "${UNINSTALL_TARGET}")"
if [[ "${UNINSTALL_FIRST_LINE}" != "#!/bin/bash"* ]]; then
    err "Downloaded uninstaller is not the expected script."
    rm -f "${TARGET}" "${UNINSTALL_TARGET}" "${UPDATE_HELPER_TARGET}"
    exit 1
fi
chmod 700 "${TARGET}" "${UNINSTALL_TARGET}"
info "Installed to ${INSTALL_DIR}"

if [ "${EXISTING_INSTALL}" -eq 1 ] || [ -n "${MIGRATE_FROM_LEGACY:-}" ]; then
    info "Auto-installing dependencies without prompts."
    if install_smartmontools; then
        info "smartmontools installed."
    else
        warn "Could not auto-install smartmontools. Install manually for SMART checks."
    fi
else
    echo -e "Install smartctl dependency (smartmontools)? (Y/n): \c"
    read_input INSTALL_SMART || true
    if [[ ! "${INSTALL_SMART:-Y}" =~ ^[Nn]$ ]]; then
        if install_smartmontools; then
            info "smartmontools installed."
        else
            warn "Could not auto-install smartmontools. Install manually for SMART checks."
        fi
    fi
fi

echo ""
echo -e "${BOLD}Setup choice:${NC}"
CONFIG_PATH="${INSTALL_DIR}/unix-monitor.json"
WEB_ENABLED="true"
PEER_ROLE="standalone"
MASTER_URL=""
PEER_TOKEN=""
SCHED_BACKEND="systemd"
SCHED_INTERVAL_MIN="1"
PRESERVE_CONFIG_UPDATE=0

if [ "${REINSTALL_MODE}" = "preserve" ] && [ -f "${CONFIG_PATH}" ]; then
    info "Preserving existing unix-monitor user data and configuration."
    WEB_ENABLED="$(json_get "${CONFIG_PATH}" "web_enabled" "true")"
    PEER_ROLE="$(json_get "${CONFIG_PATH}" "peer_role" "standalone")"
    MASTER_URL="$(json_get "${CONFIG_PATH}" "peer_master_url" "")"
    PEER_TOKEN="$(json_get "${CONFIG_PATH}" "peering_token" "")"
    SCHED_BACKEND="$(json_get "${CONFIG_PATH}" "scheduler_backend" "systemd")"
    SCHED_INTERVAL_MIN="$(normalize_interval "$(json_get "${CONFIG_PATH}" "cron_interval_minutes" "5")")"
    if [ "${SCHED_BACKEND}" != "cron" ]; then
        SCHED_BACKEND="systemd"
    fi
    DEFAULT_MODE_CHOICE="1"
    if [ "${WEB_ENABLED}" != "true" ]; then
        DEFAULT_MODE_CHOICE="2"
    fi
    CURRENT_MODE_LABEL="webserver enabled"
    if [ "${WEB_ENABLED}" != "true" ]; then
        CURRENT_MODE_LABEL="webserver disabled (agent-only)"
    fi
    info "Current mode: ${CURRENT_MODE_LABEL}"
    prompt_webserver_mode "${DEFAULT_MODE_CHOICE}"
    prompt_scheduler_settings
    PRESERVE_CONFIG_UPDATE=1
else
    MIGRATE_FROM_LEGACY="${MIGRATE_FROM_LEGACY:-}"
    if [ "${UNIX_MONITOR_ROLLOUT_AGENT:-0}" = "1" ]; then
        info "Rollout agent install — role locked to agent (no standalone/master)."
        PEER_ROLE="agent"
        if [ "${ESYS_WEB_ENABLED:-}" = "0" ] || [ "${ESYS_WEB_ENABLED:-}" = "false" ]; then
            WEB_ENABLED="false"
            prompt_agent_peering
        elif [ "${ESYS_WEB_ENABLED:-}" = "1" ] || [ "${ESYS_WEB_ENABLED:-}" = "true" ]; then
            WEB_ENABLED="true"
            prompt_agent_peering
        else
            prompt_rollout_webserver_mode "1"
        fi
        prompt_scheduler_settings
    elif [ -n "${MIGRATE_FROM_LEGACY}" ]; then
        info "Migration from ${MIGRATE_FROM_LEGACY}: using defaults (webserver + systemd)."
        MODE_CHOICE="1"
    else
        prompt_webserver_mode "1"
    fi

    if [ "${UNIX_MONITOR_ROLLOUT_AGENT:-0}" = "1" ]; then
        :
    elif [ -z "${MIGRATE_FROM_LEGACY:-}" ]; then
        prompt_scheduler_settings
    else
        SCHED_CHOICE="1"
        SCHED_INTERVAL_INPUT=""
        SCHED_BACKEND="systemd"
        SCHED_INTERVAL_MIN="1"
    fi

    cat > "${CONFIG_PATH}" <<EOF
{
  "instance_name": "$(hostname)",
  "monitors": [],
  "debug": false,
  "cron_enabled": false,
  "cron_interval_minutes": ${SCHED_INTERVAL_MIN},
  "peer_role": "${PEER_ROLE}",
  "peer_master_url": "${MASTER_URL}",
  "peering_token": "${PEER_TOKEN}",
  "peer_port": 8787,
  "web_enabled": ${WEB_ENABLED},
  "ui_host": "0.0.0.0",
  "ui_port": 8787,
  "scheduler_backend": "${SCHED_BACKEND}",
  "agent_only_notice_ack": true
}
EOF
    chmod 600 "${CONFIG_PATH}"
    info "Created config: ${CONFIG_PATH}"
fi

# Merge migrated monitors from deprecated addons (mount-monitor, unix-storage-monitor)
if [ -n "${MIGRATE_MONITORS:-}" ] && [ -f "${MIGRATE_MONITORS}" ] && [ -f "${CONFIG_PATH}" ]; then
    python3 - "${CONFIG_PATH}" "${MIGRATE_MONITORS}" <<'PY'
import json, sys
from pathlib import Path
cfg_path, mig_path = Path(sys.argv[1]), Path(sys.argv[2])
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
mig = json.loads(mig_path.read_text(encoding="utf-8"))
monitors = mig.get("monitors", [])
cfg.setdefault("monitors", []).extend(monitors)
if "cron_interval_minutes" in mig:
    cfg["cron_interval_minutes"] = mig["cron_interval_minutes"]
if "cron_enabled" in mig:
    cfg["cron_enabled"] = mig["cron_enabled"]
cfg_path.write_text(json.dumps(cfg, indent=2))
print(f"Merged {len(monitors)} migrated monitor(s).")
PY
    info "Merged migrated monitors from legacy addon."
fi

if [ "${PRESERVE_CONFIG_UPDATE}" -eq 1 ] && [ -f "${CONFIG_PATH}" ]; then
    json_apply_install_settings "${CONFIG_PATH}"
    info "Updated preserved configuration (webserver mode, scheduler, peering)."
fi

if [ "${WEB_ENABLED}" = "true" ]; then
    if [ "${EXISTING_INSTALL}" -eq 1 ] || [ -n "${MIGRATE_FROM_LEGACY:-}" ]; then
        if install_python_deps; then
            info "Python UI/auth dependencies installed."
        else
            warn "Could not install all Python UI/auth dependencies."
        fi
    else
        echo -e "Install Python UI/auth dependencies (pyotp, qrcode, pillow, werkzeug, cryptography)? (Y/n): \c"
        read_input INSTALL_PY_DEPS || true
        if [[ ! "${INSTALL_PY_DEPS:-Y}" =~ ^[Nn]$ ]]; then
            if install_python_deps; then
                info "Python UI/auth dependencies installed."
            else
                warn "Could not install all Python UI/auth dependencies."
            fi
        fi
    fi
else
    info "No-webserver mode: skipped UI/auth Python dependencies (TOTP/UI not used)."
fi

if [ "${SCHED_BACKEND}" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
    info "Installing systemd units (requires sudo)..."
    UI_UNIT_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_UI}"
    SCHED_UNIT_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SCHED}"
    TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SCHED}"
    SMART_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SMART_HELPER}"
    SMART_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SMART_HELPER}"
    BACKUP_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_BACKUP_HELPER}"
    BACKUP_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_BACKUP_HELPER}"
    SYSLOG_HELPER_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_SYSLOG_HELPER}"
    SYSLOG_HELPER_TIMER_PATH="/etc/systemd/system/${SYSTEMD_TIMER_SYSLOG_HELPER}"

    if [ "${WEB_ENABLED}" = "true" ]; then
        sudo tee "${UI_UNIT_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --ui --host 0.0.0.0 --port 8787
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    fi

    sudo tee "${SCHED_UNIT_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} Scheduled Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-scheduled
EOF

    sudo tee "${SMART_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} SMART Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-smart-helper
EOF

    sudo tee "${SMART_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} SMART helper every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${BACKUP_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} Backup Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-backup-helper
EOF

    sudo tee "${BACKUP_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} backup helper every 5 minutes

[Timer]
OnBootSec=4min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${SYSLOG_HELPER_SERVICE_PATH}" >/dev/null <<EOF
[Unit]
Description=${APP_LABEL} System Log Helper Cache Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(command -v python3) ${TARGET} --run-system-log-helper
EOF

    sudo tee "${SYSLOG_HELPER_TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} system-log helper every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee "${TIMER_PATH}" >/dev/null <<EOF
[Unit]
Description=Run ${APP_LABEL} checks every ${SCHED_INTERVAL_MIN} minute(s)

[Timer]
OnBootSec=2min
# OnUnitInactiveSec (not OnUnitActiveSec): schedule from when the oneshot *finished*.
# OnUnitActiveSec with Type=oneshot can strand the timer (elapsed / empty next realtime on some systemd versions).
OnUnitInactiveSec=${SCHED_INTERVAL_MIN}min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    if [ "${WEB_ENABLED}" = "true" ]; then
        sudo systemctl enable --now "${SYSTEMD_SERVICE_UI}"
    else
        sudo systemctl disable --now "${SYSTEMD_SERVICE_UI}" 2>/dev/null || true
    fi
    sudo systemctl enable --now "${SYSTEMD_TIMER_SCHED}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_SMART_HELPER}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_BACKUP_HELPER}"
    sudo systemctl enable --now "${SYSTEMD_TIMER_SYSLOG_HELPER}"
    # Without this, a reinstall while the machine has been up for a while can leave no run for a long time:
    # OnBootSec is from *boot*, not from install; OnUnitInactiveSec only applies after a prior service run.
    sudo systemctl start "${SYSTEMD_SERVICE_SCHED}" 2>/dev/null || true
    info "systemd services enabled (scheduler oneshot started once to prime the timer)."
elif [ "${SCHED_BACKEND}" = "cron" ]; then
    info "Config set to cron fallback. Enable cron schedule from script menu."
fi

echo ""
echo "------------------------------------------------------"
echo -e "${GREEN}${BOLD}Installation complete.${NC}"
print_install_summary "${CONFIG_PATH}" "${INSTALL_DIR}" "${SCRIPT_NAME}" "${TARGET}" "${UNINSTALL_TARGET}"
install_easymonitor_cli "${INSTALL_DIR}" "${SCRIPT_NAME}"
echo "------------------------------------------------------"
