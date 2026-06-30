## Installation
See [docs/install/unix-monitor.md](../../docs/install/unix-monitor.md) for Local, Azure hosted, and Swarm scenarios.


# Unix Monitor

## Start Here

- Entry point: `apps/unix-monitor/`
- Docs folder: `docs/apps/unix-monitor/`
- Tutorial: `docs/apps/unix-monitor/tutorial.md`

- Screenshot Preview Page: [`docs/screenshots/monitor/README.md`](../../docs/screenshots/monitor/README.md)
Unix monitor addon with Synology-grade runtime complexity adapted for generic Unix hosts.

It combines:
- mount checks (`mount-monitor` behavior)
- SMART/storage checks (`unix-storage-monitor` behavior)
- full web UI/auth/session flow
- helper-cache jobs + scheduler state
- master/agent peering APIs and remote monitor creation

Runtime name is generated from system info:
- `<RunningSystem> Kuma Monitor Addon`

## Quick Install

Browse sources: [apps/unix-monitor on GitHub](https://github.com/EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts/tree/main/apps/unix-monitor).

Use an **interactive** terminal (`ssh -t user@host`, or a local console). The installer prompts for the update channel and needs `/dev/tty`.

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/install.sh" \
  | sudo env PUBLIC_REPO=EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts bash
```

`-f` stops the download on HTTP errors so a failed fetch is not piped silently into `bash`.

## Installer Diagnostics (Unix only)

To run a diagnostics-only session (no install changes), save the installer and pass `--diagnose`:

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/install.sh" -o install-unix-monitor.sh
sudo bash install-unix-monitor.sh --diagnose
```

The report is written to `/var/lib/unix-monitor/diagnostics/installer-diagnostics-<timestamp>.txt` (fallback: `/tmp/...`).

## Architecture

- Architecture document: `apps/unix-monitor/ARCHITECTURE.md`
- Diagram image: `apps/unix-monitor/unix-monitor-architecture.png`

## Setup Modes

### Webserver mode
- Starts local UI (`--ui`) and scheduler
- Full local management (auth, monitor CRUD, diagnostics)
- Supports `standalone`, `master`, `agent`

### No-webserver mode (agent-only)
- Explicitly enforced as `peer_role=agent`
- Requires `peer_master_url` + `peering_token`
- Local UI is disabled
- Menu-based monitor management only
- Master connection is mandatory

## Check Modes

- `mount`
- `smart`
- `storage`
- `ping`
- `port`
- `dns`
- `backup` (best-effort on non-Synology systems)
- `service`

## Commands

```bash
python3 unix-monitor.py
python3 unix-monitor.py --run
python3 unix-monitor.py --run -d
python3 unix-monitor.py --ui --host 0.0.0.0 --port 8787
python3 unix-monitor.py --run-scheduled
python3 unix-monitor.py --run-scheduled-loop
python3 unix-monitor.py --run-smart-helper
python3 unix-monitor.py --run-backup-helper
python3 unix-monitor.py --run-system-log-helper
```

## Uninstall

The installer downloads an uninstaller into the install directory:

```bash
sudo /opt/unix-monitor/uninstall.sh
```

## Dependencies

Required:
- `python3` 3.8+
- `crontab`

Recommended:
- `smartctl` (`smartmontools`)
- Python packages: `pyotp`, `qrcode`, `pillow`, `werkzeug`, `cryptography`

## Notes

- Some backup/storage helper details are platform-specific; on generic Unix these run in fallback mode where Synology-only tooling is unavailable.
- Installer supports systemd by default and cron fallback.

## Packaging layout (§9)

Runtime requires the entry script plus colocated `src/` and `web/` trees (TOTP and web assets import from `src/core/auth/` and `web/styles/`). The installer downloads or copies all three into the install directory (default `/opt/unix-monitor`).

Published artefacts layout under `easymonitoring-artefacts`:

```
apps/unix-monitor/
  unix-monitor.py
  src/
  web/
  install.sh
  uninstall.sh
  update-helper.sh
  deploy/agent-installation/
    unix-monitor-agent.py
    src/
    web/
```

Agent rollout installs use `deploy/agent-installation/` paths; full edition uses the app root paths above.
