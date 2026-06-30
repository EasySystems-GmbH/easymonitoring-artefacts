# easymonitoring-artefacts

Public install payloads for the [EasyMonitoring](https://github.com/EasySystems-GmbH/easymonitoring) suite. This repo is populated from the dev repo via `./playbook sync-artefacts` (see sync contract below).

**Do not edit install payloads here by hand** — change source under `easymonitoring/apps/` and re-sync.

## PUBLIC_REPO

All curl/bash install scripts accept:

```bash
PUBLIC_REPO=EasySystems-GmbH/easymonitoring-artefacts
```

Raw content base URL:

```text
https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/
```

## Quick install (curl)

### Unix monitor (full install)

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/deploy/full-version/install.sh" \
  | sudo env PUBLIC_REPO=EasySystems-GmbH/easymonitoring-artefacts bash
```

### Unix monitor (agent-only)

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/deploy/agent-installation/install.sh" \
  | sudo env PUBLIC_REPO=EasySystems-GmbH/easymonitoring-artefacts bash
```

### Synology monitor

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/synology-monitor/deploy/full-version/install.sh" \
  | env PUBLIC_REPO=EasySystems-GmbH/easymonitoring-artefacts bash
```

Package Center feed (`packages.json`):

```text
https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/synology-monitor/community-package/repo/packages.json
```

### Rollout agent

See `apps/rollout-agent/` for per-platform agent-installation scripts after sync.

### Windows monitor

Published installers (when present after sync/build):

- `apps/windows-monitor/publish/fullinstall/` — full installer output
- `apps/windows-monitor/publish/rollout-agent/` — rollout agent EXE

Releases may also attach `.spk` / `.exe` assets: [GitHub Releases](https://github.com/EasySystems-GmbH/easymonitoring-artefacts/releases).

## Layout

```text
apps/
  unix-monitor/          # unix-monitor.py, web/, deploy/install scripts
  synology-monitor/      # synology-monitor.py, web/, community-package/
  rollout-agent/         # built agent dist + install scripts
  windows-monitor/       # optional published installers
```

`hosted-master` is **not** mirrored here — use GHCR images from the dev repo CI.

## Sync contract (easymonitoring → this repo)

Source command (run from `easymonitoring` repo root):

```bash
./playbook sync-artefacts          # copy payloads
./playbook sync-artefacts --dry-run # rsync dry-run (no writes; no builds required)
```

Target directory: `$EASYMONITORING_ARTEFACTS_ROOT` (default: sibling `../easymonitoring-artefacts`).

| Source (`easymonitoring/apps/…`) | Destination (`apps/…`) | Notes |
|----------------------------------|------------------------|-------|
| `unix-monitor/` | `unix-monitor/` | Entry script, `web/`, `deploy/`; excludes `.venv`, `__pycache__`, `state` |
| `synology-monitor/` | `synology-monitor/` | Entry script, `web/`, `community-package/`; excludes `.build` scratch |
| `synology-monitor/community-package/dist/*.spk` | same | Copied when SPK build output exists |
| `rollout-agent/` | `rollout-agent/` | Dist/install scripts; excludes local `dist` scratch |
| `windows-monitor/publish/` | `windows-monitor/publish/` | Optional EXE/installer outputs after `publish-full-installer.ps1` |

Hygiene gate before publish:

```bash
./playbook artefacts-check   # fails if `.env`, `*.pem`, `*.key` found in artefacts tree
```

## Releases

Tag releases in this repo after sync; attach large binaries (`.spk`, `.exe`) to GitHub Releases when appropriate. Install scripts resolve `PUBLIC_REPO` and may use `releases/latest` for versioned assets.
