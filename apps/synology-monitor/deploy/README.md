# Synology monitor — deployment

| Path | Edition | Contents |
| --- | --- | --- |
| `deploy/full-version/` | Full DSM package | `community-package/` (SPK build), `install.sh` (manual script install) |
| `deploy/agent-installation/` | Rollout agent SPK | `build-spk.sh`, `dist/{synology-monitor-agent.py,src/,web/,synology-package/,synology-monitor-agent.spk}` |

Root `install.sh` and `community-package/` are compatibility shims → `deploy/full-version/`.

## Full package

Build SPK: `deploy/full-version/community-package/build-spk.sh`

## Rollout agent SPK

Build: `deploy/agent-installation/build-spk.sh <version>`

Install on DSM: manual install of `dist/synology-monitor-agent.spk` — same package hooks as full edition, agent-only Python binary.
