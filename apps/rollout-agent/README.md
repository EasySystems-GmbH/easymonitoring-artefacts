## Installation
See [docs/install/rollout-agent.md](../../docs/install/rollout-agent.md) for Local, Azure hosted, and Swarm scenarios.


# Rollout agent — build orchestration

Agent **installers and artifacts** live under each monitor app:

| App | Full edition | Agent edition |
| --- | --- | --- |
| Unix | `apps/unix-monitor/deploy/full-version/` | `apps/unix-monitor/deploy/agent-installation/` |
| Synology | `apps/synology-monitor/deploy/full-version/` | `apps/synology-monitor/deploy/agent-installation/` |
| Windows | `apps/windows-monitor/deploy/full-installation/` | `apps/windows-monitor/deploy/agent-installation/` |

This folder provides:

- `scripts/patch-source.py` — bake `ROLLOUT_AGENT_BUILD=True` into agent artifacts; copies `src/` + `web/` beside each patched `*.py`
- `docker/` — Unix agent container (GHCR `unix-rollout-agent`)
- `build-all.sh` — local maintainer build (all platforms)

**Playbook:** `./playbook build-rollout` patches sources, builds SPK + Windows agent EXE, syncs **easymonitoring-artefacts**.

## Install URLs (easymonitoring-artefacts)

`PUBLIC_REPO=EasySystems-GmbH/easymonitoring-artefacts`

| Artifact | URL |
| --- | --- |
| Unix agent install | https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/deploy/agent-installation/install.sh |
| Unix rollout shim | https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/rollout-agent/unix/install-rollout.sh |
| Synology agent SPK | https://github.com/EasySystems-GmbH/easymonitoring-artefacts/releases/latest/download/synology-monitor-agent.spk |
| Docker compose | https://raw.githubusercontent.com/EasySystems-GmbH/easymonitoring-artefacts/main/apps/rollout-agent/docker-compose.yml |
| Releases | https://github.com/EasySystems-GmbH/easymonitoring-artefacts/releases |

Compatibility shims under `apps/rollout-agent/{unix,synology,windows}/` delegate to per-app `deploy/agent-installation/`; prefer the per-app URLs above in new docs.
