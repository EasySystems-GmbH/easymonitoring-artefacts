# Unix monitor — deployment

One `deploy/` folder per edition. **Full** and **agent** use the same installer; agent mode locks peering to `agent` (no standalone/master).

| Path | Edition | Contents |
| --- | --- | --- |
| `deploy/full-version/` | Full monitor | `install.sh`, `uninstall.sh`, `update-helper.sh` |
| `deploy/agent-installation/` | Rollout / fleet agent | `install.sh` (wraps full installer), `dist/{unix-monitor-agent.py,src/,web/}` (built artifacts) |

## Full monitor

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/install.sh" \
  | sudo env PUBLIC_REPO=EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts bash
```

Root `install.sh` is a compatibility shim → `deploy/full-version/install.sh`.

## Rollout agent

```bash
curl -fsSL "https://raw.githubusercontent.com/EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts/main/apps/unix-monitor/deploy/agent-installation/install.sh" \
  | sudo env PUBLIC_REPO=EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts bash
```

Same systemd + UI setup as full install; prompts only for master URL and peering token.

Docker agent image: see `apps/rollout-agent/docker/` (GHCR `unix-rollout-agent`).
