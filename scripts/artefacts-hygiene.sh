#!/usr/bin/env bash
# Mirror of easymonitoring ./playbook artefacts-check (runtime state + secrets).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ROOT="${EASYMONITORING_ROOT:-${ROOT}/../easymonitoring}"

if [[ -x "${DEV_ROOT}/playbook" ]]; then
  exec env EASYMONITORING_ARTEFACTS_ROOT="$ROOT" "${DEV_ROOT}/playbook" artefacts-check
fi

echo "[artefacts-hygiene] dev playbook not found; running standalone checks in ${ROOT}"

secret_hits=""
secret_hits="$(find "$ROOT" \
  \( -path '*/.git/*' -o -path '*/.git' \) -prune -o \
  \( -name '.env' -o -name '*.pem' -o -name '*.key' \) -print 2>/dev/null || true)"
if [[ -n "$secret_hits" ]]; then
  echo "ERROR: .env/pem/key found:"
  printf '  %s\n' "$secret_hits"
  exit 1
fi

python3 - "$ROOT" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
auth_name = re.compile(r"auth", re.I)
secret_fields = (
    "session_secret", "password_hash", "totp_secret",
    "peering_token", "previous_peering_token", "api_key", "api_keys",
)

def secret_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return bool(value)

def walk(node, prefix=""):
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in secret_fields and secret_value(value):
                yield path
            yield from walk(value, path)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            yield from walk(item, f"{prefix}[{idx}]")

errors = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or ".git" in path.parts:
        continue
    rel = path.relative_to(root).as_posix()
    name = path.name
    if auth_name.search(name) and name.endswith(".json"):
        errors.append(f"runtime auth state file: {rel}")
        continue
    if not name.endswith(".json"):
        continue
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    hits = list(walk(data))
    if hits:
        errors.append(f"secret fields in {rel}: {', '.join(hits[:5])}")

if errors:
    print("ERROR: runtime secrets/state in artefacts tree:", file=sys.stderr)
    for line in errors:
        print(f"  - {line}", file=sys.stderr)
    raise SystemExit(1)
PY

echo "artefacts-hygiene passed"
