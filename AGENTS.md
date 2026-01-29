# Agent Instructions

## Dev Container Rebuild Script
Use this when Dockerfile or Python-related files change and the dev container must be rebuilt.

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP_FILE="$ROOT_DIR/.dev-rebuild.stamp"

watch_paths=(
  "$ROOT_DIR/Dockerfile"
  "$ROOT_DIR/requirements.txt"
  "$ROOT_DIR"/*.py
)

latest_change=0
for path in "${watch_paths[@]}"; do
  if [[ -e "$path" ]]; then
    mtime=$(stat -c %Y "$path")
    if (( mtime > latest_change )); then
      latest_change=$mtime
    fi
  fi
 done

stamp_time=0
if [[ -e "$STAMP_FILE" ]]; then
  stamp_time=$(stat -c %Y "$STAMP_FILE")
fi

if (( latest_change > stamp_time )); then
  echo "Rebuilding dev container (Dockerfile/Python changes detected)..."
  (cd "$ROOT_DIR" && docker compose --profile proxy up -d --build pki-app)
  touch "$STAMP_FILE"
else
  echo "No important changes detected."
fi
```

Notes:
- Adjust the compose profile/service if you use `standalone` instead of `proxy`.
- Run from repo root or leave as-is; the script resolves its own directory.
