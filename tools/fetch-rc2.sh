#!/bin/sh
# Download a Wazuh tag and rebuild the parameter table from its source and docs.
# Usage: tools/fetch-rc2.sh [work-dir]   (TAG=v5.0.0-rc2 by default)
set -eu
TAG=${TAG:-v5.0.0-rc2}
OUT=${1:-work}
HERE=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$OUT/docs"
curl -fsSL "https://github.com/wazuh/wazuh/archive/refs/tags/$TAG.tar.gz" | tar -xz -C "$OUT"
SRC="$OUT/wazuh-${TAG#v}"

# Doc pages that describe manager internal options, flattened to one directory.
for p in configuration/manager/README.md configuration/manager/reference.md \
  modules/agent_info/configuration.md modules/agent_upgrade/configuration.md \
  modules/authd/configuration.md modules/database-sync/configuration.md modules/fim/README.md \
  modules/indexer_connector/configuration.md modules/inventory-sync-server/configuration.md \
  modules/remoted/configuration.md modules/remoted/timing-tuning.md modules/sca/README.md \
  modules/syscollector/README.md modules/task_manager/README.md \
  modules/task_manager/agent-upgrades.md modules/task_manager/configuration.md \
  modules/task_manager/manager-tasks.md modules/task_manager/schedules.md \
  modules/vulnerability-scanner/configuration.md modules/wazuh_db/configuration.md; do
  cp "$SRC/docs/ref/$p" "$OUT/docs/$(echo "$p" | tr / _)"
done
cp "$SRC/docs/ref/modules/engine/configuration.md" "$OUT/docs/engine-configuration.md"

bun "$HERE/extract-options.ts" "$SRC/src" > "$OUT/opts.json"
bun "$HERE/extract-engine.ts" "$SRC/src/engine/source/conf" > "$OUT/engine.json"
bun "$HERE/xcheck.ts" "$OUT/opts.json" "$OUT/docs" > "$OUT/xcheck.json"
bun "$HERE/build-params.ts" "$OUT/xcheck.json" "$OUT/engine.json" "$OUT/docs/engine-configuration.md"
