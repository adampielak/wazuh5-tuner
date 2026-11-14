# Changelog

## 0.1.0 - 2026-11-14

- Web UI, `--check` and HTTP API for `/etc/wazuh-manager/wazuh-manager-internal-options.conf`, Wazuh 5.0.0-rc2.
- 255 options from the v5.0.0-rc2 source, kept only where the rc2 docs agree on the default; ranges narrowed to the docs where they are tighter.
- `--check` emulates the C reader (`validate_op.c`, first line wins) and the engine reader (`fileLoader.cpp`, last line wins).
- Rules across options: `remoted.verify_msg_id` vs `remoted.worker_pool`, task-manager delete vs scan timeout, inventory sync retry bounds, keepalive throttle, auth body size.
- `tools/fetch-rc2.sh` rebuilds `data/params.json` and the `PARAMS` block from the tag.
- Live test on a 5.0.0-rc2 single-node deployment: defaults, minimums, maximums, presets and failure cases (results in README).
