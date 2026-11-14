#!/usr/bin/env bun
// Extract engine addUnit<T>(key::X, "ENV", default[, Range{lo,hi}]) and resolve key names from keys.hpp.
// Usage: bun engine.ts <conf-dir>
import { readFileSync } from "node:fs";
const dir = process.argv[2];
const keys = new Map<string, string>();
for (const m of readFileSync(`${dir}/include/conf/keys.hpp`, "utf8").matchAll(/(\w+)\s*=\s*"([^"]+)"/g)) keys.set(m[1], m[2]);
const src = readFileSync(`${dir}/src/conf.cpp`, "utf8").replace(/\/\/[^\n]*/g, "");
const out = [];
for (const m of src.matchAll(/addUnit<([^>]+?)>\s*\(([\s\S]*?)\);/g)) {
  const body = m[2].replace(/\s+/g, " ").trim();
  const k = body.match(/key::(\w+)/)?.[1];
  const env = body.match(/"(WAZUH_\w+)"/)?.[1];
  const rng = body.match(/Range\s*\{(.*)\}\s*$/)?.[1];
  const def = body.replace(/Range\s*\{.*\}\s*$/, "").split(",").slice(2).join(",").trim().replace(/,$/, "");
  out.push({ type: m[1].trim(), key: keys.get(k!) ?? k, env, def, range: rng });
}
console.log(JSON.stringify(out, null, 1));
