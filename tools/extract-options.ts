#!/usr/bin/env bun
// Extract getDefine_Int_default(section, name, min, max, default) calls from a Wazuh source tree.
// Usage: bun extract-options.ts <wazuh-src-root>  -> JSON array on stdout
// Literal args are parsed; macro or expression args are kept as text with resolved=false.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.argv[2];
if (!root) throw new Error("usage: extract-options.ts <src-root>");

function* walk(dir: string): Generator<string> {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      if (/^(unit_tests|tests?|external)$/.test(e)) continue;
      yield* walk(p);
    } else if (/\.(c|cpp)$/.test(e)) yield p;
  }
}

// Split the argument list at top-level commas, starting right after the opening parenthesis.
function args(src: string, start: number): { list: string[]; end: number } | undefined {
  let depth = 1, cur = "", list: string[] = [], inStr = false;
  for (let i = start; i < src.length; i++) {
    const ch = src[i];
    if (inStr) { cur += ch; if (ch === "\\") { cur += src[++i]; } else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { inStr = true; cur += ch; continue; }
    if (ch === "(") depth++;
    if (ch === ")" && --depth === 0) { list.push(cur.trim()); return { list, end: i }; }
    if (ch === "," && depth === 1) { list.push(cur.trim()); cur = ""; continue; }
    cur += ch;
  }
}

const str = (s: string) => (/^"([^"]*)"$/.test(s) ? s.slice(1, -1) : undefined);

// Object-like #define NAME <value> from every .h/.c in the tree (first definition wins; conflicts recorded).
const defines = new Map<string, string>(), conflicts = new Set<string>();
function* walkAll(dir: string): Generator<string> {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) { if (!/^(unit_tests|tests?|external)$/.test(e)) yield* walkAll(p); }
    else if (/\.(c|h|cpp|hpp)$/.test(e)) yield p;
  }
}
for (const f of walkAll(root)) {
  for (const m of readFileSync(f, "utf8").matchAll(/^[ \t]*#[ \t]*define[ \t]+([A-Z_][A-Z0-9_]*)[ \t]+([^\n/]+?)[ \t]*(?:\/[\/*].*)?$/gm)) {
    const prev = defines.get(m[1]);
    if (prev === undefined) defines.set(m[1], m[2]);
    else if (prev !== m[2]) conflicts.add(m[1]);
  }
}
defines.set("INT_MAX", "2147483647");

// Integer value of a C constant expression made of literals, known macros, + - * / << and parentheses.
function num(s: string, depth = 0): number | undefined {
  if (depth > 8) return undefined;
  let e = s.replace(/\s+/g, "");
  for (let i = 0; i < 8 && /[A-Z_]/.test(e); i++) {
    e = e.replace(/[A-Z_][A-Z0-9_]*/g, (id) => (conflicts.has(id) || !defines.has(id) ? id : `(${defines.get(id)})`)).replace(/\s+/g, "");
  }
  e = e.replace(/\b(\d+)[uUlL]+\b/g, "$1").replace(/\((?:unsigned|int|long|size_t|time_t)\)/g, "");
  if (!/^[\d()+\-*/<x a-fA-F]+$/.test(e) || /[a-wyzA-WYZ]/.test(e.replace(/0x[0-9a-fA-F]+/g, ""))) return undefined;
  const v = Function(`"use strict"; return (${e});`)();
  return Number.isInteger(v) ? v : undefined;
}

const out: any[] = [];
for (const file of walk(root)) {
  const src = readFileSync(file, "utf8");
  const re = /getDefine_Int_default\s*\(/g;
  for (let m; (m = re.exec(src)); ) {
    const before = src.slice(Math.max(0, m.index - 4), m.index);
    if (/int\s*$/.test(src.slice(Math.max(0, m.index - 6), m.index)) || /define\s*$/.test(before)) continue; // definition or macro
    const a = args(src, m.index + m[0].length);
    if (!a || a.list.length !== 5) continue;
    const line = src.slice(0, m.index).split("\n").length;
    const [sec, name, min, max, def] = a.list.map((s) => s.replace(/\/\*[\s\S]*?\*\//g, "").trim());
    if (/^[a-z_]+$/.test(name)) continue; // call inside a wrapper whose key is a parameter (handled below)
    const rec = { section: str(sec), name: str(name), min: num(min), max: num(max), default: num(def),
      raw: a.list.map((s) => s.replace(/\s+/g, " ")), file: relative(root, file), line };
    out.push({ ...rec, resolved: [rec.section, rec.name, rec.min, rec.max, rec.default].every((v) => v !== undefined) });
  }
}
// Task Manager wrapper: wm_task_manager_zeroable("key", min, max) reads wazuh_modules.<key> with
// fallback -1 (absent -> module default, 0 -> unlimited). See config/src/wmodules-task-manager.c.
for (const file of walk(root)) {
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(/wm_task_manager_zeroable\s*\(\s*"([a-z_]+)"\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/g)) {
    out.push({ section: "wazuh_modules", name: m[1], min: +m[2], max: +m[3], default: -1, zeroable: true,
      raw: [m[0]], file: relative(root, file), line: src.slice(0, m.index).split("\n").length, resolved: true });
  }
}
out.sort((x, y) => `${x.section}.${x.name}`.localeCompare(`${y.section}.${y.name}`));
console.log(JSON.stringify(out, null, 1));
