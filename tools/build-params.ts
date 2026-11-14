#!/usr/bin/env bun
// Build the parameter table of wazuh5-tuner.py from the verified inputs.
// Usage: bun tools/build-params.ts <xcheck.json> <engine.json> <engine-configuration.md>
// Writes data/params.json (with source and doc locations) and the PARAMS block of wazuh5-tuner.py.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [xcPath, enginePath, engineDoc] = process.argv.slice(2);
if (!engineDoc) throw new Error("usage: build-params.ts <xcheck.json> <engine.json> <engine-configuration.md>");
const repo = join(import.meta.dir, "..");
const xc = JSON.parse(readFileSync(xcPath, "utf8"));
const engine = JSON.parse(readFileSync(enginePath, "utf8")) as any[];
const INT_MAX = 2147483647;
const CAP = 9007199254740991; // largest integer a browser number field holds exactly

// Keys read only by agents or agent-side modules, never by the manager daemons.
const EXCLUDE = /^(agent|agent_info|syscheck|wazuh_command)\.|^sca\.(commands_timeout|remote_commands)$/;

// Extra rules found in source, outside getDefine_Int_default's [min,max].
const GAP: Record<string, { gap: number; at: string }> = {
  "remoted.queue_max_bytes": { gap: 1024, at: "src/remoted/src/config.c:182" },
  "remoted.batch_events_max_bytes": { gap: 1024, at: "src/remoted/src/config.c:187" },
  "wazuh_modules.inventory_sync_server_session_query_batch_size": { gap: 100, at: "src/wazuh_modules/src/wm_inventory_sync_server.c:162" },
};

// Descriptions the parsers cannot lift from one line: shared headings or meaning held in the default text.
const DESC: Record<string, string> = {
  "auth.timeout_seconds": "Receive timeout of a local-socket client connection, seconds part (both parts 0 = no timeout).",
  "auth.timeout_microseconds": "Receive timeout of a local-socket client connection, microseconds part (both parts 0 = no timeout).",
  "vulnerability-detection.scan_workers": "Concurrent scan slots. 0 = half the host's cores, minimum 1.",
  "wazuh_modules.inventory_sync_server_io_threads": "Reactor I/O threads of the inventory sync server. 0 sizes the reactor from the host or cgroup.",
};

// Inventory caps: remoted docs give one shared default and range in prose, not per key.
const LIMITS_DESC = "Inventory cap the manager sends to 5.x agents in the startup answer (limits object).";

const clean = (s = "") =>
  s.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/`/g, "").replace(/\*\*/g, "")
    .replace(/\s*\u2014\s*/g, ", ").replace(/\u2013/g, "-").replace(/\s+/g, " ").trim();
const sentence = (s = "") => {
  // Range and default live in their own fields; drop "(1-4096, default: 64)" and "Default: 20 seconds".
  const c = clean(s).replace(/\s*\(\s*-?\d+\s*(?:-|to)\s*-?\d+[^)]*\)/g, "").replace(/\s*Default:.*$/i, "").trim();
  const m = c.match(/^(.+?[.!?])(\s|$)/);
  return m ? m[1] : c;
};

type P = { key: string; type: "int" | "bool"; default: number | boolean | null; min?: number; max?: number;
  gap?: number; desc: string; src: string[]; doc: string[]; note?: string };
const params: P[] = [];
const problems: string[] = [];

for (const m of [...xc.match, ...xc.mismatch]) {
  if (EXCLUDE.test(m.k)) continue;
  // Several readers of one key (e.g. authd and the task manager) must share the range. A reader whose
  // fallback is a sentinel (<= 0) defers to the module default; the real fallbacks must agree.
  const real = m.src.filter((s: any) => s.def > 0);
  const s0 = real[0] ?? m.src[0];
  if (m.src.some((s: any) => s.min !== s0.min || s.max !== s0.max) || real.some((s: any) => s.def !== s0.def)) { problems.push(`${m.k}: source calls disagree`); continue; }
  // Prefer reference entries (### headings, tables). Keys documented only in ini blocks use the
  // block line that carries the "(lo-hi" range comment; other ini lines are example values.
  let docs = m.docs.filter((d: any) => d.how !== "ini");
  if (!docs.length) docs = m.docs.filter((d: any) => d.how === "ini" && d.lo !== undefined);
  const pick = (f: string) => docs.map((d: any) => d[f]).find((v: any) => v !== undefined && v !== null);
  const dLo = pick("lo"), dHi = pick("hi"), dDef = pick("def");
  const min = Math.max(s0.min, dLo ?? s0.min), max = Math.min(s0.max, dHi ?? s0.max);
  const gap = GAP[m.k] && GAP[m.k].gap > Math.max(s0.min, dLo ?? s0.min) ? GAP[m.k].gap : undefined;
  const ok = (v: number) => v >= min && v <= max && !(gap && v > 0 && v < gap);
  let def: number | null, note: string | undefined;
  if (ok(s0.def) && (dDef === undefined || dDef === s0.def)) def = s0.def;
  else if (!ok(s0.def) || s0.def <= 0) {
    // Source fallback is a sentinel (0 or -1): the module applies its own default, which the docs state.
    def = dDef !== undefined && ok(dDef) ? dDef : null;
    note = def === null ? "module computes the default" : `source fallback ${s0.def} means module default`;
  } else { problems.push(`${m.k}: source default ${s0.def} vs docs ${dDef}`); continue; }
  if (dLo !== undefined && dLo > s0.min) note = [note, `docs narrow the minimum to ${dLo}`].filter(Boolean).join("; ");
  const desc = DESC[m.k] ?? sentence([...docs, ...m.docs].map((d: any) => d.desc).find((x: string) => x && !/^\d/.test(x)) ?? "");
  if (!desc) problems.push(`${m.k}: no description in docs`);
  params.push({ key: m.k, type: "int", default: def, min, max, ...(gap ? { gap } : {}), desc,
    src: m.src.map((s: any) => `src/${s.at}`), doc: [...new Set(docs.map((d: any) => d.file as string))], ...(note ? { note } : {}) });
}
for (const s of xc.srcOnly) {
  if (EXCLUDE.test(s.k)) continue;
  if (!/^(fim|syscollector)\.\w+_limit$|^sca\.checks_limit$/.test(s.k)) { problems.push(`${s.k}: in source, not in docs`); continue; }
  params.push({ key: s.k, type: "int", default: 30000, min: 0, max: INT_MAX, desc: LIMITS_DESC,
    src: s.at.map((a: string) => `src/${a}`), doc: ["modules_remoted_configuration.md"] });
}

// Engine: manager-mode numeric and boolean settings only. Paths, sockets, URLs, patterns, lists,
// standalone-only keys and the two process switches (drop_privileges, server_enable_event_processing)
// are left out on purpose.
const ENGINE_SKIP = /^analysisd\.(drop_privileges|server_enable_event_processing|logging_level|tzdb_force_version_update|indexer_ssl_\w+|indexer_hosts|\w+_path|\w+_socket|\w+_pattern|geo_manifest_url)$/;
const docRows = new Map<string, string[]>();
for (const l of readFileSync(engineDoc, "utf8").split("\n"))
  if (/^\| `analysisd\./.test(l)) { const c = l.split("|").slice(1, -1).map((x) => x.trim()); docRows.set(c[0].replace(/`/g, ""), c); }
const evalNum = (e: string) => {
  const x = e.replace(/'/g, "").replace(/size_t\s*\{([^}]*)\}/g, "($1)").replace(/int64_t\s*\{([^}]*)\}/g, "($1)")
    .replace(/(\d+)ULL/g, "$1").replace(/std::numeric_limits<int>::max\(\)/g, String(INT_MAX));
  if (!/^[\d\sxa-fA-F()<*+,-]+$/.test(x)) throw new Error(`cannot evaluate ${e}`);
  return Function(`"use strict"; return (${x});`)() as number;
};
for (const u of engine) {
  if (ENGINE_SKIP.test(u.key) || /string|vector/.test(u.type)) continue;
  const row = docRows.get(u.key);
  if (!row) { problems.push(`${u.key}: engine unit without docs row`); continue; }
  const docDefRaw = row[3].match(/`([^`]+)`/)?.[1];
  const at = `src/engine/source/conf/src/conf.cpp (${u.key})`;
  if (u.type === "bool") {
    const def = u.def === "true";
    if (docDefRaw !== String(def)) problems.push(`${u.key}: bool default ${u.def} vs docs ${docDefRaw}`);
    params.push({ key: u.key, type: "bool", default: def, desc: sentence(row[2]), src: [at], doc: ["engine-configuration.md"] });
    continue;
  }
  const def = evalNum(u.def);
  if (String(def) !== docDefRaw) { problems.push(`${u.key}: default ${def} vs docs ${docDefRaw}`); continue; }
  let min = 0, max = CAP, note: string | undefined, cap: string | undefined;
  if (u.range) [min, max] = u.range.split(/,(?![^{]*\})/).map((r: string) => evalNum(r.trim()));
  else if (u.key === "analysisd.debug") { max = 2; note = "no range check in the engine (3 or more also means trace); tuner limits it to 0-2"; }
  else note = u.type === "size_t" ? "unsigned, no upper bound in the engine; tuner caps at 2^53-1" : "tuner range 0 to 2^53-1";
  // tuner_cap: C++ type of a key the engine checks only by type, so --check reports values past the tuner range as WARN.
  if (!u.range) cap = u.type;
  params.push({ key: u.key, type: "int", default: def, min, max, desc: sentence(row[2]), src: [at], doc: ["engine-configuration.md"], ...(note ? { note } : {}), ...(cap ? { tuner_cap: cap } : {}) });
}

if (problems.length) { console.error(problems.join("\n")); process.exit(1); }

// Keys some daemon reads that the tuner does not offer: --check reports them as "not checked"
// instead of "no daemon reads this key".
const tuned = new Set(params.map((p) => p.key));
const other: Record<string, string> = {};
for (const m of [...xc.match, ...xc.mismatch, ...xc.srcOnly])
  if (!tuned.has(m.k)) other[m.k] = EXCLUDE.test(m.k) ? "read by agents, not by the manager" : "not offered by the tuner";
for (const u of engine)
  if (!tuned.has(u.key)) other[u.key] = "engine setting the tuner does not offer (path, socket, URL, list or switch)";

// Sections, in UI order. First match wins.
const SECTIONS: [string, RegExp, string, string][] = [
  ["engine", /^analysisd\./, "Engine (wazuh-manager-analysisd)", "Event queue, orchestrator, indexer output, content sync and stream logs. analysisd.* keys: the LAST line wins, an inline # ends the value, booleans are true/false."],
  ["remoted_https", /^remoted\.(http_|downstream_|jwt_|auth_|control_|authd_|vd_scan_|enroll_|max_)/, "Remoted, HTTPS agent server", "HTTPS transport for 5.x agents (port 27000): reactor threads, admission control, downstream sockets, auth and control endpoint."],
  ["remoted", /^remoted\./, "Remoted, core and legacy listener", "Queues, worker pools and the legacy (4.x) listener on 1514."],
  ["limits", /^(fim|syscollector|sca)\./, "Agent inventory limits", "Caps remoted hands every 5.x agent at startup. Set the same values on every cluster node."],
  ["wazuh_db", /^wazuh_db\./, "Wazuh DB (wazuh-manager-db)", "Worker pool, commit timing, open databases, vacuum policy."],
  ["authd", /^(authd|auth)\./, "Enrollment (wazuh-manager-authd)", "Agent limit, deletion purge delay and local-socket timeouts."],
  ["tasks", /^wazuh_modules\.manager_task_/, "Task Manager", "Durable task queue: retries, timeouts, retention, log rotation, agent monitoring."],
  ["upgrade", /^wazuh_modules\.upgrade_/, "Agent upgrades", "Upgrade batches, WPK downloads and version cache."],
  ["inventory", /^wazuh_modules\.inventory_sync_server_/, "Inventory sync server", "Transport, admission and indexer connectors of the inventory sync endpoint in modulesd."],
  ["vulnerability", /^(vulnerability-detection\.|wazuh_modules\.indexer_)/, "Vulnerability detection", "Scan workers, CPE cache and the scanner's indexer bulk settings."],
  ["modules", /^(wazuh_modules|wazuh_database|wazuh)\./, "Modules daemon and shared", "wazuh-manager-modulesd common options, agent database sync, thread stack size."],
];
const out: Record<string, { label: string; desc: string; params: P[] }> = {};
for (const [id, , label, desc] of SECTIONS) out[id] = { label, desc, params: [] };
for (const p of params) {
  const s = SECTIONS.find(([, re]) => re.test(p.key));
  if (!s) throw new Error(`no section for ${p.key}`);
  out[s[0]].params.push(p);
}
for (const s of Object.values(out)) s.params.sort((a, b) => a.key.localeCompare(b.key));
writeFileSync(join(repo, "data/params.json"), JSON.stringify(out, null, 1) + "\n");

// Python block: compact JSON, one parameter per line, without the provenance fields.
const lines = ["# BEGIN PARAMS (written by tools/build-params.ts, do not edit by hand)", "PARAMS = json.loads(r\"\"\"{"];
const ids = Object.keys(out);
ids.forEach((id, i) => {
  const s = out[id];
  lines.push(` ${JSON.stringify(id)}: {"label": ${JSON.stringify(s.label)}, "desc": ${JSON.stringify(s.desc)}, "params": [`);
  s.params.forEach((p, j) => {
    const { src, doc, ...ui } = p;
    lines.push(`  ${JSON.stringify(ui)}${j < s.params.length - 1 ? "," : ""}`);
  });
  lines.push(` ]}${i < ids.length - 1 ? "," : ""}`);
});
lines.push("}\"\"\")", "OTHER_KEYS = json.loads(r\"\"\"" + JSON.stringify(Object.fromEntries(Object.entries(other).sort()), null, 0) + "\"\"\")", "# END PARAMS");
const pyPath = join(repo, "wazuh5-tuner.py");
const py = readFileSync(pyPath, "utf8");
const a = py.indexOf("# BEGIN PARAMS"), b = py.indexOf("# END PARAMS");
if (a < 0 || b < 0) throw new Error("PARAMS markers not found in wazuh5-tuner.py");
writeFileSync(pyPath, py.slice(0, a) + lines.join("\n") + py.slice(b + "# END PARAMS".length));
console.error(Object.entries(out).map(([k, v]) => `${k}=${v.params.length}`).join(" "), `total=${params.length}`);
