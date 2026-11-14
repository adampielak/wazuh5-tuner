#!/usr/bin/env bun
// Cross-check manager internal options: docs (rc2 markdown) vs source (getDefine_Int_default extract).
// Usage: bun xcheck.ts <opts.json> <docs-dir>
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
const [optsPath, docsDir] = process.argv.slice(2);
const src = JSON.parse(readFileSync(optsPath, "utf8")) as any[];
const n = (s: string) => Number(s.replace(/[`,]/g, ""));
type D = { key: string; def?: number; lo?: number; hi?: number; desc?: string; file: string; how: string };
const docs = new Map<string, D[]>();
const add = (d: D) => (docs.get(d.key) ?? docs.set(d.key, []).get(d.key)!).push(d);
const KEY = /^[a-z_-]+\.[a-z0-9_]+$/;
for (const f of readdirSync(docsDir).filter((x) => x.endsWith(".md") && !x.startsWith("engine"))) {
  const lines = readFileSync(join(docsDir, f), "utf8").split("\n");
  let inCode = false, lastComment = "";
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^```/.test(l)) { inCode = !inCode; lastComment = ""; continue; }
    if (inCode) {
      // ini: "# desc (a-b, default: N)" or "# desc (a to b ...)" + "# Default: N", then key=value
      if (/^#/.test(l)) { lastComment += " " + l.slice(1).trim(); continue; }
      const m = l.match(/^([a-z_-]+\.[a-z0-9_]+)=(-?\d+)$/);
      if (m) {
        const r = lastComment.match(/\((-?[\d,]+)\s*(?:-|to)\s*(-?[\d,]+)/);
        add({ key: m[1], def: n(m[2]), lo: r ? n(r[1]) : undefined, hi: r ? n(r[2]) : undefined, desc: lastComment.trim(), file: f, how: "ini" });
      }
      lastComment = "";
      continue;
    }
    // "### key" heading + bullets
    const h = l.match(/^#{3,4}\s+`?([a-z_-]+\.[a-z0-9_]+)`?\s*$/);
    if (h && KEY.test(h[1])) {
      let def, lo, hi, desc = "", descDone = false;
      for (let j = i + 1; j < lines.length && !/^#{1,4}\s/.test(lines[j]); j++) {
        const t = lines[j];
        // Description: the first paragraph after the heading, joined across wrapped lines.
        if (!descDone && t.trim() && !t.startsWith("-") && !t.startsWith("```") && !/^[a-z_.-]+=/.test(t)) desc += (desc ? " " : "") + t.trim();
        else if (desc) descDone = true;
        const dm = t.match(/\*\*Default value:\*\*\s*`(-?[\d,]+)`/); if (dm) def = n(dm[1]);
        const am = t.match(/\*\*Allowed values:\*\*.*?`?(-?[\d,]+)`?\s*(?:to|-|\u2013)\s*`?(-?[\d,]+)`?/); if (am && lo === undefined) { lo = n(am[1]); hi = n(am[2]); }
      }
      add({ key: h[1], def, lo, hi, desc, file: f, how: "heading" });
      continue;
    }
    // table row: a cell holding `key`, later cells: default, range "lo-hi"
    if (/^\|/.test(l)) {
      const cells = l.split("|").slice(1, -1).map((c) => c.trim());
      const ki = cells.findIndex((c) => /^`[a-z_-]+\.[a-z0-9_]+`$/.test(c));
      if (ki >= 0) {
        const rest = cells.slice(ki + 1).filter((c) => c !== "internal option");
        const dm = rest[0]?.match(/^`?(-?[\d,]+)`?(?:\s|\(|$)/);
        const rm = rest[1]?.match(/^`?(-?[\d,]+)`?\s*(?:-|\u2013|to)\s*`?(-?[\d,]+)`?/);
        if (dm || rm) add({ key: cells[ki].slice(1, -1), def: dm ? n(dm[1]) : undefined, lo: rm ? n(rm[1]) : undefined, hi: rm ? n(rm[2]) : undefined, desc: rest.slice(2).join(" ") || cells.slice(0, ki).join(" "), file: f, how: "table" });
      }
    }
  }
}
const srcBy = new Map<string, any[]>();
for (const r of src) (srcBy.get(`${r.section}.${r.name}`) ?? srcBy.set(`${r.section}.${r.name}`, []).get(`${r.section}.${r.name}`)!).push(r);
const out: any = { match: [], mismatch: [], docOnly: [], srcOnly: [] };
for (const [k, ds] of docs) {
  const ss = srcBy.get(k);
  if (!ss) { out.docOnly.push({ k, ds }); continue; }
  const s = ss[0];
  const bad = ds.filter((d) => (d.def !== undefined && d.def !== s.default) || (d.lo !== undefined && d.lo !== s.min) || (d.hi !== undefined && d.hi !== s.max));
  const distinct = new Set(ss.map((x) => `${x.min}/${x.max}/${x.default}`));
  (bad.length || distinct.size > 1 ? out.mismatch : out.match).push({ k, src: ss.map((x) => ({ min: x.min, max: x.max, def: x.default, at: `${x.file}:${x.line}` })), docs: ds });
}
for (const [k, ss] of srcBy) if (!docs.has(k)) out.srcOnly.push({ k, at: ss.map((x) => `${x.file}:${x.line}`) });
console.log(JSON.stringify(out, null, 1));
console.error(`match=${out.match.length} mismatch=${out.mismatch.length} docOnly=${out.docOnly.length} srcOnly=${out.srcOnly.length}`);
