#!/usr/bin/env node
// PipelineGuard CLI — scan GitHub Actions workflows from a terminal or CI.
// Usage: node cli/pipelineguard.mjs [paths...] [--format text|json|sarif] [--fail-on high] [--output file]
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { scan } from "../site/engine/scan.mjs";
import { RULES, SEVERITIES, SEVERITY_META } from "../site/engine/rules.mjs";

const VERSION = "1.0.0";
const HOME = "https://yousafkhamza.github.io/pipelineguard";

const args = process.argv.slice(2);
const opts = { format: "text", failOn: "high", output: null, paths: [] };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--format" || a === "-f") opts.format = args[++i];
  else if (a === "--fail-on") opts.failOn = args[++i];
  else if (a === "--output" || a === "-o") opts.output = args[++i];
  else if (a === "--version" || a === "-v") { console.log(VERSION); process.exit(0); }
  else if (a === "--help" || a === "-h") { help(); process.exit(0); }
  else opts.paths.push(a);
}
if (!opts.paths.length) opts.paths.push(".github/workflows");
if (!["text", "json", "sarif"].includes(opts.format)) die(`Unknown --format "${opts.format}". Use text, json or sarif.`);
if (opts.failOn !== "none" && !SEVERITIES.includes(opts.failOn)) die(`Unknown --fail-on "${opts.failOn}". Use ${SEVERITIES.join(", ")} or none.`);

const files = opts.paths.flatMap(collect);
if (!files.length) die(`No .yml or .yaml files found in ${opts.paths.join(", ")}.`);

const results = files.map((file) => {
  const rel = relative(process.cwd(), file).replace(/\\/g, "/");
  return { file: rel, ...scan(readFileSync(file, "utf8"), { filename: rel }) };
});

let out;
if (opts.format === "json") out = JSON.stringify({ tool: "pipelineguard", version: VERSION, results }, null, 2);
else if (opts.format === "sarif") out = JSON.stringify(toSarif(results), null, 2);
else out = toText(results);

if (opts.output) writeFileSync(opts.output, out + "\n");
else console.log(out);

const threshold = opts.failOn === "none" ? -1 : SEVERITIES.indexOf(opts.failOn);
const failing = results.flatMap((r) => r.findings).filter((f) => SEVERITIES.indexOf(f.severity) <= threshold);
const broken = results.filter((r) => !r.ok);
process.exit(failing.length || broken.length ? 1 : 0);

// ---------------------------------------------------------------------------
function collect(p) {
  if (!existsSync(p)) die(`Path not found: ${p}`);
  if (statSync(p).isDirectory())
    return readdirSync(p).flatMap((n) => {
      const full = join(p, n);
      return statSync(full).isDirectory() ? collect(full) : /\.ya?ml$/i.test(n) ? [full] : [];
    });
  return [p];
}

function toText(results) {
  const tty = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  const sevColor = { critical: "1;31", high: "33", medium: "93", low: "34", info: "32" };
  const lines = [];
  for (const r of results) {
    if (!r.ok) { lines.push(`${c("1", r.file)}  ${c("31", "could not scan")}: ${r.error}`); continue; }
    lines.push(`${c("1", r.file)}  score ${r.score.value}/100 (${r.score.grade})  ${r.findings.length} finding${r.findings.length === 1 ? "" : "s"}`);
    for (const f of r.findings)
      lines.push(`  ${c(sevColor[f.severity], f.severity.padEnd(8))} ${f.id}  line ${String(f.line).padEnd(4)} ${f.detail}\n           ${c("2", `${HOME}/rules/#${f.slug}`)}`);
    lines.push("");
  }
  const total = results.flatMap((r) => r.findings);
  const summary = SEVERITIES.map((s) => `${total.filter((f) => f.severity === s).length} ${s}`).join(", ");
  lines.push(`${results.length} file${results.length === 1 ? "" : "s"} scanned: ${summary}.`);
  return lines.join("\n");
}

function toSarif(results) {
  const level = (s) => (s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note");
  const secScore = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "PipelineGuard",
            version: VERSION,
            informationUri: HOME,
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.slug,
              shortDescription: { text: r.title },
              fullDescription: { text: r.summary },
              help: { text: r.fix, markdown: `${r.fix}\n\n[Rule reference](${HOME}/rules/#${r.slug})` },
              helpUri: `${HOME}/rules/#${r.slug}`,
              defaultConfiguration: { level: level(r.severity) },
              properties: { tags: ["security", "github-actions"], "security-severity": secScore[r.severity] },
            })),
          },
        },
        results: results.flatMap((r) =>
          r.findings.map((f) => ({
            ruleId: f.id,
            level: level(f.severity),
            message: { text: `${f.title}. ${f.detail}` },
            locations: [{ physicalLocation: { artifactLocation: { uri: r.file }, region: { startLine: f.line } } }],
            properties: { severity: f.severity, "security-severity": secScore[f.severity] },
          }))
        ),
      },
    ],
  };
}

function help() {
  console.log(`PipelineGuard ${VERSION} — security scanner for GitHub Actions workflows

Usage
  node cli/pipelineguard.mjs [paths...] [options]

Paths default to .github/workflows. Directories are searched for .yml/.yaml files.

Options
  -f, --format <text|json|sarif>   Output format (default: text)
      --fail-on <severity|none>    Exit 1 if any finding is at or above this
                                   severity (default: high)
  -o, --output <file>              Write the report to a file
  -v, --version                    Print the version
  -h, --help                       Show this help

Severities: ${SEVERITIES.map((s) => `${s} (${SEVERITY_META[s].marking.toLowerCase()})`).join(", ")}
Rules: ${HOME}/rules/`);
}

function die(msg) {
  console.error(`pipelineguard: ${msg}`);
  process.exit(2);
}
