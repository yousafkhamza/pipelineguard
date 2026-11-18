import { test } from "node:test";
import assert from "node:assert/strict";
import { scan } from "../site/engine/scan.mjs";
import { RULES } from "../site/engine/rules.mjs";
import { SAMPLES } from "../site/engine/samples.mjs";

const ids = (text) => scan(text).findings.map((f) => f.id);
const sample = (k) => SAMPLES.find((s) => s.key === k).text;

test("every rule has the fields the site and SARIF need", () => {
  for (const r of RULES) for (const k of ["id", "slug", "title", "severity", "summary", "fix", "bad", "good"]) assert.ok(r[k], `${r.id} missing ${k}`);
  assert.equal(new Set(RULES.map((r) => r.slug)).size, RULES.length);
});

test("hardened sample is clean and scores A", () => {
  const r = scan(sample("hardened"));
  assert.equal(r.findings.length, 0, JSON.stringify(r.findings, null, 2));
  assert.equal(r.score.grade, "A");
});

test("pwn request is detected", () => {
  const r = scan(sample("preview"));
  assert.ok(r.findings.some((f) => f.id === "PG001" && f.severity === "critical"));
  assert.ok(r.findings.some((f) => f.id === "PG009"));
  assert.equal(r.score.grade, "F");
});

test("script injection in run and github-script", () => {
  assert.ok(ids(sample("triage")).includes("PG002"));
  const safe = `on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - env: { T: "\${{ github.event.head_commit.message }}" }
        run: echo "$T"`;
  assert.ok(!ids(safe).includes("PG002"));
});

test("hard-coded credentials and unsecure commands", () => {
  const f = ids(sample("release"));
  assert.ok(f.includes("PG006"));
  assert.ok(f.includes("PG008"));
  assert.ok(f.includes("PG014"));
  assert.ok(f.includes("PG011"));
});

test("SHA-pinned actions are not flagged, branches are high", () => {
  const r = scan(`on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: { persist-credentials: false }
      - uses: random/thing@main`);
  const pins = r.findings.filter((f) => f.id === "PG003");
  assert.equal(pins.length, 1);
  assert.equal(pins[0].severity, "high");
});

test("invalid YAML returns a helpful error", () => {
  const r = scan("jobs:\n  a: [\n");
  assert.equal(r.ok, false);
  assert.match(r.error, /valid YAML/);
});

test("line numbers point at the offending step", () => {
  const r = scan(sample("preview"));
  const inj = r.findings.find((f) => f.id === "PG002");
  const line = sample("preview").split("\n")[inj.line - 1];
  assert.match(line, /pull_request\.title/);
});

test("legacy sample trips every newer rule", () => {
  const found = new Set(ids(sample("legacy")));
  for (const id of ["PG017","PG018","PG019","PG020","PG021","PG022","PG023","PG024","PG025","PG026","PG027","PG028","PG029","PG030","PG031","PG032","PG033","PG034","PG035","PG036"])
    assert.ok(found.has(id), `${id} not detected`);
});

test("lockfile installs and pinned versions are not flagged", () => {
  const f = ids(`on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: |
          npm ci
          npm install -g pnpm
          yarn install --frozen-lockfile
          npm install lodash@4.17.21`);
  assert.ok(!f.includes("PG032"), f.join());
});
