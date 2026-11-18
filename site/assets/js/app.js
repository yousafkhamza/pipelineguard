import { scan, buildFixPrompt } from "../../engine/scan.mjs";
import { RULE_BY_ID, SEVERITY_META, SEVERITIES } from "../../engine/rules.mjs";
import { SAMPLES } from "../../engine/samples.mjs";
import { initAI } from "./ai.js";

const $ = (s) => document.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(n.style, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null) n.append(kid);
  return n;
};
const svg = (tag, attrs = {}) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
};
const sevVar = (s) => `var(--${s})`;

const yaml = $("#yaml");
const gutter = $("#gutter");
const status = $("#status");
const sampleSel = $("#sample");
let last = null; // { text, result }

// ---------- editor ----------
function renderGutter(hits = new Map()) {
  const count = Math.max(1, yaml.value.split("\n").length);
  const frag = document.createDocumentFragment();
  for (let i = 1; i <= count; i++) {
    const sev = hits.get(i);
    const s = el("span", { class: sev ? "is-hit" : null, text: String(i) });
    if (sev) s.style.setProperty("--hit", sevVar(sev));
    frag.append(s);
  }
  gutter.replaceChildren(frag);
  gutter.scrollTop = yaml.scrollTop;
}
yaml.addEventListener("input", () => { renderGutter(); sampleSel.value = ""; });
yaml.addEventListener("scroll", () => { gutter.scrollTop = yaml.scrollTop; });
yaml.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); run(); }
  if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    const { selectionStart: a, selectionEnd: b } = yaml;
    yaml.setRangeText("  ", a, b, "end");
    renderGutter();
  }
});

function goToLine(line) {
  const lines = yaml.value.split("\n");
  const start = lines.slice(0, line - 1).reduce((n, l) => n + l.length + 1, 0);
  const end = start + (lines[line - 1] || "").length;
  yaml.focus({ preventScroll: true });
  yaml.setSelectionRange(start, end);
  const lh = parseFloat(getComputedStyle(yaml).lineHeight) || 20;
  yaml.scrollTop = Math.max(0, (line - 4) * lh);
  if (window.matchMedia("(max-width: 960px)").matches) $("#editor").scrollIntoView({ behavior: "smooth", block: "center" });
}

// ---------- samples & file ----------
for (const s of SAMPLES) sampleSel.append(el("option", { value: s.key, text: s.label }));
sampleSel.addEventListener("change", () => {
  const s = SAMPLES.find((x) => x.key === sampleSel.value);
  if (!s) return;
  yaml.value = s.text;
  renderGutter();
  run(s.file);
});
$("#file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  if (!f) return;
  if (f.size > 512 * 1024) return setStatus("That file is over 512 KB. Workflow files are usually a few KB; check you picked the right one.", true);
  yaml.value = await f.text();
  sampleSel.value = "";
  renderGutter();
  run(f.name);
  e.target.value = "";
});

// ---------- scan ----------
function setStatus(msg, isError = false) {
  status.textContent = msg;
  status.classList.toggle("is-error", isError);
}

function run(filename = "workflow.yml") {
  const text = yaml.value;
  if (!text.trim()) {
    setStatus("Paste a workflow first, or pick a sample.", true);
    yaml.focus();
    return;
  }
  const result = scan(text, { filename });
  if (!result.ok) {
    setStatus(result.error, true);
    renderGutter();
    return;
  }
  last = { text, result, filename };
  const n = result.findings.length;
  setStatus(n ? `Scanned ${filename}: ${n} finding${n === 1 ? "" : "s"}.` : `Scanned ${filename}: nothing found.`);
  const hits = new Map();
  for (const f of [...result.findings].reverse()) hits.set(f.line, f.severity); // highest severity wins
  renderGutter(hits);
  renderReport(result);
}
$("#scan").addEventListener("click", () => run(last?.filename && last.text === yaml.value ? last.filename : "workflow.yml"));

// ---------- report ----------
function buildGauge() {
  const zones = $("#gauge-zones");
  const ticks = $("#gauge-ticks");
  const cx = 100, cy = 104, r = 80;
  const angle = (v) => Math.PI * (1 - v / 100); // 0 → left, 100 → right
  const pt = (v, rad) => [cx + rad * Math.cos(angle(v)), cy - rad * Math.sin(angle(v))];
  const bands = [[0, 40, "critical"], [40, 60, "high"], [60, 75, "medium"], [75, 90, "low"], [90, 100, "info"]];
  for (const [a, b, s] of bands) {
    const [x1, y1] = pt(a, r), [x2, y2] = pt(b, r);
    zones.append(svg("path", { d: `M${x1} ${y1} A${r} ${r} 0 0 1 ${x2} ${y2}`, stroke: getComputedStyle(document.documentElement).getPropertyValue(`--${s}`).trim(), "stroke-width": 14, fill: "none" }));
  }
  for (let v = 0; v <= 100; v += 10) {
    const [x1, y1] = pt(v, r - 11), [x2, y2] = pt(v, r - (v % 50 ? 16 : 20));
    ticks.append(svg("line", { x1, y1, x2, y2, stroke: "#1B2428", "stroke-width": v % 50 ? 1.2 : 2 }));
    if (v % 50 === 0) {
      const [tx, ty] = pt(v, r - 31);
      if (v === 0 || v === 100) continue;
      const t = svg("text", { x: tx, y: ty + 3, "text-anchor": "middle" });
      t.textContent = v;
      ticks.append(t);
    }
  }
}
buildGauge();

function renderReport(result) {
  $("#empty").hidden = true;
  $("#result").hidden = false;
  const { value, grade, counts } = result.score;

  $("#needle").style.transform = `rotate(${(value / 100) * 180 - 90}deg)`;
  $("#score").textContent = value;
  $("#grade").textContent = grade;
  $("#counts").replaceChildren(
    ...SEVERITIES.map((s) => el("span", { class: `tag ${counts[s] ? `tag--${s}` : "tag--zero"}`, text: `${counts[s]} ${SEVERITY_META[s].label.toLowerCase()}` }))
  );

  // pipe map
  const map = $("#pipemap");
  map.replaceChildren();
  for (const job of result.jobs) {
    const jobFindings = result.findings.filter((f) => f.job === job.id);
    const runEl = el("div", { class: "pipe__run" });
    const slots = Math.max(job.steps.length, 1) + 1;
    // slot 0 = job-level findings, then one joint per step
    const groups = [{ label: "job settings", list: jobFindings.filter((f) => f.step == null) }].concat(
      job.steps.map((s) => ({ label: s.label, list: jobFindings.filter((f) => f.step === s.index) }))
    );
    groups.forEach((g, i) => {
      const left = `${((i + 0.5) / slots) * 100}%`;
      if (!g.list.length) {
        if (i === 0) return; // no joint drawn for clean job settings
        runEl.append(el("span", { class: "joint", style: { left }, title: g.label }));
        return;
      }
      const worst = g.list[0].severity;
      const b = el("button", {
        class: "joint is-hit", type: "button", style: { left },
        "aria-label": `${g.label}: ${g.list.length} finding${g.list.length > 1 ? "s" : ""}, worst is ${worst}`,
        title: `${g.label} (${g.list.length})`,
        onclick: () => flashFinding(g.list[0]),
      }, el("span", { class: "joint__count", text: String(g.list.length) }));
      b.style.setProperty("--hit", sevVar(worst));
      runEl.append(b);
    });
    map.append(el("div", { class: "pipe" },
      el("div", { class: "pipe__name" }, job.name, el("span", { text: `${job.steps.length} step${job.steps.length === 1 ? "" : "s"}` })),
      runEl));
  }
  // workflow-level findings (no job) get their own short pipe
  const wf = result.findings.filter((f) => !f.job);
  if (wf.length) {
    const runEl = el("div", { class: "pipe__run" });
    wf.forEach((f, i) => {
      const b = el("button", { class: "joint is-hit", type: "button", style: { left: `${((i + 0.5) / wf.length) * 100}%` }, title: f.title, "aria-label": `${f.title} (${f.severity})`, onclick: () => flashFinding(f) });
      b.style.setProperty("--hit", sevVar(f.severity));
      runEl.append(b);
    });
    map.prepend(el("div", { class: "pipe" }, el("div", { class: "pipe__name" }, "Workflow settings", el("span", { text: "triggers, env, permissions" })), runEl));
  }

  // findings list
  const list = $("#findings");
  list.replaceChildren();
  $("#fix-all").hidden = $("#copy-prompt").hidden = result.findings.length === 0;
  if (!result.findings.length) {
    list.append(el("li", { class: "clean" }, el("p", { text: "No known risky patterns found. Nice work. A clean scan isn't a guarantee, so still review what each third-party action does." })));
    return;
  }
  result.findings.forEach((f, idx) => {
    const rule = RULE_BY_ID[f.id];
    const li = el("li", { class: "finding", id: `f-${idx}` });
    li.style.setProperty("--hit", sevVar(f.severity));
    f._el = li;
    const fixBox = el("div", { class: "finding__fix", hidden: true },
      el("p", { text: rule.fix }),
      el("pre", { class: "code" }, el("code", { text: rule.good })));
    const toggle = el("button", {
      class: "btn btn--quiet", type: "button", "aria-expanded": "false",
      onclick: () => {
        const open = fixBox.hidden;
        fixBox.hidden = !open;
        toggle.setAttribute("aria-expanded", String(open));
        toggle.textContent = open ? "Hide fix" : "Show fix";
      },
      text: "Show fix",
    });
    li.append(
      el("span", { class: "finding__band", "aria-hidden": "true" }),
      el("div", { class: "finding__body" },
        el("div", { class: "finding__top" },
          el("span", { class: `tag tag--${f.severity}`, text: SEVERITY_META[f.severity].label }),
          el("span", { class: "finding__id", text: `${f.id}, line ${f.line}${f.job ? `, job ${f.job}` : ""}` })),
        el("p", { class: "finding__title", text: f.title }),
        el("p", { class: "finding__detail", text: f.detail }),
        el("div", { class: "finding__actions" },
          el("button", { class: "btn btn--quiet", type: "button", text: `Go to line ${f.line}`, onclick: () => goToLine(f.line) }),
          toggle,
          el("button", { class: "btn btn--quiet", type: "button", text: "Fix with AI", onclick: () => ai.open(f) }),
          el("a", { class: "btn btn--quiet", href: `rules/#${f.slug}`, text: "Rule details" })),
        fixBox));
    list.append(li);
  });
}

function flashFinding(f) {
  const li = f._el;
  if (!li) return;
  li.scrollIntoView({ behavior: "smooth", block: "center" });
  li.classList.add("is-flash");
  setTimeout(() => li.classList.remove("is-flash"), 1600);
  goToLine(f.line);
}

// ---------- AI ----------
const ai = initAI({
  getContext: () => last,
  buildPrompt: buildFixPrompt,
  onApply: (fixed) => {
    yaml.value = fixed;
    renderGutter();
    run(last?.filename);
    $("#scanner").scrollIntoView({ behavior: "smooth" });
  },
});
$("#fix-all").addEventListener("click", () => ai.open(null));
$("#copy-prompt").addEventListener("click", async (e) => {
  if (!last) return;
  await navigator.clipboard.writeText(buildFixPrompt(last.text, last.result.findings));
  e.target.textContent = "Prompt copied";
  setTimeout(() => (e.target.textContent = "Copy AI prompt"), 1800);
});

// ---------- boot ----------
document.querySelectorAll("[data-rule-count]").forEach((n) => (n.textContent = Object.keys(RULE_BY_ID).length));
const params = new URLSearchParams(location.search);
const startSample = SAMPLES.find((s) => s.key === (params.get("sample") || "preview"));
yaml.value = startSample.text;
sampleSel.value = startSample.key;
renderGutter();
run(startSample.file);
