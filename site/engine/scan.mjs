// PipelineGuard scan engine. Runs unchanged in the browser and in Node.
import { load } from "./js-yaml.mjs";
import { RULE_BY_ID, SEVERITY_META, SEVERITIES } from "./rules.mjs";

const SHA_RE = /^[0-9a-f]{40}$/i;
const UNTRUSTED_RE = new RegExp(
  [
    String.raw`github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment)\.(?:title|body)`,
    String.raw`github\.event\.(?:head_commit|workflow_run\.head_commit)\.(?:message|author\.(?:email|name))`,
    String.raw`github\.event\.commits(?:\[\*\]|\.\*|\[\d+\])?\.(?:message|author\.(?:email|name))`,
    String.raw`github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)`,
    String.raw`github\.event\.workflow_run\.(?:head_branch|display_title)`,
    String.raw`github\.event\.pages(?:\[\*\]|\.\*)?\.page_name`,
    String.raw`github\.head_ref`,
  ].join("|")
);
const EXPR_RE = /\$\{\{([\s\S]*?)\}\}/g;
const CREDENTIAL_PATTERNS = [
  { name: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/ },
  { name: "private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
];
const RETIRED_RUNNERS = /^(ubuntu-(16|18|20)\.04|windows-(2016|2019)|macos-(10\.15|11|12|13))$/i;
const ARCHIVED_ACTIONS = ["actions/create-release", "actions/upload-release-asset", "actions/setup-ruby", "actions/setup-elixir", "actions/setup-haskell", "actions/upload-artifact@v1", "actions/upload-artifact@v2", "actions/upload-artifact@v3", "actions/download-artifact@v1", "actions/download-artifact@v2", "actions/download-artifact@v3"];
const COMPROMISED_ACTIONS = /^(tj-actions\/changed-files|tj-actions\/[a-z-]+|reviewdog\/[a-z-]+)$/i;
const POPULAR = ["actions/checkout", "actions/setup-node", "actions/setup-python", "actions/setup-go", "actions/setup-java", "actions/cache", "actions/upload-artifact", "actions/download-artifact", "actions/github-script", "docker/login-action", "docker/build-push-action", "aws-actions/configure-aws-credentials", "github/codeql-action"];
const CRED_INPUT = /^(password|passwd|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret)$/i;
const SECURITY_STEP = /\b(audit|scan|trivy|snyk|grype|semgrep|codeql|gitleaks|lint|eslint|test|pytest|checkov|tfsec)\b/i;
const PRIVILEGED_TRIGGERS = ["pull_request_target", "workflow_run"];
const PR_TRIGGERS = ["pull_request", "pull_request_target"];
const COMMENT_TRIGGERS = ["issue_comment", "discussion_comment", "pull_request_review_comment"];

// ---------- helpers ----------
function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
const isAlwaysTrueIf = (v) => typeof v === "string" && v.includes("${{") && v.replace(/\$\{\{[\s\S]*?\}\}/g, "").trim() !== "";
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

function triggersOf(doc) {
  const on = doc.on ?? doc[true]; // YAML 1.1 parsers turn `on` into true
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  if (isObj(on)) return Object.keys(on);
  return [];
}

function makeLocator(text) {
  const lines = text.split(/\r?\n/);
  return {
    lines,
    // first line (1-based) at or after `from` containing needle
    find(needle, from = 1) {
      if (!needle) return null;
      const n = String(needle).split("\n")[0].trim();
      if (!n) return null;
      for (let i = Math.max(0, from - 1); i < lines.length; i++) if (lines[i].includes(n)) return i + 1;
      for (let i = 0; i < lines.length; i++) if (lines[i].includes(n)) return i + 1;
      return null;
    },
    findRe(re, from = 1) {
      for (let i = Math.max(0, from - 1); i < lines.length; i++) if (re.test(lines[i])) return i + 1;
      return null;
    },
  };
}

function untrustedExprs(str) {
  if (typeof str !== "string") return [];
  const hits = [];
  for (const m of str.matchAll(EXPR_RE)) {
    const inner = m[1];
    const u = inner.match(UNTRUSTED_RE);
    if (u) hits.push(u[0]);
  }
  return [...new Set(hits)];
}

function permsAreWriteAll(p) {
  return p === "write-all" || (isObj(p) && Object.values(p).every((v) => v === "write") && Object.keys(p).length > 5);
}

// ---------- main ----------
export function scan(text, { filename = "workflow.yml" } = {}) {
  const findings = [];
  const loc = makeLocator(text);
  let doc;
  try {
    doc = load(text);
  } catch (e) {
    return {
      ok: false,
      error: `This isn't valid YAML: ${e.reason || e.message}${e.mark ? ` (line ${e.mark.line + 1}, column ${e.mark.column + 1})` : ""}.`,
      findings: [],
      jobs: [],
      score: null,
    };
  }
  if (!isObj(doc) || !isObj(doc.jobs)) {
    return {
      ok: false,
      error: "No jobs: block found. Paste a complete workflow file from .github/workflows/.",
      findings: [],
      jobs: [],
      score: null,
    };
  }

  const add = (id, line, detail, jobId = null, stepIndex = null, extra = {}) => {
    const rule = RULE_BY_ID[id];
    findings.push({
      id,
      slug: rule.slug,
      title: rule.title,
      severity: extra.severity || rule.severity,
      line: line || 1,
      detail,
      job: jobId,
      step: stepIndex,
      file: filename,
    });
  };

  const triggers = triggersOf(doc);
  const privileged = triggers.filter((t) => PRIVILEGED_TRIGGERS.includes(t));
  const hasPR = triggers.some((t) => PR_TRIGGERS.includes(t));
  const hasComment = triggers.filter((t) => COMMENT_TRIGGERS.includes(t));
  const onLine = loc.findRe(/^(on|"on"|'on')\s*:/) || 1;
  const topPerms = doc.permissions;

  // PG006: hardcoded credentials anywhere in the text
  for (const { name, re } of CREDENTIAL_PATTERNS) {
    const line = loc.findRe(re);
    if (line) add("PG006", line, `Looks like a hard-coded ${name}.`);
  }

  // PG008: unsecure commands (top-level env)
  const unsecureLine = loc.findRe(/ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['"]?true/i);
  if (unsecureLine) add("PG008", unsecureLine, "ACTIONS_ALLOW_UNSECURE_COMMANDS is set to true.");

  // PG004: workflow-level permissions
  if (permsAreWriteAll(topPerms)) {
    add("PG004", loc.find("permissions") || 1, "The whole workflow is granted write-all.", null, null, { severity: "high" });
  }

  // PG016: privileged trigger without explicit permissions
  if (privileged.length && topPerms === undefined) {
    const allJobsScoped = Object.values(doc.jobs).every((j) => isObj(j) && j.permissions !== undefined);
    if (!allJobsScoped)
      add("PG016", onLine, `${privileged.join(" and ")} runs with secrets, and no permissions block limits the token.`);
  }

  // PG033 broad OIDC
  if (isObj(topPerms) && topPerms["id-token"] === "write")
    add("PG033", loc.findRe(/id-token\s*:\s*write/) || 1, "Every job in this workflow can mint cloud credentials.");
  // PG034 deploy without concurrency
  const looksDeploy = /deploy|release|publish|terraform apply|kubectl apply|helm (upgrade|install)/i.test(`${doc.name || ""} ${Object.keys(doc.jobs).join(" ")}`);
  if (looksDeploy && doc.concurrency === undefined && !Object.values(doc.jobs).some((j) => isObj(j) && j.concurrency !== undefined))
    add("PG034", loc.findRe(/^name\s*:/) || 1, "Deploy-style workflow with no concurrency group.");
  // PG035 workflow_run without branch filter
  const onObj = isObj(doc.on) ? doc.on : null;
  if (onObj && isObj(onObj.workflow_run) && !onObj.workflow_run.branches && !onObj.workflow_run["branches-ignore"])
    add("PG035", loc.find("workflow_run") || onLine, "workflow_run fires for runs on any branch, including fork PR branches.");
  else if (triggers.includes("workflow_run") && !onObj?.workflow_run)
    add("PG035", loc.find("workflow_run") || onLine, "workflow_run fires for runs on any branch, including fork PR branches.");

  let job_env_cache = {};
  const jobs = [];
  let cursor = 1;
  let missingPermsJobs = [];

  for (const [jobId, job] of Object.entries(doc.jobs)) {
    if (!isObj(job)) continue;
    const jobLine = loc.findRe(new RegExp(`^\\s+["']?${jobId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?\\s*:`), cursor) || cursor;
    cursor = jobLine;
    const jobOut = { id: jobId, name: job.name || jobId, line: jobLine, steps: [] };
    jobs.push(jobOut);

    if (job.permissions === undefined) missingPermsJobs.push(jobId);
    if (permsAreWriteAll(job.permissions))
      add("PG004", loc.find("permissions", jobLine) || jobLine, `Job "${jobId}" is granted write-all.`, jobId, null, { severity: "high" });

    // Reusable workflow call
    if (typeof job.uses === "string") {
      const line = loc.find(job.uses, jobLine);
      checkUses(job.uses, line, jobId, null);
      if (job.secrets === "inherit") add("PG014", loc.find("secrets: inherit", jobLine) || line, `Job "${jobId}" forwards all secrets.`, jobId);
      jobOut.steps.push({ index: 0, label: `calls ${job.uses.split("@")[0]}`, line });
      continue;
    }

    // PG013 timeout
    if (job["timeout-minutes"] === undefined) add("PG013", jobLine, `Job "${jobId}" can run for up to 6 hours.`, jobId);

    // PG019 always-true if
    if (isAlwaysTrueIf(job.if)) add("PG019", loc.find("if:", jobLine) || jobLine, `Job "${jobId}" has an if: that always passes.`, jobId);
    // PG028 retired runner images
    for (const label of [].concat(job["runs-on"] ?? []).map(String))
      if (RETIRED_RUNNERS.test(label)) add("PG028", loc.find(label, jobLine) || jobLine, `${label} has been retired by GitHub.`, jobId);

    // PG009 self-hosted on PR
    const runsOn = [].concat(job["runs-on"] ?? []).map(String);
    const runsOnLabels = isObj(job["runs-on"]) ? [].concat(job["runs-on"].labels ?? [], job["runs-on"].group ?? []) : runsOn;
    if (hasPR && runsOnLabels.some((l) => /self-hosted/i.test(l)))
      add("PG009", loc.find("runs-on", jobLine) || jobLine, `Job "${jobId}" runs pull request code on a self-hosted runner.`, jobId);

    // PG015 comment trigger without author check
    if (hasComment.length) {
      const cond = String(job.if ?? "");
      if (!/author_association|github\.actor|github\.triggering_actor|permission/i.test(cond))
        add("PG015", (job.if && loc.find("if:", jobLine)) || jobLine, `Job "${jobId}" runs for any commenter (${hasComment.join(", ")}).`, jobId);
    }

    // PG011 container & services images
    const images = [];
    if (job.container) images.push(typeof job.container === "string" ? job.container : job.container.image);
    if (isObj(job.services)) for (const s of Object.values(job.services)) if (isObj(s) && s.image) images.push(s.image);
    for (const img of images.filter(Boolean)) {
      if (!String(img).includes("@sha256:"))
        add("PG011", loc.find(img, jobLine) || jobLine, `Image ${img} can change under you.`, jobId);
    }

    // PG002 in job-level if/env is fine; check job env for secrets? (skipped)

    job_env_cache = { ...(doc.env || {}), ...(job.env || {}) };
    const steps = Array.isArray(job.steps) ? job.steps : [];
    let stepCursor = jobLine;
    let downloadsArtifact = false;
    steps.forEach((step, i) => {
      if (!isObj(step)) return;
      const anchor = step.uses || (typeof step.run === "string" ? step.run.split("\n").find((l) => l.trim()) : null) || step.name;
      const line = loc.find(anchor, stepCursor) || stepCursor;
      stepCursor = line;
      const label = step.name || (step.uses ? step.uses.split("@")[0] : String(step.run || "").split("\n")[0].slice(0, 48)) || `step ${i + 1}`;
      jobOut.steps.push({ index: i, label, line });

      if (typeof step.uses === "string") {
        checkUses(step.uses, line, jobId, i);
        const name = step.uses.split("@")[0].toLowerCase();
        const w = isObj(step.with) ? step.with : {};

        if (name === "actions/checkout") {
          const ref = String(w.ref ?? "");
          const repo = String(w.repository ?? "");
          if (privileged.length && /github\.event\.pull_request\.head|github\.head_ref|refs\/pull\/|github\.event\.workflow_run\.head|merge_commit_sha/.test(ref + repo))
            add("PG001", loc.find("ref:", line) || line, `Checks out PR code (${ref || repo}) under ${privileged.join("/")}.`, jobId, i);
          if (w["persist-credentials"] !== false && String(w["persist-credentials"]) !== "false")
            add("PG010", line, "Token stays in .git/config for every later step.", jobId, i);
        }
        if (/^(actions\/download-artifact|dawidd6\/action-download-artifact)$/.test(name) && triggers.includes("workflow_run"))
          downloadsArtifact = { line, i };
        if (name === "actions/github-script" && typeof w.script === "string") {
          for (const e of untrustedExprs(w.script))
            add("PG002", loc.find(e, line) || line, `${e} is expanded into JavaScript.`, jobId, i, { severity: privileged.length || hasComment.length ? "critical" : "high" });
        }
        // untrusted expressions passed into `with:` are usually safe (the action receives a string)
      }

      if (typeof step.run === "string") {
        const run = step.run;
        for (const e of untrustedExprs(run))
          add("PG002", loc.find(e, line) || line, `${e} is expanded into the shell script.`, jobId, i, {
            severity: privileged.length || hasComment.length || triggers.includes("issues") ? "critical" : "high",
          });

        const secretExprs = [...run.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g)].map((m) => m[1]).filter((n) => n !== "GITHUB_TOKEN");
        if (secretExprs.length) {
          const echoed = /\b(echo|printf|cat|print)\b[^\n|]*\$\{\{\s*secrets\./.test(run) && !/--password-stdin|>\s*\S/.test(run);
          add("PG005", loc.find("secrets." + secretExprs[0], line) || line,
            `secrets.${[...new Set(secretExprs)].join(", secrets.")} written into the script${echoed ? " and printed" : ""}.`,
            jobId, i, { severity: echoed ? "high" : "medium" });
        }
        if (/(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(-E\s+)?(ba|z|k)?sh\b/.test(run))
          add("PG007", loc.findRe(/(curl|wget).*\|\s*(sudo\s+)?(ba|z|k)?sh/, line) || line, "Runs a downloaded script without verifying it.", jobId, i);
        if (downloadsArtifact && /GITHUB_ENV|GITHUB_PATH|\bsource\b|^\s*\.\s|bash\s+\S+\.sh|unzip|tar\s+x/m.test(run))
          add("PG012", line, "Uses downloaded artifact contents in a privileged workflow_run job.", jobId, i, { severity: /GITHUB_ENV|GITHUB_PATH|source/.test(run) ? "critical" : "high" });
      }
      checkStepExtras(step, line, jobId, i);
    });

    if (downloadsArtifact && !findings.some((f) => f.id === "PG012" && f.job === jobId))
      add("PG012", downloadsArtifact.line, "Downloads artifacts from a run that may come from a fork.", jobId, downloadsArtifact.i, { severity: "medium" });
  }

  // PG004: no permissions anywhere
  if (topPerms === undefined && missingPermsJobs.length && !findings.some((f) => f.id === "PG016")) {
    add("PG004", 1, `No permissions block. ${missingPermsJobs.length === Object.keys(doc.jobs).length ? "Every job gets" : `Jobs ${missingPermsJobs.join(", ")} get`} the repository default token.`);
  }

  function checkStepExtras(step, line, jobId, i) {
    if (isAlwaysTrueIf(step.if)) add("PG019", loc.find("if:", line) || line, "This step's if: always passes.", jobId, i);
    const w = isObj(step.with) ? step.with : {};
    const uses = typeof step.uses === "string" ? step.uses : "";
    const name = uses.split("@")[0].toLowerCase();
    if (uses && !uses.startsWith("./") && !uses.startsWith("docker://")) {
      for (const [k, v] of Object.entries(w))
        if (CRED_INPUT.test(k) && typeof v === "string" && v.trim() && !v.includes("${{"))
          add("PG020", loc.find(`${k}:`, line) || line, `Input "${k}" has a literal value.`, jobId, i);
      if (name === "actions/upload-artifact" && /^(\.|\.\/|\*\*|\.\/\*\*|\*)$/.test(String(w.path ?? "").trim()))
        add("PG024", loc.find("path:", line) || line, `Uploads "${w.path}", which includes .git.`, jobId, i);
      if (privileged.length && /^actions\/cache(\/(save|restore))?$/.test(name) || privileged.length && w.cache)
        add("PG025", line, `Cache used under ${privileged.join("/")}.`, jobId, i);
      if (ARCHIVED_ACTIONS.some((a) => (a.includes("@") ? uses.toLowerCase().startsWith(a) : name === a)))
        add("PG027", line, `${uses} is archived.`, jobId, i);
      if (COMPROMISED_ACTIONS.test(name)) {
        const pinned = SHA_RE.test(uses.split("@")[1] || "");
        add("PG029", line, `${name} was compromised in 2025${pinned ? "; check the pinned SHA is a reviewed one" : " and is referenced by tag"}.`, jobId, i, { severity: pinned ? "low" : "medium" });
      }
      if (!POPULAR.includes(name)) {
        const near = POPULAR.find((p) => editDistance(p, name) <= 2 && p.split("/")[1] === name.split("/")[1] || editDistance(p, name) === 1);
        if (near) add("PG030", line, `"${name}" is one character away from "${near}".`, jobId, i);
      }
    }
    if (typeof step.run !== "string") {
      if (step["continue-on-error"] === true && SECURITY_STEP.test(uses))
        add("PG036", loc.find("continue-on-error", line) || line, `${uses} can fail without failing the job.`, jobId, i);
      return;
    }
    const run = step.run;
    const exprs = [...run.matchAll(EXPR_RE)].map((m) => m[1].trim());
    const inputs = exprs.filter((e) => /^(inputs|github\.event\.inputs)\./.test(e));
    if (inputs.length) add("PG017", loc.find(inputs[0], line) || line, `${inputs.join(", ")} expanded into the script.`, jobId, i);
    const outs = exprs.filter((e) => /^(steps|needs)\.[\w-]+\.outputs\./.test(e) || /^needs\.[\w-]+\.outputs\./.test(e));
    if (outs.length) add("PG018", loc.find(outs[0], line) || line, `${outs.join(", ")} expanded into the script.`, jobId, i);
    if (exprs.some((e) => /^(github\.token|secrets\.GITHUB_TOKEN)$/.test(e)))
      add("PG021", loc.findRe(/github\.token|secrets\.GITHUB_TOKEN/, line) || line, "The repository token is written into the script.", jobId, i);
    const tls = run.match(/curl\b[^\n]*?\s(-k|--insecure)\b|wget\s[^\n]*--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED=0|GIT_SSL_NO_VERIFY=(1|true)|StrictHostKeyChecking=no|git config[^\n]*http\.sslVerify\s+false|pip[^\n]*--trusted-host/);
    if (tls) add("PG022", loc.find(tls[0].trim(), line) || line, `"${tls[0].trim()}" disables certificate checks.`, jobId, i);
    const stepEnv = JSON.stringify(step.env ?? {}) + JSON.stringify(job_env_cache);
    if (/(^|\n)\s*set\s+-[a-wyz]*x/.test(run) && /secrets\./.test(stepEnv + run))
      add("PG023", loc.findRe(/set\s+-[a-wyz]*x/, line) || line, "set -x will print expanded commands that use secrets.", jobId, i);
    if (/::(set-output|save-state)\b/.test(run))
      add("PG026", loc.findRe(/::(set-output|save-state)/, line) || line, "Uses a removed workflow command.", jobId, i);
    if (/docker\s+run\b[^\n]*(--privileged|\/var\/run\/docker\.sock)/.test(run))
      add("PG031", loc.findRe(/--privileged|docker\.sock/, line) || line, "Container gets root-level access to the runner.", jobId, i);
    const unlocked = run.split(/\n|&&|;|\|\|/).map((c) => c.trim()).find((c) => {
      const [tool, sub, ...rest] = c.split(/\s+/);
      const args = rest.filter((a) => !a.startsWith("-"));
      const flags = rest.join(" ");
      if (tool === "npm" && (sub === "install" || sub === "i")) return !/(^|\s)(-g|--global)\b/.test(flags) && args.length === 0;
      if (tool === "yarn" && (sub === undefined || sub === "install" || sub?.startsWith("-"))) return !/frozen-lockfile|immutable/.test(c);
      if (tool === "pnpm" && (sub === "install" || sub === "i")) return !/frozen-lockfile/.test(flags) && args.length === 0;
      return false;
    });
    if (unlocked) add("PG032", loc.find(unlocked, line) || line, `"${unlocked}" can pull unreviewed versions.`, jobId, i);
    if (step["continue-on-error"] === true && SECURITY_STEP.test(run))
      add("PG036", loc.find("continue-on-error", line) || line, "A check in this step can fail without failing the job.", jobId, i);
  }

  function checkUses(uses, line, jobId, stepIndex) {
    if (uses.startsWith("./")) return;
    if (uses.startsWith("docker://")) {
      if (!uses.includes("@sha256:")) add("PG011", line, `${uses} is not pinned to a digest.`, jobId, stepIndex);
      return;
    }
    const [path, ref = ""] = uses.split("@");
    if (SHA_RE.test(ref)) return;
    const owner = path.split("/")[0].toLowerCase();
    const firstParty = owner === "actions" || owner === "github";
    let severity = firstParty ? "low" : "medium";
    if (!ref || /^(main|master|dev|develop|trunk|latest|HEAD)$/i.test(ref)) severity = firstParty ? "medium" : "high";
    add("PG003", line, `${path}@${ref || "(no ref)"} ${/^v?\d/.test(ref) ? "is a movable tag" : "follows a branch"}.`, jobId, stepIndex, { severity });
  }

  // de-duplicate identical findings
  const seen = new Set();
  const unique = findings.filter((f) => {
    const k = `${f.id}|${f.line}|${f.detail}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  unique.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.line - b.line);

  return { ok: true, triggers, findings: unique, jobs, score: scoreOf(unique) };
}

export function scoreOf(findings) {
  let penalty = 0;
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) {
    counts[f.severity]++;
    // diminishing returns per repeat so 30 unpinned tags don't drown a pwn request
    penalty += SEVERITY_META[f.severity].weight / Math.sqrt(counts[f.severity]);
  }
  const value = Math.max(0, Math.round(100 - penalty));
  let grade = value >= 90 ? "A" : value >= 75 ? "B" : value >= 60 ? "C" : value >= 40 ? "D" : "F";
  if (counts.critical) grade = value >= 40 ? "D" : "F";
  return { value, grade, counts };
}

// Builds the prompt used by the AI fix feature (and by "copy prompt").
export function buildFixPrompt(text, findings, focus = null) {
  const list = (focus ? [focus] : findings)
    .map((f) => `- [${f.severity.toUpperCase()}] ${f.id} line ${f.line}: ${f.title}. ${f.detail}`)
    .join("\n");
  return `You are a GitHub Actions security reviewer. Fix the issues listed below in this workflow.

Rules:
- Keep the workflow's behaviour the same; only change what is needed for security.
- Pass untrusted ${"${{ }}"} values through env: and quote the shell variable.
- Pin actions to a full commit SHA with the version tag in a trailing comment. If you don't know the SHA, write <PIN-SHA> and keep the tag comment.
- Add the smallest permissions: block that works.
- Reply with: (1) a short explanation per issue, one or two sentences each, then (2) the complete fixed workflow in a single \`\`\`yaml code block.

Issues found by PipelineGuard:
${list}

Workflow:
\`\`\`yaml
${text}
\`\`\``;
}
