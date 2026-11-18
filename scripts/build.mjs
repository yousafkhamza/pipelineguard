// Generates the crawlable parts of the site from the rule catalogue:
//   - the rules table on index.html
//   - rules/index.html (one anchored section per rule, plus JSON-LD)
//   - sitemap.xml with today's lastmod
// Run: node scripts/build.mjs   (CI runs this before publishing to Pages)
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { RULES, SEVERITY_META } from "../site/engine/rules.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "site");
const BASE = "https://yousafkhamza.github.io/pipelineguard/";
const today = new Date().toISOString().slice(0, 10);
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
// turn `code` spans in rule text into <code>
const rich = (s) => esc(s).replace(/(\$\{\{[^}]*\}\}|\b(?:pull_request_target|workflow_run|pull_request|issue_comment|discussion_comment|persist-credentials: false|secrets: inherit|permissions: contents: read|timeout-minutes|ACTIONS_ALLOW_UNSECURE_COMMANDS|\$GITHUB_ENV|\$GITHUB_PATH|GITHUB_TOKEN|write-all|run:|env:)\b)/g, "<code>$1</code>");

// ---------- index.html rules table ----------
const table = `<!-- rules:start -->
      <table class="ruletable">
        <thead><tr><th scope="col">Rule</th><th scope="col">What it catches</th><th scope="col">Default severity</th></tr></thead>
        <tbody>
${RULES.map((r) => `          <tr><td><a href="rules/#${r.slug}">${r.id}</a></td><td>${esc(r.title)}</td><td><span class="tag tag--${r.severity}">${SEVERITY_META[r.severity].label}</span></td></tr>`).join("\n")}
        </tbody>
      </table>
      <!-- rules:end -->`;
const indexPath = join(root, "index.html");
let index = readFileSync(indexPath, "utf8");
index = index.replace(/<!-- rules:start -->[\s\S]*?<!-- rules:end -->/, table);
index = index.replace(/<strong data-rule-count>\d+<\/strong>/, `<strong data-rule-count>${RULES.length}</strong>`);
index = index.replace(/(content="Paste a workflow, see which line is exploitable, get the fix\. )\d+ checks/, `$1${RULES.length} checks`);
writeFileSync(indexPath, index);

// ---------- rules/index.html ----------
const head = readFileSync(indexPath, "utf8").match(/<link rel="preload"[\s\S]*?assets\/css\/style.css">/)[0].replace(/href="assets\//g, 'href="../assets/');
const ld = {
  "@context": "https://schema.org",
  "@type": "TechArticle",
  headline: "GitHub Actions security rules: pwn requests, script injection, unpinned actions and more",
  description: `Reference for all ${RULES.length} PipelineGuard checks, each with a vulnerable and a fixed GitHub Actions example.`,
  url: `${BASE}rules/`,
  dateModified: today,
  inLanguage: "en",
  author: { "@type": "Person", name: "Yousaf Hamza", alternateName: "Yousaf K Hamza", url: "https://yousafkhamza.github.io/" },
  isPartOf: { "@type": "WebSite", name: "PipelineGuard", url: BASE },
  hasPart: RULES.map((r) => ({ "@type": "WebPageElement", name: `${r.id}: ${r.title}`, url: `${BASE}rules/#${r.slug}` })),
};
const breadcrumbs = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "PipelineGuard", item: BASE },
    { "@type": "ListItem", position: 2, name: "Rules", item: `${BASE}rules/` },
  ],
};

const rulesPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHub Actions Security Rules (${RULES.length} Checks with Fixes) | PipelineGuard</title>
  <meta name="description" content="How to fix pull_request_target pwn requests, script injection, unpinned actions, leaked secrets, self-hosted runner risks and over-broad GITHUB_TOKEN permissions in GitHub Actions. Vulnerable and fixed YAML for each.">
  <meta name="author" content="Yousaf Hamza (Yousaf K Hamza)">
  <link rel="canonical" href="${BASE}rules/">
  <meta name="theme-color" content="#1B2428">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'none'">
  <meta property="og:type" content="article">
  <meta property="og:site_name" content="PipelineGuard">
  <meta property="og:title" content="GitHub Actions security rules, with fixes">
  <meta property="og:description" content="${RULES.length} checks for GitHub Actions workflows, each with vulnerable and fixed YAML. By Yousaf Hamza.">
  <meta property="og:url" content="${BASE}rules/">
  <meta property="og:image" content="${BASE}og.png">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="icon" href="../favicon.svg" type="image/svg+xml">
  ${head}
  <script type="application/ld+json">${JSON.stringify(ld)}</script>
  <script type="application/ld+json">${JSON.stringify(breadcrumbs)}</script>
</head>
<body>
  <a class="skip" href="#rules">Skip to the rules</a>
  <header class="masthead">
    <div class="wrap masthead__inner">
      <a class="wordmark" href="../" aria-label="PipelineGuard home">
        <svg class="wordmark__icon" viewBox="0 0 32 32" aria-hidden="true"><rect x="1" y="12" width="30" height="8" rx="1.5" fill="currentColor"/><rect x="11" y="9" width="10" height="14" rx="1.5" fill="#EFC12B" stroke="currentColor" stroke-width="2"/><rect x="15" y="2" width="2" height="8" fill="currentColor"/><rect x="9" y="1" width="14" height="3" rx="1.5" fill="currentColor"/></svg>
        <span>PipelineGuard</span>
      </a>
      <nav class="nav" aria-label="Main">
        <a href="../#scanner">Scanner</a>
        <a href="./" aria-current="page">Rules</a>
        <a href="../#ci">Use in CI</a>
        <a href="https://github.com/yousafkhamza/pipelineguard" rel="noopener">GitHub</a>
      </nav>
    </div>
  </header>
  <main>
    <section class="page-head wrap">
      <h1>GitHub Actions security rules</h1>
      <p>Every check PipelineGuard runs, what the attack looks like, and the change that closes it. Each rule shows a vulnerable workflow next to a fixed one you can copy.</p>
      <p><a class="link" href="../#scanner">Scan your own workflow</a></p>
    </section>
    <div class="rulepage wrap" id="rules">
      <nav class="rulepage__toc" aria-label="Rules">
        <ol>
${RULES.map((r) => `          <li><a href="#${r.slug}" class="sev-${r.severity}"><span>${r.id}</span>${esc(r.title)}</a></li>`).join("\n")}
        </ol>
      </nav>
      <div>
${RULES.map((r) => `        <article class="rule sev-${r.severity}" id="${r.slug}">
          <span class="rule__band" aria-hidden="true"></span>
          <div class="rule__body">
            <div class="finding__top"><span class="tag tag--${r.severity}">${SEVERITY_META[r.severity].label}</span><span class="finding__id">${r.id}, ${r.slug}</span></div>
            <h2>${esc(r.title)}</h2>
            <p>${rich(r.summary)}</p>
            <p><b>How to fix it.</b> ${rich(r.fix)}</p>
            <div class="rule__pair">
              <figure><figcaption>Vulnerable</figcaption><pre class="code"><code>${esc(r.bad)}</code></pre></figure>
              <figure><figcaption>Fixed</figcaption><pre class="code"><code>${esc(r.good)}</code></pre></figure>
            </div>
          </div>
        </article>`).join("\n")}
      </div>
    </div>
  </main>
  <footer class="footer">
    <div class="wrap footer__inner">
      <p>PipelineGuard was built by <a href="https://yousafkhamza.github.io/" rel="author">Yousaf Hamza</a> (Yousaf K Hamza), a DevOps and platform engineer in Dubai. It's open source under the MIT licence.</p>
      <p><a href="https://github.com/yousafkhamza/pipelineguard">Source on GitHub</a> <span aria-hidden="true">/</span> <a href="https://github.com/yousafkhamza/pipelineguard/issues/new">Suggest a rule</a></p>
    </div>
  </footer>
</body>
</html>
`;
mkdirSync(join(root, "rules"), { recursive: true });
writeFileSync(join(root, "rules", "index.html"), rulesPage);

// ---------- sitemap ----------
writeFileSync(
  join(root, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${BASE}</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>1.0</priority></url>
  <url><loc>${BASE}rules/</loc><lastmod>${today}</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>
</urlset>
`
);

console.log(`Built: ${RULES.length} rules, index table, rules/index.html, sitemap.xml (${today})`);
