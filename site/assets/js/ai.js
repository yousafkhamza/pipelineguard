// Bring-your-own-key AI fixes. Requests go directly from the browser to the provider.
// The key lives in a JS variable for this tab only; nothing is written to storage.

const DEFAULT_MODEL = { anthropic: "claude-sonnet-5-5", openai: "gpt-4.1" };

export function initAI({ getContext, buildPrompt, onApply }) {
  const dlg = document.getElementById("ai-dialog");
  const provider = document.getElementById("ai-provider");
  const model = document.getElementById("ai-model");
  const keyInput = document.getElementById("ai-key");
  const runBtn = document.getElementById("ai-run");
  const copyBtn = document.getElementById("ai-copy-prompt");
  const scope = document.getElementById("ai-scope");
  const out = document.getElementById("ai-out");
  let focus = null;
  const keys = { anthropic: "", openai: "" };

  provider.addEventListener("change", () => {
    model.value = DEFAULT_MODEL[provider.value];
    keyInput.value = keys[provider.value];
  });
  keyInput.addEventListener("input", () => (keys[provider.value] = keyInput.value.trim()));

  function prompt() {
    const ctx = getContext();
    return buildPrompt(ctx.text, ctx.result.findings, focus);
  }

  copyBtn.addEventListener("click", async () => {
    await navigator.clipboard.writeText(prompt());
    copyBtn.textContent = "Prompt copied";
    setTimeout(() => (copyBtn.textContent = "Copy prompt instead"), 1800);
  });

  runBtn.addEventListener("click", async () => {
    const key = keys[provider.value];
    if (!key) {
      showError("Add an API key first, or use Copy prompt instead and paste it into any chat assistant.");
      keyInput.focus();
      return;
    }
    runBtn.disabled = true;
    runBtn.textContent = "Drafting…";
    out.hidden = false;
    out.replaceChildren(para("Waiting for the model. This usually takes 10 to 30 seconds."));
    try {
      const text = provider.value === "anthropic" ? await callAnthropic(key, model.value, prompt()) : await callOpenAI(key, model.value, prompt());
      renderAnswer(text);
    } catch (err) {
      showError(err.message);
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = "Draft the fix";
    }
  });

  function renderAnswer(text) {
    out.replaceChildren();
    const m = text.match(/```(?:ya?ml)?\s*\n([\s\S]*?)```/i);
    const prose = (m ? text.replace(m[0], "") : text).trim();
    for (const block of prose.split(/\n{2,}/)) if (block.trim()) out.append(para(block.replace(/[*_`#]+/g, "").trim()));
    if (m) {
      const fixed = m[1].replace(/\s+$/, "") + "\n";
      const pre = document.createElement("pre");
      pre.className = "code";
      const code = document.createElement("code");
      code.textContent = fixed;
      pre.append(code);
      const actions = document.createElement("div");
      actions.className = "ai__actions";
      const apply = btn("Load fix into editor and rescan", "btn btn--primary", () => { dlg.close(); onApply(fixed); });
      const copy = btn("Copy fixed YAML", "btn btn--quiet", async () => {
        await navigator.clipboard.writeText(fixed);
        copy.textContent = "Copied";
      });
      actions.append(apply, copy);
      out.append(pre, actions, para("Check the fix before you commit it. Models can invent commit SHAs, so look up real SHAs on each action's releases page."));
    }
  }

  function showError(msg) {
    out.hidden = false;
    const p = para(msg);
    p.style.color = "var(--critical)";
    p.style.fontWeight = "600";
    out.replaceChildren(p);
  }

  return {
    open(finding) {
      const ctx = getContext();
      if (!ctx) return;
      focus = finding;
      scope.textContent = finding
        ? `Fixing ${finding.id} on line ${finding.line}: ${finding.title}.`
        : `Fixing all ${ctx.result.findings.length} findings in ${ctx.filename}.`;
      out.hidden = true;
      out.replaceChildren();
      keyInput.value = keys[provider.value];
      dlg.showModal();
      (keyInput.value ? runBtn : keyInput).focus();
    },
  };
}

async function callAnthropic(key, model, prompt) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
      "anthropic-dangerous-direct-browser-access": "true",
    },
    body: JSON.stringify({ model, max_tokens: 4096, messages: [{ role: "user", content: prompt }] }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Anthropic returned ${res.status}: ${data?.error?.message || res.statusText}. Check the key and model name.`);
  return (data.content || []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
}

async function callOpenAI(key, model, prompt) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
    body: JSON.stringify({ model, messages: [{ role: "user", content: prompt }] }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`OpenAI returned ${res.status}: ${data?.error?.message || res.statusText}. Check the key and model name.`);
  return data.choices?.[0]?.message?.content || "";
}

function para(text) {
  const p = document.createElement("p");
  p.textContent = text;
  return p;
}
function btn(text, cls, onclick) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = cls;
  b.textContent = text;
  b.addEventListener("click", onclick);
  return b;
}
