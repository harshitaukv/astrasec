/* AstraSec dashboard: Immune memory, Defence policy, Risk and config, Evaluation. */
"use strict";

const ACTION_HELP = {
  allow: "Pass the prompt to the model unchanged.",
  mask: "Hide personal data such as emails, phone numbers and card numbers, then forward.",
  sanitize: "Strip the hostile parts, re-check what is left, and forward it only if it is now safe.",
  rate_limit: "Slow the client down; repeated attacks put them in quarantine.",
  block: "Refuse the request and never forward it.",
};

/* ------------------------------------------------------------------ immune memory */
async function viewMemory(view) {
  const [mem, sigs, adapt, ov] = await Promise.all([api("/api/memory?limit=40"), api("/api/signatures"), api("/api/adaptations?limit=40"), api("/api/overview")]);
  const st = mem.stats, maxL = Math.max(1, ...Object.values(st.by_label));
  view.innerHTML = head("Immune memory", "Attacks the system has seen, what it did about them, and the rules and model updates it has produced on its own.", `
    <button class="btn ghost" data-action="recommend">Generate recommendations</button>
    <button class="btn ghost" data-action="propose">Ask Llama 3.1 for new rules</button>
    <button class="btn" data-action="retrain">Retrain the classifier</button>`) + `
    <div id="mem-notes"></div>
    <div class="split even">
      <div>
        <div class="stat-line"><div><b class="num">${st.cases}</b><span>distinct attacks remembered</span></div><div><b class="num">${st.total_recurrences}</b><span>times they have come back</span></div><div><b class="num">${pct(st.defence_success_rate ?? 0)}</b><span>of defences held</span></div></div>
      </div>
      <div class="hbars">${ATTACKS.map(k => `<div class="hbar"><span>${TITLES[k]}</span>${bar((st.by_label[k] || 0) / maxL, colorOf(k))}<span class="v num">${st.by_label[k] || 0}</span></div>`).join("")}</div>
    </div>

    <section class="block"><h2>Remembered attacks</h2>
      ${mem.cases.length ? `<div class="scroll"><table><thead><tr><th>Last seen</th><th>Prompt</th><th>Type</th><th>Seen</th><th>Defence held</th><th>Response used</th><th>Source</th></tr></thead><tbody>
      ${mem.cases.map(c => `<tr><td class="num">${fmtTime(c.last_seen)}</td><td class="prompt" title="${esc(c.prompt)}">${esc(c.prompt)}</td><td>${chipLabel(c.label)}</td><td class="num">${c.hits}</td><td class="num">${c.successes}/${c.hits}</td><td>${actChip(c.action)}</td><td class="small">${c.source === "analyst" ? "Confirmed by analyst" : c.source === "output_filter" ? "Output filter, awaiting review" : "Live traffic"}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty"><h3>Memory is empty</h3><p>Attacks are stored automatically the first time they are seen.</p></div>`}
    </section>

    <section class="block"><h2>Signatures the system wrote for itself</h2>
      <p class="muted" style="margin-bottom:8px">${ov.signatures.static} built-in signatures ship with AstraSec. The ones below were mined from repeated attacks or proposed by Llama 3.1; proposals stay pending until a person approves them.</p>
      ${sigs.length ? `<div class="scroll tall"><table><thead><tr><th>Id</th><th>Type</th><th>Pattern</th><th>Origin</th><th>Status</th><th>False alarms</th><th></th></tr></thead><tbody>
      ${sigs.map(s => `<tr><td>${esc(s.sid)}</td><td>${chipLabel(s.label)}</td><td class="prompt" title="${esc(s.pattern)}">${esc(s.pattern)}</td><td>${s.source === "llm" ? "Llama 3.1" : "Mined from attacks"}</td><td>${esc(s.status)}</td><td class="num">${s.fp_reports}</td>
      <td>${s.status === "active" ? `<button class="btn ghost small" data-action="sigstatus" data-sid="${esc(s.sid)}" data-status="retired">Retire</button>` : `<button class="btn ghost small" data-action="sigstatus" data-sid="${esc(s.sid)}" data-status="active">${s.status === "pending" ? "Approve" : "Reactivate"}</button>`}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">None yet. Signatures are mined once the same kind of attack has been seen enough times, and after analysts mark missed attacks on the Traffic page.</p>`}
    </section>

    <section class="block"><h2>Self-healing log</h2>
      ${adapt.length ? `<div class="scroll tall"><table><tbody>${adapt.map(a => `<tr><td class="num" style="white-space:nowrap">${fmtTime(a.ts)}</td><td><span class="chip">${esc(a.kind.replace(/_/g, " "))}</span></td><td>${esc(a.summary)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">Nothing yet. Entries appear when the system changes its own thresholds, policy, signatures or model.</p>`}
    </section>`;
}

async function pollRetrain() {
  const box = $("#mem-notes");
  let html = "";
  for (let i = 0; i < 90; i++) {
    const s = await api("/api/retrain/status");
    if (s.status === "running") { box.innerHTML = `<div class="well" style="margin-bottom:24px">Retraining on the original dataset plus confirmed attacks and false alarms…</div>`; await new Promise(r => setTimeout(r, 2000)); continue; }
    if (s.status === "deployed" || s.status === "rejected") {
      html = `<div class="well" style="margin-bottom:24px"><b>${s.status === "deployed" ? "New model deployed." : "Candidate model rejected."}</b> It learned from ${s.extra_samples} reviewed samples. Held-out macro-F1 ${s.candidate.macro_f1} against ${s.reference.macro_f1} before; false-alarm rate ${pct(s.candidate.false_positive_rate, 1)} against ${pct(s.reference.false_positive_rate, 1)}. ${s.status === "rejected" ? "It was not deployed because it was worse than the current model." : ""}</div>`;
    } else html = `<div class="well" style="margin-bottom:24px">${esc(s.reason || s.error || s.status)}</div>`;
    return html;
  }
}

/* ------------------------------------------------------------------ defence policy */
async function viewPolicy(view) {
  const [pol, ov] = await Promise.all([api("/api/policy"), api("/api/overview")]);
  const th = ov.thresholds;
  view.innerHTML = head("Defence policy", "The rule table that picks a defence for each kind of threat. AstraSec tightens rows by itself when a defence keeps failing; you can also change any row by hand.") + `
    <div class="scroll"><table class="policy-grid"><thead><tr><th>Threat</th>${["high", "medium", "low"].map(s => `<th>${s[0].toUpperCase() + s.slice(1)} severity</th>`).join("")}</tr></thead><tbody>
    ${ATTACKS.map(l => `<tr><td>${chipLabel(l)}</td>${["high", "medium", "low"].map(s => { const k = `${l}:${s}`; return `<td><select data-policy="${k}" aria-label="${TITLES[l]}, ${s} severity" style="width:auto;min-width:130px">${pol.actions.map(a => `<option value="${a}" ${pol.policy[k] === a ? "selected" : ""}>${ACTION_TEXT[a]}</option>`).join("")}</select></td>`; }).join("")}</tr>`).join("")}</tbody></table></div>
    <section class="block split even">
      <div><h2>What each action does</h2><div style="margin-top:8px">${pol.actions.map(a => `<div class="finding"><div>${actChip(a)}</div><div>${ACTION_HELP[a]}</div></div>`).join("")}</div></div>
      <div><h2>Detection thresholds</h2>
        <div class="stat-line" style="margin:8px 0 12px"><div><b class="num">${th.flag}</b><span>attack flag threshold (allowed range ${th.flag_min} to ${th.flag_max})</span></div><div><b class="num">${th.memory_similarity}</b><span>similarity needed to recall a past attack</span></div><div><b class="num">${th.anomaly_flag}</b><span>anomaly score treated as unusual</span></div></div>
        <p class="muted">The flag threshold moves down when analysts report missed attacks and up when they report false alarms, always inside the allowed range. Each change is written to the self-healing log.</p>
        <h3 style="margin-top:22px">Quarantine</h3>
        <p class="muted small" style="margin:4px 0 8px">A client is quarantined for two minutes after three flagged attacks in five minutes.</p>
        ${ov.quarantined.length ? `<table><tbody>${ov.quarantined.map(q => `<tr><td>${esc(q.client)}</td><td class="num">${Math.round(q.seconds_left)} s left</td><td><button class="btn ghost small" data-action="release" data-client="${esc(q.client)}">Release</button></td></tr>`).join("")}</tbody></table>` : `<p class="muted small">Nobody is quarantined right now.</p>`}
      </div>
    </section>`;
  view.addEventListener("change", async e => {
    const k = e.target.dataset?.policy; if (!k) return;
    try { await api("/api/policy", { method: "PUT", body: { key: k, action: e.target.value } }); toast(`${k.replace(":", ", ").replace(/_/g, " ")} now ${ACTION_TEXT[e.target.value].toLowerCase()}.`); }
    catch (err) { toast(err.message, true); route(); }
  });
}

/* ------------------------------------------------------------------ risk and config */
const CFG_FLAGS = [
  ["system_prompt_hardened", "System prompt has security instructions"], ["canary_token", "Canary token planted in the prompt"], ["secrets_in_prompt", "Secrets are written in the system prompt"],
  ["input_validation", "Inputs are validated"], ["output_filtering", "Outputs are screened"], ["pii_masking", "Personal data is masked"],
  ["rate_limiting", "Requests are rate-limited"], ["audit_logging", "Audit logging is on"], ["auth_required", "Callers must authenticate"],
  ["tls_enabled", "Traffic uses TLS"], ["model_endpoint_public", "Model endpoint is public"], ["human_approval_for_tools", "Tool use needs human approval"], ["model_supply_chain_verified", "Model files are checksum-verified"],
];
const SAMPLE_REQ = "torch==1.13.0\nlangchain==0.0.200\npillow==9.0.0\nrequests==2.25.0\nnumpy==1.26.4\n";

async function viewRisk(view) {
  const r = await api("/api/risk"), p = r.posture, c = r.config;
  const names = { prompts: "Prompts", api: "API traffic", config: "Configuration", dependencies: "Dependencies" };
  view.innerHTML = head("Risk and config", "The health score combines four areas. Change the configuration to see what each control is worth.") + `
    <div class="hero" style="margin-bottom:8px">
      <div><div class="score num">${Math.round(p.health_score)}<small>out of 100</small></div><span class="level ${lvClass(p.level)}">${esc(p.level)}</span>
        <p class="muted" style="margin-top:14px">${p.config_audit.passed} of ${p.config_audit.total} configuration checks pass. ${p.dependency_scan.packages} packages scanned, ${p.dependency_scan.findings} with known vulnerabilities.</p></div>
      <div class="comp">${Object.entries(p.components).map(([k, x]) => `<div class="comp-row"><div>${names[k]}<small>${Math.round(x.weight * 100)}% of score</small></div>${bar(x.health / 100, x.health >= 85 ? "var(--healthy)" : x.health >= 60 ? "var(--amber)" : "var(--eosin)")}<b class="num">${Math.round(x.health)}</b></div>`).join("")}</div>
    </div>

    <section class="block"><h2>Findings, most severe first</h2>
      <div>${p.register.map(f => `<div class="finding"><div>${sevChip(f.severity)}<p class="small">${esc(f.area)}</p></div><div><b>${esc(f.title)}</b><p>${esc(f.fix)}</p></div></div>`).join("") || `<p class="muted">No open findings.</p>`}</div>
    </section>

    <section class="block"><h2>Application configuration</h2>
      <p class="muted" style="margin-bottom:12px">Describes the assistant being protected (${esc(c.name)}). Saving re-runs the audit straight away.</p>
      <form id="cfg-form"><div class="toggles">${CFG_FLAGS.map(([k, l]) => `<label><input type="checkbox" name="${k}" ${c[k] ? "checked" : ""}>${l}</label>`).join("")}</div>
        <div class="row" style="margin-top:14px">
          <label class="f" style="width:170px">Tool access<select name="tool_access">${["none", "read", "write", "admin"].map(v => `<option ${c.tool_access === v ? "selected" : ""}>${v}</option>`).join("")}</select></label>
          <label class="f" style="width:170px">Max input characters<input type="number" name="max_input_chars" value="${c.max_input_chars}" min="0"></label>
          <label class="f" style="width:140px">Temperature<input type="number" step="0.1" min="0" max="2" name="temperature" value="${c.temperature}"></label>
          <button class="btn" type="submit" style="align-self:flex-end">Save and re-audit</button>
        </div></form>
    </section>

    <section class="block"><h2>Dependency scan</h2>
      <p class="muted" style="margin-bottom:10px">Paste a requirements.txt. Versions are checked against the advisory snapshot bundled with AstraSec.</p>
      <textarea id="req-text" style="min-height:120px">${esc(SAMPLE_REQ)}</textarea>
      <p style="margin:10px 0"><button class="btn" data-action="scan">Scan packages</button></p><div id="scan-out"></div>
    </section>`;
  $("#cfg-form").addEventListener("submit", async e => {
    e.preventDefault(); const f = e.target, body = {};
    CFG_FLAGS.forEach(([k]) => body[k] = f[k].checked);
    body.tool_access = f.tool_access.value; body.max_input_chars = +f.max_input_chars.value; body.temperature = +f.temperature.value;
    try { await api("/api/risk/config", { method: "PUT", body }); toast("Configuration saved."); route(); } catch (err) { toast(err.message, true); }
  });
}

const STOP = new Set("the a an of to for this that these those it is are was were be been have has had do does did and or but in on at by with from as into over about all any".split(" "));

/* ------------------------------------------------------------------ evaluation */
function confusion(m, labels) {
  const max = Math.max(1, ...m.flat());
  return `<div class="scroll"><table class="matrix"><thead><tr><th class="lab">Actual \\ predicted</th>${labels.map(l => `<th>${esc(TITLES[l])}</th>`).join("")}</tr></thead><tbody>
  ${m.map((row, i) => `<tr><td class="lab">${esc(TITLES[labels[i]])}</td>${row.map((v, j) => `<td class="num" style="background:${v ? `rgba(${i === j ? "19,122,108" : "201,58,115"},${0.12 + 0.6 * v / max})` : "transparent"};font-weight:${v ? 600 : 400}">${v}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

async function viewEvaluation(view) {
  const m = await api("/api/model/metrics").catch(() => null);
  let rt = null; try { rt = await api("/api/redteam/latest"); } catch { /* none yet */ }
  view.innerHTML = head("Evaluation", "How well the models work, measured on data they were not trained on. Weak spots are listed rather than hidden.", `<button class="btn" data-action="redteam">Run red-team test</button>`) +
    `<div id="rt-slot">${rt ? renderRedteam(rt) : `<section class="block" style="margin-top:0"><div class="well">No red-team run yet. The test fires 80 hand-written attacks and 40 tricky harmless prompts at an isolated copy of AstraSec, then teaches the copy about its misses and tests again. It takes about ten seconds and does not change live memory.</div></section>`}</div>
    ${m ? renderModelMetrics(m) : `<div class="empty"><h3>No training metrics found</h3><p>Run <b>python -m training.train_all</b> to train the models and write models/metrics.json.</p></div>`}`;
}

function renderModelMetrics(m) {
  const labs = m.labels, f = m.held_out.fused, ml = m.held_out.ml_only, sg = m.held_out.signatures_only, b = m.behavior_engine, d = m.dataset;
  const row = (n, x) => `<tr><td>${n}</td><td class="num">${pct(x.accuracy, 1)}</td><td class="num">${pct(x.macro_f1, 1)}</td><td class="num">${pct(x.binary.detection_rate, 1)}</td><td class="num">${pct(x.binary.false_positive_rate, 1)}</td></tr>`;
  return `
  <section class="block"><h2>Training data</h2>
    <p class="muted" style="max-width:70ch">${d.total.toLocaleString()} prompts written from ${d.families} template families. The test set is ${d.test.toLocaleString()} prompts from ${d.held_out_families.length} whole families the model never saw, so the numbers reward generalising rather than memorising templates. ${esc(d.note)}</p>
    <div class="hbars" style="margin-top:14px;max-width:640px">${labs.map(l => `<div class="hbar"><span>${TITLES[l]}</span>${bar(d.label_counts[l] / Math.max(...Object.values(d.label_counts)), colorOf(l))}<span class="v num">${d.label_counts[l]}</span></div>`).join("")}</div>
  </section>

  <section class="block"><h2>Which classifier was chosen</h2>
    <p class="muted" style="margin-bottom:8px">Each candidate was cross-validated with whole families held out per fold. <b>${esc(m.selected_model)}</b> had the best macro-F1.</p>
    <table style="max-width:640px"><thead><tr><th>Model</th><th>CV accuracy</th><th>CV macro-F1</th><th>Time</th></tr></thead><tbody>${m.model_comparison.map(x => `<tr ${x.model === m.selected_model ? 'style="font-weight:600"' : ""}><td>${esc(x.model.replace("_", " "))}</td><td class="num">${pct(x.cv_accuracy, 1)}</td><td class="num">${pct(x.cv_macro_f1, 1)}</td><td class="num">${x.cv_seconds} s</td></tr>`).join("")}</tbody></table>
  </section>

  <section class="block split even">
    <div><h2>Held-out results</h2><p class="muted" style="margin-bottom:8px">Detection is the share of attacks flagged; false alarms are harmless prompts flagged.</p>
      <table><thead><tr><th>Configuration</th><th>Accuracy</th><th>Macro-F1</th><th>Detection</th><th>False alarms</th></tr></thead><tbody>${row("Signatures only", sg)}${row("Model only", ml)}${row("Production (both fused)", f)}</tbody></table></div>
    <div><h2>Per class, production setup</h2><table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Cases</th></tr></thead><tbody>${labs.map(l => { const x = f.per_class[l]; return `<tr><td>${chipLabel(l)}</td><td class="num">${pct(x.precision, 1)}</td><td class="num">${pct(x.recall, 1)}</td><td class="num">${pct(x.f1, 1)}</td><td class="num">${x.support}</td></tr>`; }).join("")}</tbody></table></div>
  </section>

  <section class="block"><h2>Where the production model gets confused</h2>
    <p class="muted" style="margin-bottom:10px">Rows are the true class. Off-diagonal pink cells are mistakes. Most adversarial inputs are still caught but filed under the wrong attack type, and the remaining errors are harmless prompts about AI concepts that look like attacks.</p>
    ${confusion(f.confusion_matrix, labs)}
  </section>

  <section class="block split even">
    <div><h2>Behaviour learning engine</h2>
      <p class="muted" style="margin:6px 0 10px">${esc(b.algorithm)}. ${esc(b.note)}</p>
      <div class="stat-line"><div><b class="num">${pct(b.benign_false_alarm_rate, 1)}</b><span>normal prompts flagged as unusual</span></div><div><b class="num">${pct(b.attack_flag_rate, 0)}</b><span>attacks flagged as unusual</span></div><div><b class="num">${b.roc_auc_attack_vs_benign}</b><span>ROC-AUC, attack against normal</span></div></div></div>
    <div><h2>Model separation (ROC-AUC)</h2><div class="hbars" style="margin-top:10px">${labs.map(l => `<div class="hbar"><span>${TITLES[l]}</span>${bar(m.held_out.roc_auc_ovr[l], colorOf(l))}<span class="v num">${m.held_out.roc_auc_ovr[l].toFixed(3)}</span></div>`).join("")}</div></div>
  </section>

  <section class="block"><h2>Words the model relies on</h2><div class="split even" style="gap:26px">${ATTACKS.map(l => `<div><h3>${chipLabel(l)}</h3><div class="tags" style="margin-top:8px">${(m.top_terms[l] || []).filter(t => !t.term.split(" ").every(w => STOP.has(w))).slice(0, 7).map(t => `<span class="tag">${esc(t.term)}</span>`).join("")}</div></div>`).join("")}</div></section>`;
}

function renderRedteam(r) {
  const c = r.cold_start, h = r.fresh_holdout, a = r.after_feedback;
  const ph = (t, sub, x) => `<div><h3>${t}</h3><p class="muted small" style="margin-bottom:8px">${sub}</p><div class="big num">${pct(x.detection_rate, 1)}</div><p class="small">of attacks detected</p>
    <div class="kv small" style="margin-top:8px"><span>Caught at input <b class="num">${pct(x.input_detection_rate, 1)}</b></span><span>Right type <b class="num">${pct(x.type_accuracy, 1)}</b></span><span>Harmless flagged <b class="num">${pct(x.false_positive_rate, 1)}</b></span></div></div>`;
  return `
  <section class="block" style="margin-top:0"><h2>Red-team test</h2>
    <p class="muted" style="max-width:72ch;margin-bottom:16px">${esc(r.note)} Ran ${new Date(r.generated_at * 1000 || r.generated_at).toString() === "Invalid Date" ? "" : "on " + esc(String(r.generated_at))} in ${r.seconds} s against ${esc(r.chatbot)}.</p>
    <div class="phase">${ph("First contact", `${c.n_attacks} hand-written attacks, ${c.n_benign} harmless prompts, no prior knowledge`, c)}${ph("Fresh set", `${h.n_attacks} new attacks written after the first run, never used anywhere`, h)}${ph("After learning", "The first set again, reworded, after the misses were reported", a)}</div>
  </section>

  <section class="block split even">
    <div><h2>Did the attacks work?</h2><p class="muted" style="margin-bottom:10px">Share of attacks that made the demo assistant do something unsafe.</p>
      <div class="hbars">
        <div class="hbar" style="grid-template-columns:150px 1fr 52px"><span>Without AstraSec</span>${bar(c.asr_unprotected, "var(--eosin)")}<span class="v num">${pct(c.asr_unprotected, 1)}</span></div>
        <div class="hbar" style="grid-template-columns:150px 1fr 52px"><span>With AstraSec</span>${bar(c.asr_protected, "var(--healthy)")}<span class="v num">${pct(c.asr_protected, 1)}</span></div></div>
      <p class="muted small" style="margin-top:10px">Some attacks slip past the input check and are stopped when the reply is screened, which is why protected success is lower than input detection.</p></div>
    <div><h2>By attack type</h2><table><thead><tr><th>Type</th><th>Detected</th><th>Right type</th><th>Unprotected</th></tr></thead><tbody>${Object.entries(c.per_class).map(([k, x]) => `<tr><td>${chipLabel(k)}</td><td class="num">${x.detected}/${x.n}</td><td class="num">${x.type_correct}/${x.n}</td><td class="num">${pct(x.asr_unprotected)}</td></tr>`).join("")}</tbody></table>
      <p class="muted small" style="margin-top:10px">Response time: median ${c.latency_ms.p50} ms, 95th percentile ${c.latency_ms.p95} ms.</p></div>
  </section>

  <section class="block split even">
    <div><h2>Attacks that got past the input check</h2>${c.missed.length ? `<table><tbody>${c.missed.map(x => `<tr><td>${esc(x.prompt)}<br><span class="muted small">${esc(TITLES[x.truth] || x.truth)}</span></td></tr>`).join("")}</tbody></table>` : `<p class="muted">None.</p>`}</div>
    <div><h2>Harmless prompts that were flagged</h2>${c.false_positives.length ? `<table><tbody>${c.false_positives.map(x => `<tr><td>${esc(x.prompt)}<br><span class="muted small">Called ${esc(TITLES[x.pred] || x.pred)}, ${esc((ACTION_TEXT[x.action] || x.action).toLowerCase())}</span></td></tr>`).join("")}</tbody></table>` : `<p class="muted">None.</p>`}</div>
  </section>`;
}

/* ------------------------------------------------------------------ actions for these views */
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-action]"); if (!el) return;
  const a = el.dataset.action;
  if (a === "retrain") {
    el.disabled = true;
    try { await api("/api/retrain", { method: "POST" }); const note = await pollRetrain(); await route(); const box = $("#mem-notes"); if (box) box.innerHTML = note || ""; } catch (err) { toast(err.message, true); }
    el.disabled = false;
  } else if (a === "recommend") {
    el.disabled = true; toast("Working out recommendations…");
    try {
      const r = await api("/api/recommendations", { method: "POST" });
      $("#mem-notes").innerHTML = `<div class="panel" style="margin-bottom:26px"><h2>Recommendations</h2><p class="muted small" style="margin:4px 0 8px">${esc(r.summary)} Source: ${esc(r.source)}.</p>${r.recommendations.map(x => `<div class="finding"><div>${sevChip(x.priority)}</div><div><b>${esc(x.title)}</b><p>${esc(x.why)}</p><p style="color:var(--ink)">${esc(x.action)}</p></div></div>`).join("")}</div>`;
    } catch (err) { toast(err.message, true); }
    el.disabled = false;
  } else if (a === "propose") {
    el.disabled = true;
    try { const r = await api("/api/signatures/propose", { method: "POST" }); toast(r.error || r.note || (r.proposed ? `${r.proposed} rule(s) proposed, waiting for approval.` : "No new rules proposed.")); route(); }
    catch (err) { toast(err.message, true); }
    el.disabled = false;
  } else if (a === "sigstatus") {
    try { await api(`/api/signatures/${encodeURIComponent(el.dataset.sid)}/status`, { method: "POST", body: { status: el.dataset.status } }); toast(`${el.dataset.sid} is now ${el.dataset.status}.`); route(); } catch (err) { toast(err.message, true); }
  } else if (a === "scan") {
    el.disabled = true;
    try {
      const r = await api("/api/risk/dependencies", { method: "POST", body: { requirements: $("#req-text").value } });
      $("#scan-out").innerHTML = `<p><b>${r.packages}</b> packages scanned, <b>${r.findings.length}</b> with known vulnerabilities (${esc(r.source)}).</p>` +
        (r.findings.length ? r.findings.map(f => `<div class="finding"><div>${sevChip(f.severity)}</div><div><b>${esc(f.package)}</b> <span class="muted small">${esc(f.id)}</span><p>${esc(f.title)}</p><p style="color:var(--ink)">${esc(f.fix)}</p></div></div>`).join("") : "");
    } catch (err) { toast(err.message, true); }
    el.disabled = false;
  } else if (a === "redteam") {
    el.disabled = true; el.textContent = "Running…";
    try { const r = await api("/api/redteam/run", { method: "POST" }); $("#rt-slot").innerHTML = renderRedteam(r); toast("Red-team test finished."); }
    catch (err) { toast(err.message, true); }
    el.disabled = false; el.textContent = "Run red-team test";
  }
});
