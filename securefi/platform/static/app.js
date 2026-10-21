"use strict";

const $ = (selector) => document.querySelector(selector);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const tag = (value, css = value) =>
  `<span class="tag ${esc(css)}">${esc(String(value).replaceAll("_", " "))}</span>`;
const can = (...roles) =>
  state?.role === "admin" || roles.includes(state?.role);
let token = sessionStorage.getItem("securefi-access") || "";
let state,
  tab = "soc";
const filters = { query: "", severity: "all", status: "active", source: "all" };
const pages = {
  soc: [
    "Overview",
    "Your current exposure, investigations and response activity.",
  ],
  alerts: [
    "Alert inbox",
    "Prioritise findings, assign ownership and record triage decisions.",
  ],
  cases: [
    "Cases & response",
    "Keep investigation notes, approvals and response evidence together.",
  ],
  assets: [
    "Asset inventory",
    "Add business context to the assets behind your alerts.",
  ],
  detections: [
    "Detection library",
    "Versioned detection logic, ATT&CK relationships and tuning context.",
  ],
  cloud: [
    "Cloud & Kubernetes",
    "Review cloud configuration and container security observations.",
  ],
  ai: [
    "AI security & models",
    "Monitor AI threat signals and manage approved anomaly models.",
  ],
  web3: [
    "Web3 monitoring",
    "Investigate wallet and contract observations from development-chain telemetry.",
  ],
  compliance: [
    "Controls & evidence",
    "Preserve reviewable reports and verify their recorded integrity.",
  ],
  activity: [
    "Activity log",
    "Trace changes, decisions and approvals in this workspace.",
  ],
};

async function api(path, body) {
  const response = await fetch("/api/" + path, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: "Bearer " + token,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The request failed.");
  return result;
}
function notify(message) {
  $("#notice").textContent = message;
  $("#notice").hidden = false;
}
async function refresh() {
  state = await api("state");
  render();
}
function modal(title, html) {
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = html;
  $("#error").textContent = "";
  if (!$("#modal").open) $("#modal").showModal();
}
function bindForm(selector, handler, success = "Changes saved.") {
  $(selector).onsubmit = async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector(
      'button[type="submit"],button',
    );
    if (button) button.disabled = true;
    try {
      const result = await handler(new FormData(event.currentTarget));
      $("#modal").close();
      await refresh();
      notify(typeof success === "function" ? success(result) : success);
    } catch (error) {
      $("#error").textContent = error.message;
    } finally {
      if (button) button.disabled = false;
    }
  };
}
async function action(button, path, body, message) {
  if (button) button.disabled = true;
  try {
    const result = await api(path, body);
    await refresh();
    notify(message);
    return result;
  } catch (error) {
    notify(error.message);
  } finally {
    if (button) button.disabled = false;
  }
}
function selectOptions(values, selected) {
  return values
    .map(
      ([value, label]) =>
        `<option value="${esc(value)}" ${String(value) === String(selected) ? "selected" : ""}>${esc(label)}</option>`,
    )
    .join("");
}
function download(value, filename) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function empty(title, message, button = "") {
  return `<div class="empty"><h3>${esc(title)}</h3><p>${esc(message)}</p>${button}</div>`;
}
function alertTable(alerts) {
  if (!alerts.length)
    return empty(
      "No matching alerts",
      "Import event data or adjust your inbox filters.",
    );
  return `<div class="table"><table><thead><tr><th>Detection / asset</th><th>Priority</th><th>Source</th><th>Owner</th><th>Status</th></tr></thead><tbody>${alerts.map((a) => `<tr><td><button class="link" data-alert="${esc(a.id)}">${esc(a.name)}</button><small>${esc(a.rule_id)} · ${esc(a.asset)}</small></td><td>${tag(a.severity)}<small>${a.risk.score}/100</small></td><td>${esc(a.source)}</td><td>${esc(a.assignee || "Unassigned")}</td><td>${tag(a.status)}${a.acceptance_expired ? "<small>Acceptance expired</small>" : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

function overview() {
  const m = state.metrics,
    alerts = (state.alerts || []).filter((a) => a.active !== false);
  $("#content").innerHTML = `<div class="metrics">${[
    ["Active alerts", m.active_alerts ?? m.alerts, "Awaiting investigation"],
    ["High priority", m.high_risk, "Risk score 80 or above"],
    ["Open cases", m.open_cases, "Investigation in progress"],
    ["Events processed", m.events, "Across your workspace"],
  ]
    .map(
      ([label, value, note], i) =>
        `<div class="metric ${i === 1 ? "urgent" : ""}"><span class="metric-label">${label}</span><strong>${value}</strong><small>${note}</small></div>`,
    )
    .join("")}</div>
  <div class="grid"><section class="panel"><div class="panel-head"><h2>Priority queue</h2>${tag("Highest risk first", "good")}</div>${state.alerts ? alertTable(alerts.slice(0, 6)) : empty("Executive overview", "This access profile displays aggregate operational metrics.")}</section>
  <section class="panel"><h2>Exposure by source</h2>${[
    "identity",
    "cloud",
    "kubernetes",
    "endpoint",
    "network",
    "application",
    "ai",
    "web3",
  ]
    .map((source) => {
      const count = state.alerts
        ? alerts.filter((a) => a.source === source).length
        : state.source_counts?.[source] || 0;
      return `<div class="bar-row"><span>${source === "ai" ? "AI systems" : source[0].toUpperCase() + source.slice(1)}</span><strong>${count}</strong></div><progress value="${count}" max="${Math.max(1, m.active_alerts ?? alerts.length)}" aria-label="${source} active alerts"></progress>`;
    })
    .join("")}</section></div>
  <div class="grid"><section class="panel"><h2>Response coordination</h2><div class="stat-line"><span>Detection rules</span><strong>${state.rules.length}</strong></div><div class="stat-line"><span>Approval-controlled playbooks</span><strong>${state.playbooks.length}</strong></div><div class="stat-line"><span>Completed simulation runs</span><strong>${m.completed_runs}</strong></div><p class="muted">Response actions use a reversible simulation adapter and a separate approving identity.</p></section>
  <section class="panel"><h2>Workspace readiness</h2><p class="muted">Inspect your event pipeline and add asset ownership before assessing exposure.</p><p class="code">Queue: ${esc(JSON.stringify(m.jobs))}</p>${can("ingestor") ? '<p><button id="process-queue" class="secondary">Process queued events</button></p>' : ""}${can("analyst") ? '<button id="load-samples" class="secondary">Load sample telemetry</button>' : ""}<div class="callout">AI drafts support investigation. Human review remains part of the decision.</div></section></div>`;
  if ($("#process-queue"))
    $("#process-queue").onclick = (e) =>
      action(
        e.currentTarget,
        "worker",
        {},
        "Queued events processed. Refresh the queue totals for remaining work.",
      );
  if ($("#load-samples"))
    $("#load-samples").onclick = (e) =>
      action(
        e.currentTarget,
        "sample-data",
        {},
        "Sample telemetry loaded. Existing IDs were deduplicated.",
      );
}
function inbox() {
  $("#content").innerHTML =
    `<div class="toolbar"><input id="search" aria-label="Search alerts" placeholder="Search detection, asset, owner or rule ID" value="${esc(filters.query)}"><select id="severity-filter" aria-label="Severity">${selectOptions([["all", "All severities"], ...["critical", "high", "medium", "low"].map((s) => [s, s])], filters.severity)}</select><select id="status-filter" aria-label="Status">${selectOptions([["active", "Active alerts"], ["all", "All statuses"], ...["new", "triaged", "in_progress", "false_positive", "risk_accepted", "resolved"].map((s) => [s, s.replaceAll("_", " ")])], filters.status)}</select><select id="source-filter" aria-label="Source">${selectOptions([["all", "All sources"], ...["identity", "cloud", "kubernetes", "endpoint", "network", "application", "ai", "web3"].map((s) => [s, s])], filters.source)}</select></div><section class="panel" id="alert-results"></section>`;
  const filter = () => {
    const alerts = (state.alerts || []).filter(
      (a) =>
        (filters.status === "all" ||
          (filters.status === "active"
            ? a.active
            : a.status === filters.status)) &&
        (filters.severity === "all" || a.severity === filters.severity) &&
        (filters.source === "all" || a.source === filters.source) &&
        [a.name, a.asset, a.assignee, a.rule_id]
          .join(" ")
          .toLowerCase()
          .includes(filters.query.toLowerCase()),
    );
    $("#alert-results").innerHTML = alertTable(alerts);
  };
  $("#search").oninput = (e) => {
    filters.query = e.target.value;
    filter();
  };
  for (const [selector, key] of [
    ["#severity-filter", "severity"],
    ["#status-filter", "status"],
    ["#source-filter", "source"],
  ])
    $(selector).onchange = (e) => {
      filters[key] = e.target.value;
      filter();
    };
  filter();
}
function assets() {
  const items = state.assets || [];
  $("#content").innerHTML =
    `<section class="panel"><div class="panel-head"><h2>Business asset register</h2>${can("analyst") ? '<button id="add-asset">Register asset</button>' : ""}</div><p class="muted">Registered criticality and exposure update alert priority and enrich future observations.</p>${items.length ? `<div class="table"><table><thead><tr><th>Asset</th><th>Owner</th><th>Criticality</th><th>Exposure</th><th>Context</th></tr></thead><tbody>${items.map((a) => `<tr><td>${can("analyst") ? `<button class="link" data-asset="${esc(a.id)}">${esc(a.name)}</button>` : esc(a.name)}</td><td>${esc(a.owner)}</td><td>${a.criticality}/5</td><td>${a.internet_exposed ? "Internet-facing" : "Internal"}</td><td>${tag(a.registered ? "registered" : "observed")}</td></tr>`).join("")}</tbody></table></div>` : empty("Build your asset inventory", "Register an asset or import event observations to discover asset names.")}</section>`;
  if ($("#add-asset")) $("#add-asset").onclick = () => assetDialog();
}
function cases() {
  $("#content").innerHTML =
    `<section class="panel"><h2>Investigation register</h2>${(state.cases || []).length ? state.cases.map((c) => `<div class="detail"><div class="panel-head"><button class="link" data-case="${esc(c.id)}">${esc(c.reference || c.id.slice(0, 8))} · ${esc(c.title)}</button>${tag(c.status)}</div><p class="muted">${esc(c.owner)} · ${esc(c.asset)} · ${esc(new Date(c.created_at).toLocaleString())}</p><p>${esc(c.notes.at(-1))}</p><div class="actions"><button class="secondary" data-case="${esc(c.id)}">Open investigation</button>${can("analyst", "cloud") ? `<button data-request="${esc(c.id)}">Request response</button>` : ""}</div></div>`).join("") : empty("No open investigations", "Open an alert and record your investigation to create a case.")}</section><section class="panel"><h2>Response approval queue</h2>${(state.runs || []).length ? state.runs.map((r) => `<div class="detail"><div class="panel-head"><strong>${esc(r.playbook.replaceAll("_", " "))}</strong>${tag(r.status)}</div><p class="muted">Requested by ${esc(r.requested_by)} · Expires ${esc(new Date(r.expires_at).toLocaleString())}</p><small>Execution mode: simulation</small><div class="actions">${r.status === "pending_approval" && can("approver") ? `<button data-approve="${esc(r.id)}">Review approval</button>` : ""}${r.status === "approved" && can("analyst", "cloud", "approver") ? `<button data-execute="${esc(r.id)}">Execute simulation</button>` : ""}${r.status === "completed" && can("analyst", "cloud", "approver") ? `<button class="secondary" data-rollback="${esc(r.id)}">Restore before-state</button>` : ""}</div></div>`).join("") : empty("No responses requested", "Approved actions and their outcomes appear here.")}</section>`;
}
function detections() {
  $("#content").innerHTML =
    `<section class="panel"><h2>Versioned detection library</h2><p class="muted">Each rule includes source requirements, false-positive context and a response recommendation. ATT&CK relationships distinguish observed behaviour from control gaps and analogies.</p><div class="table"><table><thead><tr><th>Rule</th><th>Source</th><th>ATT&CK</th><th>Relationship</th><th>Severity</th></tr></thead><tbody>${state.rules.map((r) => `<tr><td><button class="link" data-rule="${esc(r.id)}">${esc(r.id)} · ${esc(r.name)}</button><small>${esc(r.false_positives)}</small></td><td>${esc(r.source)}</td><td>${esc(r.attack.technique)}</td><td>${esc(r.attack.relationship.replaceAll("_", " "))}</td><td>${tag(r.severity)}</td></tr>`).join("")}</tbody></table></div></section>`;
}
function sourceView(sources, title, note) {
  $("#content").innerHTML =
    `<section class="panel"><h2>${esc(title)}</h2><p class="muted">${esc(note)}</p>${alertTable((state.alerts || []).filter((a) => sources.includes(a.source)))}</section>`;
}
function aiView() {
  sourceView(
    ["ai"],
    "AI threat monitoring",
    "Review prompt, output, tool-permission, deployment and model-integrity indicators.",
  );
  $("#content").innerHTML +=
    `<section class="panel"><div class="panel-head"><h2>Behavioural model registry</h2>${can("analyst") ? '<button id="train">Train sample baselines</button>' : ""}</div><p class="muted">Candidate models need a separate approver before activation. Metrics describe the included synthetic dataset.</p>${(state.models || []).map((m) => `<div class="detail"><div class="panel-head"><strong>Model ${esc(m.id.slice(0, 8))}</strong>${tag(m.status)}</div><p class="code">SHA-256 ${esc(m.model_sha256)}</p><p>Precision ${m.evaluation.supervised_logistic.precision.toFixed(3)} · Recall ${m.evaluation.supervised_logistic.recall.toFixed(3)} · F1 ${m.evaluation.supervised_logistic.f1.toFixed(3)}</p><small>Trainer: ${esc(m.trained_by)}</small>${can("approver") ? `<p><button data-promote="${esc(m.id)}">Approve and activate version</button></p>` : ""}</div>`).join("") || empty("No trained models", "Train a candidate, inspect its holdout results and request independent promotion.")}</section>`;
  if ($("#train"))
    $("#train").onclick = (e) =>
      action(
        e.currentTarget,
        "models/train",
        {},
        "Model candidate created. A separate approver can activate it.",
      );
}
function compliance() {
  $("#content").innerHTML =
    `<section class="panel"><div class="panel-head"><h2>Evidence reports</h2><div class="actions">${can("compliance", "analyst") ? '<button id="report">Generate report</button><button id="audit" class="secondary">Verify audit chain</button>' : ""}</div></div><p class="muted">Reports capture cases, asset context, approvals and AI draft provenance. Candidate control mappings need review.</p>${(state.evidence || []).map((e) => `<div class="detail"><div class="panel-head"><strong>${esc(new Date(e.created_at).toLocaleString())}</strong>${tag(e.attestation ? "hash recorded" : "local snapshot")}</div><p class="code">${esc(e.digest)}</p><div class="actions"><button data-evidence="${esc(e.id)}">Download JSON</button><button class="secondary" data-ledger-verify="${esc(e.id)}">Verify document</button>${state.integrations?.blockchain_enabled ? `<button class="secondary" data-anchor="${esc(e.id)}">Record hash</button>` : ""}</div></div>`).join("") || empty("No evidence reports", "Generate a report after reviewing your cases and response outcomes.")}</section><div class="grid"><section class="panel"><h2>Evidence registry connection</h2><p class="muted">Optional Solidity hash registry on development chain 31337. Only the hash is recorded; report contents stay off-chain.</p>${state.integrations?.blockchain_enabled && can("approver") ? '<button id="deploy-ledger" class="secondary">Deploy or check registry</button>' : tag(state.integrations?.blockchain_enabled ? "Enabled" : "Not configured")}<p class="muted">A local-chain record establishes a digest match, not the truth of the evidence.</p></section><section class="panel"><h2>Assurance boundary</h2><p class="muted">Audit links need an independently retained checkpoint to detect full rewriting or truncation. Review applicability before drawing a compliance conclusion.</p></section></div><section class="panel"><h2>Control register</h2>${state.controls.map((c) => `<details class="detail"><summary><strong>${esc(c.id)} · ${esc(c.title)}</strong></summary><p>${esc(c.evidence)}</p><p class="code">${esc(JSON.stringify(c.mappings, null, 2))}</p></details>`).join("")}</section>`;
  if ($("#report"))
    $("#report").onclick = (e) =>
      action(e.currentTarget, "evidence", {}, "Evidence report created.");
  if ($("#audit"))
    $("#audit").onclick = async () => {
      try {
        notify(JSON.stringify(await api("audit")));
      } catch (e) {
        notify(e.message);
      }
    };
  if ($("#deploy-ledger"))
    $("#deploy-ledger").onclick = (e) =>
      action(
        e.currentTarget,
        "ledger/deploy",
        {},
        "Development-chain registry is available.",
      );
}
async function activity() {
  $("#content").innerHTML =
    '<section class="panel"><h2>Workspace activity</h2><p class="muted">Loading recent activity…</p></section>';
  try {
    const entries = await api("activity");
    if (tab !== "activity") return;
    $("#content").innerHTML =
      `<section class="panel"><h2>Recent changes and decisions</h2>${entries.map((e) => `<div class="timeline"><strong>${esc(e.action.replaceAll(".", " · "))}</strong><p>${esc(e.actor)} · ${esc(new Date(e.at).toLocaleString())}</p><p class="code">${esc(JSON.stringify(e.details))}</p></div>`).join("") || empty("No activity yet", "Your workspace changes and review decisions appear here.")}</section>`;
  } catch (e) {
    notify(e.message);
  }
}
function render() {
  $("#identity").textContent = state.tenant + " / " + state.role;
  if (
    ["executive", "ingestor"].includes(state.role) &&
    !["soc", "detections", "compliance"].includes(tab)
  )
    tab = "soc";
  $("#title").textContent = pages[tab][0];
  $("#subtitle").textContent = pages[tab][1];
  document.querySelectorAll("[data-tab]").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tab);
    b.hidden =
      (["executive", "ingestor"].includes(state.role) &&
        !["soc", "detections", "compliance"].includes(b.dataset.tab)) ||
      (state.role === "cloud" && b.dataset.tab === "activity");
  });
  $("#import").hidden = !can("analyst", "ingestor", "cloud");
  const views = {
    soc: overview,
    alerts: inbox,
    assets,
    cases,
    detections,
    cloud: () =>
      sourceView(
        ["cloud", "kubernetes"],
        "Cloud configuration and workload exposure",
        "Findings reflect imported observations; this application does not scan a cloud account automatically.",
      ),
    ai: aiView,
    web3: () =>
      sourceView(
        ["web3"],
        "Development-chain observations",
        "Synthetic approval, transfer and contract events. Production-chain data and real funds are excluded.",
      ),
    compliance,
    activity,
  };
  views[tab]();
}

function alertDialog(id) {
  const alert = state.alerts.find((a) => a.id === id);
  modal(
    alert.name,
    `<div class="panel-head">${tag(alert.severity)} ${tag(alert.status)}<small>${esc(alert.rule_id)} · ${esc(alert.source)}</small></div><p>${esc(alert.recommended_action)}</p><p class="muted">${esc(alert.asset)} · ATT&CK ${esc(alert.attack.technique || "Not mapped")} · ${esc(alert.attack.relationship.replaceAll("_", " "))}</p><details><summary>Explain priority score: ${alert.risk.score}/100</summary><pre class="code">${esc(JSON.stringify(alert.risk, null, 2))}</pre></details><h3>Source evidence</h3><div class="actions">${alert.evidence_ids.map((id) => `<button class="secondary" data-event="${esc(id)}">${esc(id)}</button>`).join("")}</div>${
      can("analyst", "cloud")
        ? `<form id="triage-form"><h3>Triage decision</h3><div class="two"><label>Status<select name="status">${selectOptions(
            [
              "new",
              "triaged",
              "in_progress",
              "false_positive",
              "risk_accepted",
              "resolved",
            ].map((v) => [v, v.replaceAll("_", " ")]),
            alert.status === "investigating" ? "in_progress" : alert.status,
          )}</select></label><label>Assigned owner<input name="assignee" maxlength="120" value="${esc(alert.assignee || "")}"></label></div><label>Risk acceptance expiry<input type="date" name="accepted_until" value="${esc(alert.accepted_until || "")}"></label><label>Decision note<textarea name="note" required maxlength="4000">${esc(alert.triage_note || "")}</textarea></label><label>Verification evidence (required to resolve)<textarea name="verification" maxlength="4000">${esc(alert.verification || "")}</textarea></label><button type="submit">Save triage</button></form><form id="case-form"><h3>Start an investigation</h3><label>Initial investigation note<textarea name="note" required maxlength="4000"></textarea></label><button type="submit">Open case</button></form>`
        : ""
    }`,
  );
  if ($("#triage-form"))
    bindForm("#triage-form", (f) =>
      api("alerts/triage", { id, ...Object.fromEntries(f) }),
    );
  if ($("#case-form"))
    bindForm("#case-form", (f) =>
      api("cases", { alert_id: id, note: f.get("note") }),
    );
}
function assetDialog(id) {
  const asset = (state.assets || []).find((a) => a.id === id) || {};
  modal(
    asset.name ? "Update asset context" : "Register an asset",
    `<form id="asset-form"><label>Asset name<input name="name" required maxlength="120" value="${esc(asset.name || "")}" ${asset.name ? "readonly" : ""}></label><label>Owner / team<input name="owner" required maxlength="120" value="${esc(asset.owner === "Unassigned" ? "" : asset.owner || "")}"></label><div class="two"><label>Business criticality<select name="criticality">${selectOptions(
      [1, 2, 3, 4, 5].map((v) => [v, v + " / 5"]),
      asset.criticality || 3,
    )}</select></label><label>Environment<select name="environment">${selectOptions(
      ["test", "staging", "production"].map((v) => [v, v]),
      asset.environment || "test",
    )}</select></label></div><label>Exposure<select name="internet_exposed">${selectOptions(
      [
        ["false", "Internal"],
        ["true", "Internet-facing"],
      ],
      String(!!asset.internet_exposed),
    )}</select></label><label>Reason for this context update<textarea name="note" required maxlength="4000"></textarea></label><button type="submit">Save asset</button></form>`,
  );
  bindForm("#asset-form", (f) =>
    api("assets", {
      ...Object.fromEntries(f),
      criticality: Number(f.get("criticality")),
      internet_exposed: f.get("internet_exposed") === "true",
    }),
  );
}
function caseDialog(id) {
  const c = state.cases.find((c) => c.id === id),
    drafts = (state.assistant_drafts || []).filter((d) => d.case_id === id);
  const transitions = {
    investigating: ["investigating", "contained", "resolved"],
    contained: ["contained", "investigating", "resolved"],
    resolved: ["resolved", "closed", "investigating"],
    closed: ["closed", "investigating"],
  };
  modal(
    (c.reference || "Case") + " · " + c.title,
    `<div class="panel-head">${tag(c.status)}<small>${esc(c.asset)}</small></div><h3>Investigation timeline</h3>${(
      c.activity ||
      c.notes.map((note) => ({ note, at: c.created_at, actor: c.owner }))
    )
      .slice(-20)
      .map(
        (a) =>
          `<div class="timeline"><small>${esc(a.actor)} · ${esc(new Date(a.at).toLocaleString())}</small><p>${esc(a.note)}</p></div>`,
      )
      .join("")}${
      can("analyst", "cloud")
        ? `<form id="case-update-form"><div class="two"><label>Case status<select name="status">${selectOptions(
            transitions[c.status].map((v) => [v, v]),
            c.status,
          )}</select></label><label>Owner<input name="owner" required maxlength="120" value="${esc(c.owner)}"></label></div><label>Investigation update<textarea name="note" required maxlength="4000"></textarea></label><label>Verification evidence (required to resolve or close)<textarea name="verification" maxlength="4000">${esc(c.verification || "")}</textarea></label><button type="submit">Save investigation update</button></form><h3>Investigation assistant</h3><p class="muted">Configured provider: ${esc(state.integrations?.ai_provider || "rules")}. Drafts do not execute actions or close cases.</p><button data-draft="${esc(c.id)}" class="secondary">Generate investigation draft</button>`
        : ""
    }${drafts.map((d) => `<div class="detail"><div class="panel-head"><strong>${d.provider === "ollama" ? "AI · " + esc(d.model) : "Deterministic fallback"}</strong>${tag(d.status)}</div>${d.fallback_reason ? `<p class="muted">${esc(d.fallback_reason)}</p>` : ""}<p>${esc(d.draft.summary)}</p><ol>${d.draft.investigation_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>${d.status === "pending" && can("analyst", "cloud") ? `<button data-draft-review="${esc(d.id)}" class="secondary">Review draft</button>` : `<p class="muted">${esc(d.review_note || "")}</p>`}</div>`).join("")}`,
  );
  if ($("#case-update-form"))
    bindForm("#case-update-form", (f) =>
      api("cases/update", { id, ...Object.fromEntries(f) }),
    );
}
function responseDialog(caseId) {
  const c = state.cases.find((c) => c.id === caseId),
    alert = state.alerts.find((a) => a.id === c.alert_id);
  modal(
    "Request a response approval",
    `<p class="muted">${esc(c.reference || "Case")} · ${esc(c.title)}</p><form id="run-form"><label>Playbook<select name="playbook">${selectOptions(
      state.playbooks.map((p) => [p.id, p.title]),
      alert?.playbook,
    )}</select></label><div class="callout">The selected playbook changes a synthetic resource through the simulation adapter. A separate identity must approve it before execution.</div><button type="submit">Request independent approval</button></form>`,
  );
  bindForm("#run-form", (f) =>
    api("runs", { case_id: caseId, playbook: f.get("playbook") }),
  );
}
function importDialog() {
  modal(
    "Import event observations",
    `<p class="muted">Upload a JSON event array, an object with an events array, or JSON Lines. Maximum 2 MiB / 500 events. This release requires explicitly synthetic telemetry; use examples/sample-events.json as the contract reference.</p><form id="import-form"><label>Event file<input name="file" type="file" accept=".json,.jsonl,.ndjson" required></label><label>Processing mode<select name="queued"><option value="false">Process immediately</option><option value="true">Place in durable processing queue</option></select></label><button type="submit">Import events</button></form>`,
  );
  bindForm(
    "#import-form",
    async (f) => {
      const file = f.get("file");
      if (file.size > 2 * 1024 * 1024) throw Error("File exceeds 2 MiB");
      const text = (await file.text()).trim();
      let document;
      try {
        document = JSON.parse(text);
      } catch {
        document = text
          .split(/\r?\n/)
          .filter(Boolean)
          .map((line) => JSON.parse(line));
      }
      const events = Array.isArray(document)
        ? document
        : document.events || (document.event_id ? [document] : document);
      if (!Array.isArray(events))
        throw Error("The file must contain an event array");
      const result = await api("events", {
        events,
        queued: f.get("queued") === "true",
      });
      return result;
    },
    (result) =>
      `${result.accepted} accepted, ${result.duplicates} duplicates. ${result.queued ? "Queued for processing." : "Detection complete."}`,
  );
}
document.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const d = button.dataset;
  try {
    if (d.alert) alertDialog(d.alert);
    if (d.asset) assetDialog(d.asset);
    if (d.case) caseDialog(d.case);
    if (d.request) responseDialog(d.request);
    if (d.event) {
      const source = await api("events/detail", { id: d.event });
      modal(
        "Source observation",
        `<pre class="code">${esc(JSON.stringify(source, null, 2))}</pre>`,
      );
    }
    if (d.rule) {
      const rule = state.rules.find((r) => r.id === d.rule);
      modal(
        rule.name,
        `<p>${esc(rule.false_positives)}</p><pre class="code">${esc(JSON.stringify(rule, null, 2))}</pre>`,
      );
    }
    if (d.approve) {
      modal(
        "Review response approval",
        `<form id="approve-form"><label>Decision<select name="decision"><option value="approve">Approve bounded simulation</option><option value="reject">Reject</option></select></label><label>Review note<textarea name="note" required maxlength="4000"></textarea></label><button type="submit">Record decision</button></form>`,
      );
      bindForm("#approve-form", (f) =>
        api("runs/approve", { id: d.approve, ...Object.fromEntries(f) }),
      );
    }
    if (d.execute)
      await action(
        button,
        "runs/execute",
        { id: d.execute },
        "Simulation completed; before-state is available for recovery.",
      );
    if (d.rollback)
      await action(
        button,
        "runs/execute",
        { id: d.rollback, rollback: true },
        "Before-state restored.",
      );
    if (d.promote)
      await action(
        button,
        "models/promote",
        { id: d.promote },
        "Model version activated.",
      );
    if (d.draft) {
      const result = await action(
        button,
        "assistant/generate",
        { case_id: d.draft },
        "Draft created. Check its provider and validate the suggestions.",
      );
      if (result) caseDialog(d.draft);
    }
    if (d.draftReview) {
      modal(
        "Review investigation draft",
        `<form id="draft-review-form"><label>Decision<select name="decision"><option value="approved">Approve for reference</option><option value="rejected">Reject</option></select></label><label>Review note<textarea name="note" required maxlength="4000"></textarea></label><button type="submit">Record review</button></form>`,
      );
      bindForm("#draft-review-form", (f) =>
        api("assistant/review", {
          id: d.draftReview,
          ...Object.fromEntries(f),
        }),
      );
    }
    if (d.evidence)
      download(
        state.evidence.find((e) => e.id === d.evidence),
        "securefi-evidence-" + d.evidence + ".json",
      );
    if (d.anchor)
      await action(
        button,
        "ledger/anchor",
        { id: d.anchor },
        "Evidence hash recorded on the development chain.",
      );
    if (d.ledgerVerify) {
      const result = await api("ledger/verify", { id: d.ledgerVerify });
      modal(
        "Evidence verification",
        `<h3>${result.verified ? "Verified against the current development chain" : "Verification result"}</h3><p>Matches document: <strong>${result.matches_document ? "Yes" : "No"}</strong></p><p>Recorded on chain: <strong>${result.recorded_on_chain ? "Yes" : "No"}</strong></p><p>${esc(result.reason || "This verifies a digest match, not evidence truth or compliance.")}</p><pre class="code">${esc(JSON.stringify(result, null, 2))}</pre>`,
      );
    }
  } catch (error) {
    notify(error.message);
  }
});
$("#login-form").onsubmit = async (event) => {
  event.preventDefault();
  token = $("#token").value.trim();
  try {
    await refresh();
    sessionStorage.setItem("securefi-access", token);
    $("#login").hidden = true;
    $("#workspace").hidden = false;
    $("#token").value = "";
    $("#login-error").textContent = "";
  } catch (error) {
    $("#login-error").textContent = error.message;
  }
};
$("#logout").onclick = () => {
  token = "";
  state = null;
  sessionStorage.removeItem("securefi-access");
  $("#workspace").hidden = true;
  $("#login").hidden = false;
};
$("#refresh").onclick = () => refresh().catch((e) => notify(e.message));
$("#import").onclick = importDialog;
$("#close").onclick = () => $("#modal").close();
document.querySelectorAll("[data-tab]").forEach(
  (button) =>
    (button.onclick = () => {
      tab = button.dataset.tab;
      render();
    }),
);
if (token) {
  $("#token").value = token;
  $("#login-form").dispatchEvent(new Event("submit", { cancelable: true }));
}
