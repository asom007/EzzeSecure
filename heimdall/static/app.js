"use strict";

const state = { csrf: null, user: null, route: "overview", data: null, request: 0, serverId: "local-demo", servers: [] };
const $ = (id) => document.getElementById(id);
const views = [
  ["MONITOR", "overview", "◫", "Overview", "The signals that matter. All in one place."],
  ["", "servers", "▤", "Servers", "Registered infrastructure and its latest observed state."],
  ["", "sites", "◎", "Sites", "Configured websites and bounded traffic observations."],
  ["", "health", "♡", "Health", "Resource health, application checks, and service availability."],
  ["", "security", "⬡", "Security", "Observed events and traffic signals from the selected server."],
  ["", "incidents", "⚑", "Incidents", "Investigate conditions that need your attention."],
  ["", "metrics", "▥", "Metrics", "Collected measurements over time. Evidence, not estimates."],
  ["OPERATE", "services", "⌘", "Services", "The observed state of registered services."],
  ["", "jobs", "◷", "Jobs & scheduler", "Scheduled tasks, queue health, and recent job activity."],
  ["", "commands", "›_", "Command center", "Ask a question or propose an action in plain language."],
  ["", "approvals", "✓", "Approvals", "Review the exact action before explicitly confirming execution."],
  ["INTELLIGENCE", "analyses", "✧", "AI analyses", "Evidence-based interpretation from the configured intelligence provider."],
  ["", "trust", "◈", "Trust & Reputation", "Protect forms from abuse and monitor trust and reputation evidence."],
  ["", "notifications", "♧", "Notifications", "Updates and attention signals recorded by the control plane."],
  ["", "audit", "≡", "Audit trail", "Recorded commands, approvals, and operational outcomes."],
  ["WORKSPACE", "settings", "⚙", "Settings", "Workspace configuration, AI provider connection, and registered capabilities."]
];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function append(parent, ...children) { children.filter(Boolean).forEach((child) => parent.append(child)); return parent; }
const labels = { cpu_percent: "CPU utilization", ram_percent: "Memory usage", disk_percent: "Disk utilization", cpu_count: "CPU cores", memory_total_bytes: "Total memory", memory_available_bytes: "Available memory", disk_total_bytes: "Total storage", disk_free_bytes: "Free storage", http_5xx_ratio: "Server error rate", authenticated_ratio: "Authenticated traffic", top_ip_ratio: "Largest source share", insufficient_evidence: "Not enough history yet", no_sustained_pressure: "No sustained pressure", local_demo: "Local demo", awaiting_enrollment: "Waiting for enrollment", enrolled: "Waiting for first heartbeat", enrollment_expired: "Enrollment expired", server_id: "Server", sample_count: "Recorded samples", window_minutes: "Observation window", upgrade_supported: "Upgrade supported by evidence", unknown: "Not established", deterministic: "Local evidence analysis", command_class: "Request type", A: "Read and diagnose", B: "Approval required", C: "Restricted request" };
function human(value) { const text = String(value ?? "Unavailable"); return labels[text] || labels[text.toLowerCase()] || text.replace(/[_-]/g, " ").replace(/^[A-Z0-9 ]+$/, (v) => v.toLowerCase()).replace(/^./, (c) => c.toUpperCase()); }
function present(value) { return value !== null && value !== undefined && value !== "" && (typeof value !== "object" || Object.values(value).some(present)); }
function bytes(value) { if (value == null || value === "" || !Number.isFinite(Number(value))) return "Not available"; const i = Math.min(4, Math.floor(Math.log(Math.max(1, Number(value))) / Math.log(1024))); return `${num(Number(value) / 1024 ** i, 1)} ${["B", "KiB", "MiB", "GiB", "TiB"][i]}`; }
function displayValue(key, value) {
  if (value == null) return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (/(_at|timestamp|last_seen|first_seen|last_run|last_notified|expires)$/.test(key)) return date(value);
  if (/_bytes$/.test(key)) return bytes(value);
  if (/_percent$/.test(key)) return `${num(value, 1)}%`;
  if (/_ratio$/.test(key)) return `${num(Number(value) * 100, 1)}%`;
  if (key === "uptime_seconds") return `${num(Number(value) / 3600, 1)} hours`;
  if (key === "window_minutes") return `${num(Number(value) / 60, 1)} hours`;
  if (key === "server_id") return state.servers.find(server => server.id === value)?.name || (value === "local-demo" ? "Local demo" : value);
  if (typeof value === "number") return num(value, 2);
  if (/^(status|state|severity|classification|category|provider|environment|mode|intent|action|channel|approval_state|command_class)$/.test(key)) return human(value);
  return String(value);
}
const unsafeEvidenceKey = /password|passwd|secret|token|authorization|cookie|api.?key|credential|private.?key|payload|exception|message.?body|customer|phone|email|\.env|dsn|connection.?string|config.?line|raw|access_logs|error_logs|config_path|document_root|source_path/i;
const safeEvidenceKeys = new Set(["observed_at", "received_at", "metrics", "cpu_percent", "ram_percent", "disk_percent", "load", "cpu_count", "memory_total_bytes", "disk_total_bytes", "disk_free_bytes", "application", "framework", "queue_driver", "queue_mode", "queue_backlog", "queue_workers", "expected_workers", "scheduler_last_run", "scheduler_running", "scheduler_registered", "scheduler_interval_seconds", "database_healthy", "database_latency_ms", "database_reachable", "database_sql_healthy", "failed_jobs", "failed_jobs_count", "failed_jobs_latest_at", "http_status", "http_latency_ms", "http_probe", "status", "latency_ms", "healthy", "available", "reachable", "traffic", "requests_per_minute", "baseline_requests_per_minute", "http_2xx", "http_3xx", "http_4xx", "http_5xx", "http_5xx_ratio", "error_rate", "baseline_error_rate", "services", "name", "state", "substate", "processes", "pid", "memory_bytes", "cpu_ticks", "ports", "port", "protocol", "bind_scope", "sites", "domains", "web_server", "configuration_complete", "limitations", "reason", "request_count", "error_count", "server_error_count", "evidence", "scope", "truncated", "files_read", "sites_found", "missing", "changed", "new", "removed", "expected", "active", "observed"]);
function safeEvidence(value, depth = 0) {
  if (depth > 7) return undefined;
  if (Array.isArray(value)) return value.slice(0, 100).map(item => safeEvidence(item, depth + 1)).filter(item => item !== undefined);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([key]) => safeEvidenceKeys.has(key) && !unsafeEvidenceKey.test(key)).map(([key, item]) => [key, safeEvidence(item, depth + 1)]).filter(([, item]) => item !== undefined));
  if (typeof value === "string") return /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|-----BEGIN|bearer\s+\S+|(?:password|token|secret|authorization|cookie|dsn)\s*[:=]|(?:\+?\d[\d .()-]{7,}\d)/i.test(value) ? "[REDACTED]" : value.slice(0, 400);
  return typeof value === "number" || typeof value === "boolean" ? value : undefined;
}
function advanced(data, title = "Technical details") { const safe = safeEvidence(data); if (!present(safe)) return null; return append(el("details", "advanced-evidence"), el("summary", "", title), el("p", "helper-text", "Selected safe technical observations. Unavailable fields are omitted."), el("pre", "", JSON.stringify(safe, null, 2))); }
const internalKeys = /^(id|org_id|identity_id|agent_id|correlation_key|code_hash|parameters|tools|expires|data|registered_actions|network|disk_io|coverage|adequately_sampled_days|peak_percent|median_percent|missing_evidence)$/;
function proseList(values) { const list = el("ul", "readable-list"); values.filter(present).forEach(value => list.append(el("li", "", typeof value === "object" ? value.interpretation || value.summary || value.reason || value.description || human(value.name || value.status || "Recorded observation") : human(value)))); return list; }
function valueText(value) {
  if (value === null || value === undefined) return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return "Evidence available";
  return String(value);
}
function num(value, decimals = 0) { return Number.isFinite(Number(value)) && value !== null && value !== "" ? Number(value).toLocaleString(undefined, { maximumFractionDigits: decimals }) : "—"; }
function date(value) { if (!value) return "Not recorded"; const d = new Date(typeof value === "number" ? value * 1000 : value); return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
function tone(value) {
  const s = String(value || "").toLowerCase();
  if (/critical|attack|error|fail|down|unhealthy|denied|blocked/.test(s)) return "bad";
  if (/warning|warn|medium|high|pending|degrad|pressure|backlog/.test(s)) return "warn";
  if (/healthy|normal|running|active|success|completed|approved|low|online|ok|resolved/.test(s)) return "good";
  return "";
}
function pill(value) { return el("span", `pill ${tone(value)}`, human(value)); }
function link(text, target) { const a = el("a", "panel-link", text); a.href = `#${target}`; return a; }
function button(text, className, handler) { const b = el("button", `button ${className || "secondary"}`, text); b.type = "button"; b.addEventListener("click", handler); return b; }
function panel(title, subtitle, action) {
  const p = el("section", "panel");
  const header = el("div", "panel-header");
  append(header, append(el("div"), el("h2", "", title), subtitle ? el("p", "panel-subtitle", subtitle) : null), action);
  p.append(header); return p;
}
function empty(title, detail) { return append(el("div", "empty-state"), el("strong", "", title), el("span", "", detail)); }
function fields(data, excluded = []) {
  const dl = el("dl", "fields");
  Object.entries(data || {}).filter(([key, value]) => !excluded.includes(key) && !internalKeys.test(key) && present(value) && typeof value !== "object").forEach(([key, value]) => append(dl, el("dt", "", human(key)), el("dd", "", displayValue(key, value))));
  return dl;
}
function record(data, fallback) {
  if (!data || typeof data !== "object") return el("p", "muted", human(data));
  const content = { ...data, ...(data.data && typeof data.data === "object" ? data.data : {}) };
  const card = el("article", "record");
  const title = content.title || content.name || content.action || content.classification || content.kind || fallback || "Recorded activity";
  const status = content.severity || content.status || content.state || content.command_class;
  append(card, append(el("div", "record-header"), el("h3", "", human(title)), status ? pill(status) : null));
  ["summary", "message", "interpretation", "assessment", "recommendation", "request"].forEach(key => { if (typeof content[key] === "string" && content[key]) card.append(el("p", "record-copy", content[key])); });
  const skip = ["title", "summary", "name", "severity", "status", "state", "message", "interpretation", "assessment", "recommendation", "request", "action", "classification", "kind"];
  append(card, fields(content, skip));
  if (content.parameters && typeof content.parameters === "object") append(card, fields(content.parameters));
  ["facts", "recommendations"].forEach(key => { if (Array.isArray(content[key]) && content[key].length) append(card, el("h4", "", human(key)), proseList(content[key])); });
  append(card, advanced(data)); return card;
}
function message(text, error = false) { const node = $("global-message"); node.textContent = text; node.className = `global-message${error ? " error" : ""}`; node.hidden = !text; }
function showLogin() { state.csrf = null; state.user = null; state.data = null; state.request++; $("app").hidden = true; $("content").replaceChildren(); $("login-screen").hidden = false; $("password").value = ""; }
async function api(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (options.method && options.method !== "GET") { headers["Content-Type"] = "application/json"; if (state.csrf) headers["X-CSRF-Token"] = state.csrf; }
  const response = await fetch(path, { ...options, headers: { ...headers, ...options.headers }, credentials: "same-origin", cache: "no-store" });
  let data; try { data = await response.json(); } catch { throw new Error("The server returned an unreadable response. Please try again."); }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    const detail = data.error || data.message || `Request failed (${response.status})`;
    throw new Error(typeof detail === "string" ? detail : valueText(detail));
  }
  return data;
}
const post = (path, data) => api(path, { method: "POST", body: JSON.stringify(data) });
async function busy(node, operation) { node.disabled = true; try { await operation(); } catch (error) { message(error.message, true); } finally { node.disabled = false; } }
async function establishSession(data) {
  state.csrf = data.csrf_token; state.user = data.user; state.demoEnabled = data.demo_enabled !== false;
  document.querySelectorAll('[data-route="commands"], [data-route="approvals"]').forEach(node => { node.hidden = !state.demoEnabled; });
  $("session-user").textContent = typeof data.user === "string" ? data.user : data.user?.username || "Local operator";
  $("login-screen").hidden = true; $("app").hidden = false; $("password").value = ""; await refreshServers(); state.serverId = state.servers.find(server => server.id !== "local-demo" && !["revoked", "awaiting_enrollment"].includes(server.status))?.id || state.servers.find(server => server.id !== "local-demo")?.id || (state.demoEnabled === false ? "" : "local-demo"); $("server-selector").value = state.serverId; renderRoute();
}

function metricCards(snapshot) {
  const m = snapshot?.metrics || {};
  const app = snapshot?.application || {};
  const cards = el("div", "metrics-grid");
  const driver = String(app.queue_driver || app.queue?.driver || app.queue_mode || "").toLowerCase();
  const http = app.http_probe || app.http || {};
  const httpStatus = http.status_code ?? http.status ?? app.http_status;
  const fourth = driver === "sync" ? ["Queue", "Sync driver", "", "Jobs execute during requests", "≋"] :
    app.queue_backlog != null ? ["Queue backlog", app.queue_backlog, "", "Pending application jobs", "≋"] :
    ["Application", httpStatus === 200 || http.available === true ? "Available" : "Not observed", "", httpStatus ? `HTTP ${httpStatus} observed` : "HTTP probe not established", "◉"];
  [["CPU utilization", m.cpu_percent, "%", "Current reading", "▥"], ["Memory usage", m.ram_percent, "%", "Current reading", "▦"], ["Disk utilization", m.disk_percent, "%", "Current reading", "▤"], fourth].forEach(([label, value, unit, note, icon]) => {
    const card = el("article", "metric-card");
    append(card, append(el("div", "metric-label"), el("span", "", label), el("span", "metric-icon", icon)), append(el("div", "metric-number", typeof value === "string" ? value : num(value, 1)), el("small", "", unit)));
    if (unit === "%") { const meter = el("div", "meter"); const fill = el("span"); fill.style.width = `${Math.max(0, Math.min(100, Number(value) || 0))}%`; if (Number(value) >= 85) fill.style.background = "var(--amber)"; meter.append(fill); card.append(meter); }
    else { const spacer = el("div", "meter"); card.append(spacer); }
    card.append(el("div", "metric-note", note)); cards.append(card);
  }); return cards;
}
function chart(history) {
  const rows = (history || []).map((r) => ({ metrics: r.metrics || r.snapshot?.metrics || {}, at: r.observed_at || r.snapshot?.observed_at || r.created_at }));
  if (rows.filter(r => ["cpu_percent", "ram_percent", "disk_percent"].some(key => r.metrics[key] != null && Number.isFinite(Number(r.metrics[key])))).length < 2) return empty("A trend starts with two snapshots", "Collect another snapshot to see resource history.");
  const selected = rows.slice(-40), ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg"); svg.setAttribute("viewBox", "0 0 600 190"); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Recorded CPU, memory and disk utilization from zero to one hundred percent"); svg.classList.add("chart");
  const shape = (tag, attrs, text) => { const node = document.createElementNS(ns, tag); Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value)); if (text) node.textContent = text; svg.append(node); return node; };
  [0, 25, 50, 75, 100].forEach((tick) => { const y = 165 - tick * 1.45; shape("line", { x1: 2, x2: 598, y1: y, y2: y, class: "chart-axis" }); });
  const axis = el("div", "chart-y-axis"); axis.setAttribute("aria-hidden", "true");
  [100, 75, 50, 25, 0].forEach((tick) => axis.append(el("span", "", `${tick}%`)));
  [["disk_percent", "#b19cd9"], ["ram_percent", "#729cdb"], ["cpu_percent", "#54d7bd"]].forEach(([key, color]) => {
    let points = [];
    const flush = () => { if (points.length > 1) shape("polyline", { points: points.join(" "), fill: "none", stroke: color, "stroke-width": 2.1, "stroke-linejoin": "round", "stroke-linecap": "round" }); points = []; };
    selected.forEach((row, i) => {
      const value = row.metrics[key];
      if (value == null || !Number.isFinite(Number(value))) { flush(); return; }
      points.push(`${2 + i * 596 / (selected.length - 1)},${165 - Math.max(0, Math.min(100, Number(value))) * 1.45}`);
    });
    flush();
  });
  return append(el("div"), append(el("div", "chart-plot"), axis, svg), append(el("div", "chart-footer"), el("span", "", date(selected[0].at)), el("span", "", `${selected.length} recorded samples`), el("span", "", date(selected[selected.length - 1].at))));
}
function chartPanel(history) {
  const legend = el("div", "chart-legend");
  [["CPU", "#54d7bd"], ["RAM", "#729cdb"], ["Disk", "#b19cd9"]].forEach(([label, color]) => { const dot = el("span", "legend-dot"); dot.style.background = color; legend.append(append(el("span", "legend-item"), dot, el("span", "", label))); });
  return append(panel("Resource activity", "Recorded snapshots · utilization %", legend), chart(history));
}
function analysisPanel(analysis = {}, snapshot = {}) {
  analysis = analysis || {};
  const p = panel("Intelligence summary", human(analysis.provider || "deterministic"), pill(analysis.severity || "awaiting evidence")); p.classList.add("insight-panel");
  const traffic = snapshot.traffic || {}, rate = traffic.requests_per_minute, baseline = traffic.baseline_requests_per_minute;
  const spike = rate != null && baseline > 0 && rate / baseline >= 2;
  const heading = spike && analysis.category === "traffic_spike" ? "Traffic above observed baseline" : human(analysis.classification || "No analysis yet");
  append(p, append(el("div", "insight-heading"), el("span", "insight-icon", "✧"), el("h3", "", heading)));
  if (spike) p.append(el("p", "record-copy", `Measured: ${num(rate, 1)} requests/minute versus ${num(baseline, 1)} baseline · ${num(rate / baseline, 1)}× reference.`));
  p.append(el("p", "insight-copy", `Assessment: ${analysis.interpretation || "Not established. Collect more evidence to assess this observation."}`));
  if (spike) {
    const app = snapshot.application || {}, probe = app.http_probe || {}, db = app.database || {}, context = [];
    const http = probe.status_code ?? app.http_status;
    if (http != null) context.push(`HTTP probe ${http}`);
    const sql = db.sql_healthy ?? db.healthy ?? app.database_healthy;
    if (typeof sql === "boolean") context.push(`database check ${sql ? "successful" : "failed"}`);
    if (traffic.http_5xx_ratio != null) context.push(`${num(traffic.http_5xx_ratio * 100, 1)}% server errors`);
    if (snapshot.metrics?.cpu_percent != null) context.push(`CPU ${num(snapshot.metrics.cpu_percent, 1)}%`);
    if (context.length) p.append(el("p", "record-copy", `Other observed facts: ${context.join(" · ")}.`));
  }
  const facts = el("ul", "insight-facts"); (analysis.facts || []).filter(fact => !fact.startsWith("Incomplete evidence:")).slice(0, 4).forEach((fact) => facts.append(el("li", "", fact))); p.append(facts);
  const recommendation = analysis.recommendations?.[0] || analysis.recommendation;
  if (recommendation) p.append(el("p", "record-copy", `Next step: ${recommendation}`));
  const confidence = analysis.confidence === undefined ? "No confidence recorded" : Number.isFinite(Number(analysis.confidence)) ? `${num(Number(analysis.confidence) <= 1 ? Number(analysis.confidence) * 100 : analysis.confidence)}% confidence` : `${human(analysis.confidence)} confidence`;
  if (analysis.confidence === "low" && analysis.missing_evidence?.length) {
    const names = {database_healthy:"database check",requests_per_minute:"request rate","positive traffic baseline":"traffic reference",queue_backlog:"queue backlog",queue_workers:"worker count",cpu_percent:"CPU reading",ram_percent:"memory reading",disk_percent:"disk reading"};
    p.append(el("p", "helper-text", `Confidence is low because ${analysis.missing_evidence.slice(0, 4).map(key => names[key] || "supporting context").join(", ")} ${analysis.missing_evidence.length > 1 ? "are" : "is"} unavailable.`));
  }
  p.append(append(el("div", "insight-footer"), el("span", "", confidence), link("Inspect analysis ↗", "analyses"))); return p;
}
function eventsList(items, max) {
  if (!items?.length) return empty("Nothing needs attention", "No matching records are available in this local workspace.");
  const list = el("div", "event-list");
  items.slice(0, max || items.length).forEach((item) => { const label = item.summary || item.message || item.assessment || item.title || human(item.kind || item.action || "Recorded event"); list.append(append(el("div", "event-row"), el("span", `event-indicator ${tone(item.severity || item.status)}`), append(el("div"), el("p", "", label), el("small", "", [human(item.severity || item.status || item.kind || "event"), date(item.created_at || item.observed_at || item.timestamp || item.opened_at || item.last_seen || item.first_seen)].join(" · "))))); }); return list;
}
function table(columns, rows) {
  const table = el("table", "data-table");
  const head = el("thead"), tr = el("tr"); columns.forEach(([name]) => tr.append(el("th", "", name))); head.append(tr);
  const body = el("tbody"); rows.forEach((row) => { const tr = el("tr"); columns.forEach(([, get]) => { const td = el("td"); const value = get(row); td.append(value instanceof Node ? value : document.createTextNode(valueText(value))); tr.append(td); }); body.append(tr); });
  return append(el("div", "table-wrap"), append(table, head, body));
}
function serverTable(servers) {
  if (!servers?.length) return empty("No registered servers", "No server records were returned by the control plane.");
  return table([["Server", (s) => { const a = el("a", "server-name"); a.href = `#server/${encodeURIComponent(s.id || "local-demo")}`; return append(a, el("span", "server-icon", "▤"), append(el("span", "", s.name || s.id), el("small", "", s.id === "local-demo" ? "Simulated environment" : "Read-only agent"))); }], ["Status", (s) => pill(s.status || "unknown")], ["Environment", (s) => human(s.environment || "local demo")], ["Last seen", (s) => date(s.last_seen)]], servers);
}
function overview(data, details) {
  const fragment = document.createDocumentFragment(); fragment.append(metricCards(data.snapshot));
  fragment.append(append(el("div", "columns"), chartPanel(details?.history || []), analysisPanel(data.analysis, data.snapshot || {})));
  const server = data.server ? [data.server] : [];
  fragment.append(append(el("div", "columns"), append(panel("Infrastructure", `Selected server · ${data.server?.id === "local-demo" ? "simulated evidence" : "read-only monitoring"}`, link("View servers ↗", "servers")), serverTable(server)), append(panel("Recent incidents", "Signals requiring investigation", link("View all ↗", "incidents")), eventsList(data.incidents || [], 3))));
  return fragment;
}
function dataRecords(items, title, description) {
  if (!items?.length) return append(panel(title, description), empty(`No ${title.toLowerCase()} recorded`, "New records will appear here when activity is collected or commands are submitted."));
  const list = el("div", "stack"); items.forEach((item, i) => list.append(record(item, `${title} ${i + 1}`))); return list;
}
function approvalCard(approval, context) {
  const card = record(Object.fromEntries(Object.entries(approval).filter(([key]) => key !== "code")), "Action approval"); card.classList.add("approval-card");
  if (approval.code) { append(card, el("p", "helper-text", "Review the bound action, target, and expiry above. Enter this challenge yourself only if you want the simulated action to execute."), el("div", "approval-code", approval.code)); }
  const terminal = /executed|expired|rejected|cancelled|consumed|completed|approved|superseded|locked/i.test(approval.state || approval.status || "");
  if (approval.id && !terminal) {
    const form = el("form", "approval-form"), input = el("input"); input.required = true; input.autocomplete = "off"; input.placeholder = "Enter confirmation code"; input.setAttribute("aria-label", "Approval confirmation code");
    const submit = el("button", "button secondary", "Confirm simulated action"); submit.type = "submit";
    const mock = (context?.channel || approval.channel) === "whatsapp-mock";
    let senderInput;
    if (mock && !context?.sender) { senderInput = el("input"); senderInput.required = true; senderInput.type = "tel"; senderInput.autocomplete = "off"; senderInput.placeholder = "Configured owner's phone number"; form.append(append(el("label", "", "Original simulator sender"), senderInput)); }
    form.append(append(el("label", "", "Explicit confirmation required"), input), submit);
    form.addEventListener("submit", (event) => { event.preventDefault(); busy(submit, async () => { const result = mock ? await post("/api/commands", { text: `CONFIRM ${input.value.trim()}`, server_id: approval.server_id || "local-demo", channel: "whatsapp-mock", sender: context?.sender || senderInput.value.trim() }) : await post(`/api/approvals/${encodeURIComponent(approval.id)}/confirm`, { code: input.value.trim() }); form.remove(); card.append(record(result, "Execution result")); message("Confirmation submitted. The execution result is shown below."); }); }); card.append(form);
  } return card;
}
function commandCenter() {
  const layout = el("div", "command-layout"), p = panel("Talk to EzzeSecure", "English and Arabic demo commands · local-demo"), guide = panel("Every action has a boundary", "Community monitoring is read-only; action demos are simulated");
  p.append(el("p", "notice", "Diagnostic questions can return evidence immediately. Operational changes require a separate approval and confirmation code."));
  const form = el("form", "command-form"), channel = el("select");
  [["console", "Console"], ["whatsapp-mock", "Authenticated WhatsApp simulator"]].forEach(([value, label]) => { const option = el("option", "", label); option.value = value; channel.append(option); });
  const sender = el("input"); sender.type = "tel"; sender.placeholder = "Configured owner's phone number"; sender.autocomplete = "off";
  const senderLabel = append(el("label", "", "Simulator sender · must match configured owner"), sender); senderLabel.hidden = true;
  channel.addEventListener("change", () => { senderLabel.hidden = channel.value !== "whatsapp-mock"; sender.required = !senderLabel.hidden; });
  const text = el("textarea"); text.required = true; text.maxLength = 2000; text.placeholder = "Why is the server slow?"; text.dir = "auto";
  append(form, append(el("label", "", "Request channel"), channel), senderLabel, append(el("label", "", "Your request"), text));
  const submit = el("button", "button primary", "Send request ↗"); submit.type = "submit";
  form.append(append(el("div", "form-row"), el("span", "helper-text", "Target: local-demo · simulated environment"), submit));
  const suggestions = el("div", "suggestions"); ["Check server health", "Why is cron delayed?", "Restart queue workers", "شغّل المجدول الآن"].forEach((prompt) => { const b = button(prompt, "", () => { text.value = prompt; text.focus(); }); b.className = "suggestion"; suggestions.append(b); });
  const response = el("div", "command-response"); response.setAttribute("aria-live", "polite");
  form.addEventListener("submit", (event) => { event.preventDefault(); busy(submit, async () => { const body = { text: text.value.trim(), server_id: "local-demo", channel: channel.value }; if (channel.value === "whatsapp-mock") body.sender = sender.value.trim(); const result = await post("/api/commands", body); response.replaceChildren(el("p", "", result.message || "Request processed.")); response.append(record(Object.fromEntries(Object.entries(result).filter(([key]) => !["message", "approval", "result", "analysis"].includes(key))), "Request interpretation")); if (result.analysis) response.append(record(result.analysis, "Diagnostic analysis")); if (result.result) response.append(record(result.result, "Result")); if (result.approval) response.append(approvalCard(result.approval, body)); message(""); }); });
  append(p, form, suggestions, response);
  [["A / Read and diagnose", "Health checks, metrics, and explanations use available evidence without changing server state."], ["B / Review and confirm", "Allowlisted operational actions create an approval bound to the operator, action, server, and expiry."], ["C / Restricted requests", "Unsupported or unsafe requests are rejected. There is no arbitrary shell interface."], ["WhatsApp / Local simulator", "This authenticated simulator checks the configured owner number. It does not send or receive real WhatsApp messages."]].forEach(([title, detail]) => guide.append(append(el("div", "action-guide"), el("h3", "", title), el("p", "", detail))));
  return append(layout, p, guide);
}

function evidencePanel(title, subtitle, data) {
  const p = panel(title, subtitle);
  if (!present(data)) return append(p, empty("No evidence collected yet", "This check needs an observation from the selected server."));
  append(p, fields(data));
  if (Array.isArray(data?.load) && data.load.length) p.append(fields({ "Load average (1, 5, 15 minutes)": data.load.map(value => num(value, 2)).join(" · ") }));
  Object.entries(data || {}).filter(([key, value]) => key !== "load" && Array.isArray(value) && value.length && !internalKeys.test(key)).forEach(([key, value]) => append(p, el("h3", "", human(key)), proseList(value)));
  return append(p, advanced(data));
}
function ioPanels(metrics = {}) {
  const network = metrics.network || {}, disk = metrics.disk_io || {};
  const rate = value => value == null ? "Not observed yet" : `${bytes(value)}/s`;
  const n = panel("Network activity", "Cumulative interface counters and rates between samples");
  n.append(network.interfaces?.length ? table([["Interface", x => x.interface], ["Received", x => bytes(x.rx_bytes)], ["Sent", x => bytes(x.tx_bytes)], ["Receive rate", x => rate(x.rx_bytes_per_second)], ["Send rate", x => rate(x.tx_bytes_per_second)]], network.interfaces) : empty("No network measurements", network.reason || "This snapshot has no network counters."));
  append(n, advanced(network));
  const d = panel("Disk I/O", "Device counters may overlap; do not sum partitions and virtual devices");
  d.append(disk.devices?.length ? table([["Device", x => x.device], ["Read rate", x => rate(x.read_bytes_per_second)], ["Write rate", x => rate(x.written_bytes_per_second)], ["Operations in progress", x => num(x.io_in_progress)]], disk.devices) : empty("No disk I/O measurements", disk.reason || "This snapshot has no device counters."));
  append(d, advanced(disk));
  return append(el("div", "stack"), n, d);
}

function capacityPanel(capacity = {}, snapshot = {}) {
  const p = panel("Capacity & resource health", "Current measurements and historical context", pill(capacity.status || "insufficient_evidence"));
  const metrics = snapshot.metrics || {}, resources = el("div", "resource-summary");
  for (const [name, key, threshold] of [["CPU", "cpu_percent", 85], ["Memory", "ram_percent", 85], ["Disk", "disk_percent", 90]]) {
    const current = metrics[key], median = capacity.median_percent?.[key], peak = capacity.peak_percent?.[key];
    const card = append(el("div"), el("h3", "", name));
    const percentage = value => value == null ? "Not observed" : `${num(value, 1)}%`;
    append(card, el("p", "", `Current: ${percentage(current)}`), el("p", "muted", `Median: ${percentage(median)} · Peak: ${percentage(peak)}`), pill(current == null ? "unknown" : current >= threshold ? "current_pressure" : "within_margin"));
    if (name === "CPU" && metrics.cpu_count) card.append(el("p", "muted", `${num(metrics.cpu_count)} cores`));
    if (name === "Memory" && metrics.memory_total_bytes) card.append(el("p", "muted", `${bytes(metrics.memory_total_bytes)} total`));
    if (name === "Disk" && metrics.disk_total_bytes) card.append(el("p", "muted", `${bytes(metrics.disk_total_bytes)} total · ${bytes(metrics.disk_free_bytes)} free`));
    resources.append(card);
  }
  const minutes = capacity.window_minutes || 0;
  const history = minutes < 60 ? `${num(minutes)} minutes` : `${num(minutes / 60, 1)} hours`;
  append(p, resources, el("h3", "", "Observation history"), el("p", "record-copy", `${num(capacity.sample_count || 0)} samples collected · approximately ${history} of history`));
  append(p, el("h3", "", "Assessment"), el("p", "record-copy", human(capacity.status || "insufficient_evidence")), el("h3", "", "Recommendation"));
  const recommendation = capacity.status === "insufficient_evidence" ? "Keep collecting observations. EzzeSecure needs at least 72 hours of representative history across three adequately sampled days before making a long-term capacity recommendation." : capacity.recommendation;
  append(p, el("p", "notice", recommendation || "Keep collecting timestamped observations to assess sustained demand."), el("p", "helper-text", "Current margin describes this resource reading only. It does not establish overall application health or future capacity."));
  return append(p, advanced(capacity, "Technical details · capacity"));
}

const observed = value => value === null || value === undefined || value === "" ? "Not observed" : String(value);
function fact(label, value, detail) {
  const row = append(el("div", "evidence-fact"), el("span", "evidence-label", label), el("strong", "", observed(value)));
  if (detail) row.append(el("small", "", detail));
  return row;
}
function applicationPanel(snapshot = {}) {
  const app = snapshot.application || {}, probe = app.http_probe || app.http || {}, db = app.database || {}, queue = app.queue || {}, scheduler = app.scheduler || {}, failed = app.failed_jobs_metadata || {};
  const p = panel("Application health", "Independent checks from the latest observation");
  const grid = el("div", "evidence-grid");
  grid.append(fact("Framework", app.framework ? human(app.framework) : "Not observed"));
  const status = probe.status_code ?? probe.status ?? app.http_status;
  const latency = probe.latency_ms ?? app.http_latency_ms;
  const httpState = status === 200 || probe.available === true ? "Available" : typeof status === "number" ? `HTTP ${status}` : "Not observed";
  grid.append(fact("HTTP probe", httpState, status != null ? `HTTP ${status}${latency != null ? ` · ${num(latency, 1)} ms` : ""}` : "Safe local probe only"));
  const dbHealthy = db.sql_healthy ?? db.healthy ?? app.database_sql_healthy ?? app.database_healthy;
  const dbReachable = db.reachable ?? app.database_reachable;
  const dbLatency = db.latency_ms ?? app.database_latency_ms;
  grid.append(fact("DB reachability", dbReachable === true ? "Available" : dbReachable === false ? "Unavailable" : "Not observed", "TCP or connection probe, when supplied"));
  grid.append(fact("Database", dbHealthy === true ? "SQL check successful" : dbHealthy === false ? "SQL check failed" : dbReachable === true ? "Reachable" : dbReachable === false ? "Unavailable" : "Not observed", dbLatency != null ? `${num(dbLatency, 1)} ms observed latency` : "Read-only operational check"));
  const driver = String(queue.driver || app.queue_driver || app.queue_mode || "").toLowerCase();
  const backlog = queue.backlog ?? app.queue_backlog;
  const workers = queue.workers ?? app.queue_workers;
  grid.append(fact("Queue", driver === "sync" ? "Synchronous" : driver ? human(driver) : "Not observed", driver === "sync" ? "Jobs execute during requests; no background worker required. Backlog is not applicable." : backlog != null ? `${num(backlog)} pending${workers != null ? ` · ${num(workers)} workers observed` : ""}` : "Backlog not observed"));
  const lastRun = scheduler.last_run ?? app.scheduler_last_run;
  const age = lastRun ? (new Date(snapshot.observed_at || snapshot.received_at || Date.now()) - new Date(lastRun)) / 60000 : NaN;
  const interval = scheduler.expected_interval_seconds ?? app.scheduler_interval_seconds;
  const stale = Number.isFinite(age) && interval > 0 && age > interval / 60 * 2;
  grid.append(fact("Scheduler", stale ? "Stale observation" : Number.isFinite(age) && age >= -1 ? "Recently observed" : scheduler.registered === true || app.scheduler_registered === true ? "Configured" : "Not established", lastRun ? `Last runner activity: ${date(lastRun)}${Number.isFinite(age) && age >= -1 ? ` · ${num(Math.max(0, age))} min before snapshot` : ""}` : "Task completion is not observed"));
  const failures = typeof app.failed_jobs === "number" ? app.failed_jobs : app.failed_jobs?.count ?? failed.count ?? app.failed_jobs_count;
  grid.append(fact("Failed jobs", failures == null ? "Not observed" : num(failures), failures === 0 ? "No recorded failed jobs" : failed.latest_at || app.failed_jobs_latest_at ? `Latest recorded: ${date(failed.latest_at || app.failed_jobs_latest_at)}` : "Metadata only; job payloads are never shown"));
  if (failed.recent_count != null || app.failed_jobs_recent_count != null) grid.append(fact("Recent failures", num(failed.recent_count ?? app.failed_jobs_recent_count), "Failed-job metadata only"));
  return append(p, grid, el("p", "helper-text", "Scheduler runner activity does not prove that every scheduled task completed successfully."), advanced({application: app}, "Technical details"));
}
function trafficPanel(snapshot = {}) {
  const t = snapshot.traffic || {}, p = panel("Traffic", "Aggregated observations and baseline context");
  const current = t.requests_per_minute, baseline = t.baseline_requests_per_minute;
  const grid = el("div", "evidence-grid");
  grid.append(fact("Request rate", current == null ? "Not observed" : `${num(current, 1)}/min`, baseline > 0 ? `Reference ${num(baseline, 1)}/min · ${num(current / baseline, 1)}× baseline` : "Reference not established"));
  for (const [label, keys] of [["2xx", ["http_2xx", "responses_2xx"]], ["3xx", ["http_3xx", "responses_3xx"]], ["4xx", ["http_4xx", "responses_4xx"]], ["5xx", ["http_5xx", "responses_5xx"]]]) {
    const value = keys.map(key => t[key]).find(value => value != null);
    grid.append(fact(`${label} responses`, value == null ? "Not observed" : num(value)));
  }
  const errors = t.http_5xx_ratio ?? t.error_rate;
  const errorBaseline = t.baseline_http_5xx_ratio ?? t.baseline_error_rate;
  grid.append(fact("Server error rate", errors == null ? "Not observed" : `${num(errors * 100, 1)}%`, errorBaseline != null && errors != null ? `Reference ${num(errorBaseline * 100, 1)}% · ${errors >= errorBaseline ? "+" : ""}${num((errors - errorBaseline) * 100, 1)} percentage points` : "Reference not observed"));
  append(p, grid);
  if (baseline > 0 && current >= baseline * 2) append(p, el("p", "notice", "Traffic is above the observed baseline. The cause is not established. Compare error rates and application checks before treating it as a security incident."));
  return append(p, advanced({traffic: t}));
}
function servicesPanel(services, comparison, snapshot = {}) {
  const p = panel("Services", "Expected and observed service state");
  const rows = Array.isArray(services) ? services : [];
  if (!rows.length) return append(p, empty("Services not observed", "The latest snapshot contains no service observations."));
  const configured = snapshot.source === "systemd" || rows.every(row => row.source === "simulated" || row.expected === true);
  const expected = comparison?.expected ?? (configured ? rows.filter(row => row.expected !== false).length : "Not established");
  const active = rows.filter(row => ["active", "running"].includes(String(row.state || row.status || "").toLowerCase())).length;
  const count = value => Array.isArray(value) ? value.length : typeof value === "number" ? value : null;
  const missing = count(comparison?.removed) ?? (configured ? rows.filter(row => ["missing", "not_found"].includes(String(row.state || row.status || "").toLowerCase())).length : "Not established");
  const changed = count(comparison?.changed);
  append(p, append(el("div", "evidence-grid"), fact("Expected", expected), fact("Active", active), fact("Missing", missing), fact("Changed", changed == null ? "Not established" : changed)));
  p.append(el("p", "notice", expected === active && missing === 0 ? "Expected services are currently present. This does not establish overall server health." : "Review unavailable or changed services and their expected operating state."));
  p.append(table([["Service", row => row.name || "Unnamed service"], ["State", row => pill(row.state || row.status || "not observed")]], rows));
  return append(p, advanced({services: rows}));
}
function processesPanel(snapshot = {}) {
  const p = panel("Process summary", "Bounded Agent sample ordered by resident memory; CPU ticks are cumulative, not utilization");
  const rows = Array.isArray(snapshot.processes) ? snapshot.processes : [];
  if (!rows.length) return append(p, empty("Processes not observed", snapshot.evidence?.processes?.reason || "No process summaries were returned in the latest snapshot."));
  p.append(table([["Process", row => row.name || "Unnamed process"], ["PID", row => row.pid ?? "Not observed"], ["State", row => row.state || "Not observed"], ["Resident memory", row => bytes(row.memory_bytes)]], rows));
  return append(p, advanced({processes: rows}));
}
function networkBaselinePanel(snapshot = {}, comparison) {
  const p = panel("Network baseline", "Listening ports compared with an established reference");
  const rows = Array.isArray(snapshot.ports) ? snapshot.ports : [];
  if (!rows.length && !comparison) return append(p, empty("Ports not observed", "No listening-port evidence is available."));
  const count = value => Array.isArray(value) ? value.length : typeof value === "number" ? value : "Not established";
  append(p, append(el("div", "evidence-grid"), fact("Expected listeners", comparison?.expected ?? "Not established"), fact("New", count(comparison?.new)), fact("Removed", count(comparison?.removed)), fact("Changed", count(comparison?.changed))));
  if (Array.isArray(comparison?.new)) comparison.new.slice(0, 5).forEach(item => {
    const label = Array.isArray(item) ? `${String(item[0]).toUpperCase()} ${item[1]}` : String(item);
    p.append(el("p", "record-copy", `Measured: ${label} is now listening. Baseline: this listener was not in the established reference.`));
  });
  if (count(comparison?.new) > 0) p.append(el("p", "notice", "Assessment: new listening service requires review. Next step: identify its owning process or service and confirm whether the change was intended."));
  p.append(table([["Listener", row => `${String(row.protocol || "TCP").toUpperCase()} ${row.port ?? "?"}`], ["Bind scope", row => row.bind_scope || "Not observed"], ["State", row => human(row.state || "listening")]], rows));
  return append(p, advanced({ports: rows}));
}

function sitesPanel(snapshot) {
  const sites = Array.isArray(snapshot.sites) ? snapshot.sites : [];
  const p = panel("Websites on this server", "Configuration discovery does not establish reachability or per-site resource use");
  if (!sites.length) return append(p, empty("No website configuration observed", snapshot.evidence?.sites?.reason || "Configure readable Nginx or Apache virtual hosts for the agent to discover websites."), advanced(snapshot.evidence?.sites));
  const cards = el("div", "stack");
  sites.forEach(site => {
    const traffic = site.traffic || {};
    const status = String(site.status || "unknown").toLowerCase();
    const state = ["unavailable", "down"].includes(status) ? "Unavailable" : ["degraded", "warning"].includes(status) ? "Degraded" : ["healthy", "available"].includes(status) ? "Reachability confirmed" : "Health not established";
    const card = panel(site.domains?.join(", ") || "Unnamed website", human(site.web_server || "web server"), pill(state));
    append(card, append(el("div", "evidence-grid"), fact("Configuration", site.configuration_complete === true ? "Configured" : "Incomplete", "Discovered virtual-host declaration"), fact("HTTP reachability", ["healthy", "available"].includes(status) ? "Confirmed" : "Not established"), fact("Traffic attribution", traffic.available === true ? "Bounded sample" : "Unavailable")));
    if (traffic.available === true) card.append(el("p", "helper-text", `${num(traffic.request_count)} requests and ${num(traffic.server_error_count)} server errors in the bounded log sample.`));
    if (traffic.recent_failures?.length) append(card, el("h3", "", "Log-tail failures"), proseList(traffic.recent_failures.map(failure => `HTTP ${failure.status}: ${num(failure.count)} observed responses`)));
    append(card, advanced({domains: site.domains, web_server: site.web_server, configuration_complete: site.configuration_complete, limitations: site.limitations, traffic: {available: traffic.available, reason: traffic.reason, request_count: traffic.request_count, error_count: traffic.error_count, server_error_count: traffic.server_error_count}}, "Technical details")); cards.append(card);
  }); return append(p, cards);
}
function copyValue(label, value) {
  const block = el("div", "copy-block"), input = el("textarea", "copy-value"); input.value = value; input.readOnly = true; input.rows = 2; input.setAttribute("aria-label", label);
  return append(block, append(el("label", "", label), input), button("Copy", "secondary", async event => { const control = event.currentTarget; try { await navigator.clipboard.writeText(value); control.textContent = "Copied"; } catch { input.focus(); input.select(); message("Select and copy the highlighted text."); } }));
}
function enrollmentResult(result) {
  const p = panel("Connect your Linux server", `One-time enrollment expires ${date(result.expires_at)}`);
  append(p, el("p", "notice", "Keep this token private. It is displayed once and expires after ten minutes. Community agents only collect evidence; they cannot execute remote commands."), el("ol", "setup-steps"));
  const steps = p.querySelector("ol");
  ["Install the Community agent on the Linux server using the deployment guide.", "Run connection setup below once. For Cloudflare Access, append --cloudflare-access and enter Client ID/Secret at protected prompts. Existing connection files are never overwritten.", "HTTPS connects directly to the configured public origin. Loopback HTTP requires the existing local/tunnel setup for remote hosts.", "Run enrollment below and paste the one-time token at its protected prompt. Credentials never belong in command arguments.", "For renewed enrollment, remove the revoked agent credential file locally first; retain the separate connection configuration. Start the agent service and check for its first heartbeat."].forEach(step => steps.append(el("li", "", step)));
  append(p, copyValue("Connection setup command", result.configure_command || "Update the Control Plane to obtain connection setup instructions"), copyValue("Enrollment command", result.command || "Enrollment command unavailable"), copyValue("One-time enrollment token", result.token), link("View connection status →", `server/${result.server_id}`)); return p;
}
function addServer() {
  const p = panel("Add a Linux server", "Give this server a friendly name, then enroll its read-only agent");
  const form = el("form", "command-form"), name = el("input"); name.required = true; name.maxLength = 80; name.placeholder = "For example, Website server"; name.autocomplete = "off";
  const submit = el("button", "button primary", "Create enrollment token"); submit.type = "submit";
  append(form, append(el("label", "", "Server name"), name), el("p", "helper-text", "This registers a server locally. It does not access the server, install software, or change its configuration."), submit);
  const result = el("div", "stack");
  form.addEventListener("submit", event => { event.preventDefault(); busy(submit, async () => { const data = await post("/api/enrollment", { name: name.value.trim() }); result.replaceChildren(enrollmentResult(data)); form.hidden = true; await refreshServers(); }); });
  return append(p, form, result);
}
function connectionPanel(server) {
  const p = panel("Agent connection", "Real server · Community read-only monitoring", pill(server.status));
  append(p, fields({ name: server.name, last_seen: server.last_seen }), el("p", "notice", "The agent sends observations to this console. Restart, shell, service and deployment actions are unavailable for real servers."));
  const actions = el("div", "form-row"), result = el("div");
  actions.append(button("Renew enrollment", "secondary", event => busy(event.currentTarget, async () => {
    if (!window.confirm("Renew enrollment? This revokes the existing agent connection. You will need to remove the old local credential file and enroll this server again.")) return;
    result.replaceChildren(enrollmentResult(await post(`/api/servers/${encodeURIComponent(server.id)}/reenroll`, {}))); await refreshServers();
  })));
  if (server.status !== "revoked") actions.append(button("Revoke connection", "secondary", event => busy(event.currentTarget, async () => { if (!window.confirm("Revoke this agent connection? New snapshots will stop; saved evidence will remain.")) return; await post(`/api/servers/${encodeURIComponent(server.id)}/revoke`, {}); await refreshServers(); await renderRoute(); message("Agent connection revoked."); })));
  actions.append(button("Remove from console", "secondary", event => busy(event.currentTarget, async () => {
    if (!window.confirm(`Remove ${server.name} from this console? Its stored observations will be deleted and its agent revoked. Audit history remains. Nothing is uninstalled on the server.`)) return;
    await post(`/api/servers/${encodeURIComponent(server.id)}/remove`, {}); await refreshServers(); location.hash = "servers"; message("Server removed from the console. No remote files were changed.");
  })));
  return append(p, actions, result);
}
async function refreshServers() {
  const data = await api("/api/servers"); state.servers = data.items || [];
  const selector = $("server-selector"); selector.replaceChildren();
  state.servers.forEach(server => { const option = el("option", "", `${server.name} · ${server.id === "local-demo" ? "DEMO" : "READ-ONLY"}`); option.value = server.id; selector.append(option); });
  if (!state.servers.some(s => s.id === state.serverId)) state.serverId = state.servers.find(s => s.id !== "local-demo")?.id || (state.demoEnabled === false ? "" : "local-demo");
  selector.value = state.serverId;
}
function applyMode() {
  const demo = state.demoEnabled !== false && state.serverId === "local-demo", demoActionPage = state.demoEnabled !== false && ["commands", "approvals"].includes(state.route);
  const shownDemo = demo || demoActionPage;
  $("mode-label").textContent = shownDemo ? "DEMO · SIMULATED" : "REAL SERVER · READ-ONLY";
  $("mode-title").textContent = shownDemo ? "Demo environment" : "Real server monitoring";
  $("mode-description").textContent = demoActionPage ? "Command and approval demos always target local-demo. Real Community agents cannot execute actions." : demo ? "Metrics, incidents and actions for local-demo are simulated. Select a real server to inspect collected evidence." : "Collected observations from your selected server. Community agents have no remote execution capability.";
  $("workspace-mode").textContent = shownDemo ? "DEMO ENVIRONMENT" : "READ-ONLY MONITORING";
  $("sidebar-mode").textContent = shownDemo ? "Simulated infrastructure" : "Real collected evidence";
  $("scenario-label").hidden = !demo || demoActionPage;
  $("collect").hidden = demoActionPage || !state.serverId; $("collect").querySelector("span").textContent = demo ? "Collect demo snapshot" : "Refresh evidence";
  $("brief").hidden = demoActionPage || !state.serverId;
  $("server-selector").disabled = demoActionPage;
}
async function viewContent(route) {
  if (state.demoEnabled === false && ["commands", "approvals"].includes(route)) return panel("Read-only monitoring", "Demo actions are disabled.");
  if (state.demoEnabled === false && !state.servers.length && ["overview", "health", "security", "metrics", "services", "jobs", "sites"].includes(route)) return addServer();
  if (route === "add-server") return addServer();
  if (route === "commands") return commandCenter();
  if (route === "servers") { await refreshServers(); return append(panel("Registered servers", "Select a server to inspect its current evidence", link("Add server +", "add-server")), serverTable(state.servers)); }
  if (route === "overview" || route.startsWith("server/") || ["health", "security", "metrics", "services", "jobs", "sites"].includes(route)) {
    const serverId = route.startsWith("server/") ? route.slice(7) : state.serverId;
    state.serverId = serverId; $("server-selector").value = serverId; applyMode();
    const data = await api(`/api/servers/${encodeURIComponent(serverId)}`); updateSnapshot(data); const snapshot = data.snapshot || {};
    if (route === "overview") { const incidents = await api("/api/incidents"); data.incidents = (incidents.items || []).filter(item => item.server_id === serverId); return overview(data, data); }
    if (route.startsWith("server/")) {
      const fragment = el("div", "stack");
      append(fragment, serverId === "local-demo" ? el("p", "notice", "This server is a demo fixture. All of its observations and action outcomes are simulated.") : null, metricCards(snapshot), append(el("div", "columns"), chartPanel(data.history), analysisPanel(data.analysis, snapshot)), applicationPanel(snapshot), append(el("div", "detail-grid"), servicesPanel(snapshot.services, data.baseline?.services, snapshot), networkBaselinePanel(snapshot, data.baseline?.ports)), processesPanel(snapshot), trafficPanel(snapshot), capacityPanel(data.capacity, snapshot), sitesPanel(snapshot), serverId !== "local-demo" ? connectionPanel(data.server) : null);
      if (window.renderAIReview) fragment.append(window.renderAIReview(serverId));
      if (window.renderBlackBox && serverId !== "local-demo") fragment.append(window.renderBlackBox(data.black_box, data.incident_timeline));
      return append(fragment, advanced(snapshot, "Technical details · snapshot"));
    }
    if (route === "sites") return sitesPanel(snapshot);
    if (route === "metrics") return append(el("div", "stack"), metricCards(snapshot), chartPanel(data.history), capacityPanel(data.capacity, snapshot), trafficPanel(snapshot), ioPanels(snapshot.metrics));
    if (route === "health") return append(el("div", "stack"), metricCards(snapshot), applicationPanel(snapshot), capacityPanel(data.capacity, snapshot), servicesPanel(snapshot.services, data.baseline?.services, snapshot));
    if (route === "security") return append(el("div", "stack"), el("p", "notice", serverId === "local-demo" ? "These observations are simulated. Classification is an interpretation of the demo fixture." : "Classification interprets collected evidence. Missing log or application probes limit what can be established."), append(el("div", "detail-grid"), trafficPanel(snapshot), analysisPanel(data.analysis, snapshot)), networkBaselinePanel(snapshot, data.baseline?.ports), append(panel("Observed events", "Latest snapshot"), eventsList(snapshot.events)), window.renderBlackBox && serverId !== "local-demo" ? window.renderBlackBox(data.black_box, data.incident_timeline) : null);
    if (route === "services") return servicesPanel(snapshot.services, data.baseline?.services, snapshot);
    if (route === "jobs") { const jobs = await api("/api/jobs"); return append(el("div", "stack"), applicationPanel(snapshot), dataRecords((jobs.items || []).filter(item => item.server_id === serverId), "Jobs", "Recorded job activity")); }
  }
  if (route === "trust") {
    if (!window.renderTrustReputation) {
      return panel("Trust & Reputation", "Trust interface is unavailable.");
    }
    return window.renderTrustReputation();
  }
  if (route === "settings") {
    const data = await api("/api/settings");
    const root = el("div", "settings-tabs-shell");

    const header = el("div", "settings-tabs-header");
    append(
      header,
      el("div", "settings-eyebrow", "CONTROL CENTER"),
      el("h2", "", "Settings"),
      el("p", "muted", "Manage connections, alerts, security and advanced options.")
    );

    const tabs = el("div", "settings-tabs");
    tabs.setAttribute("role", "tablist");

    const content = el("div", "settings-tab-content");

    const panes = {};
    const buttons = {};

    const addTab = (id, label) => {
      const button = el("button", "settings-tab", label);
      button.type = "button";
      button.setAttribute("role", "tab");

      const pane = el("div", "settings-tab-pane");
      pane.dataset.settingsPane = id;
      pane.setAttribute("role", "tabpanel");

      button.addEventListener("click", () => activate(id));

      buttons[id] = button;
      panes[id] = pane;
      tabs.append(button);
      content.append(pane);
    };

    const activate = id => {
      Object.entries(buttons).forEach(([key, button]) => {
        const active = key === id;
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", String(active));
      });

      Object.entries(panes).forEach(([key, pane]) => {
        pane.hidden = key !== id;
      });

      try {
        sessionStorage.setItem("ezzesecure-settings-tab", id);
      } catch (_) {}
    };

    addTab("general", "General");
    addTab("alerts", "Alerts");
    addTab("security", "Security");
    addTab("advanced", "Advanced");

    const sectionTitle = (title, description) => {
      const section = el("div", "settings-tab-heading");
      append(section, el("h3", "", title), el("p", "muted", description));
      return section;
    };

    panes.general.append(
      sectionTitle(
        "General",
        "Workspace and services connected to EzzeSecure."
      )
    );

    const workspace = el("div", "settings-identity");
    append(
      workspace,
      el("div", "settings-identity-label", "Workspace"),
      el("strong", "", data.organization || "Local workspace"),
      el("span", "muted", `Signed in as ${data.username || "operator"}`)
    );
    panes.general.append(workspace);

    const connections = el("div", "settings-connections");
    connections.append(
      sectionTitle(
        "Connections",
        "Connect notification channels and optional intelligence services."
      )
    );

    const connectionGrid = el("div", "connection-grid");

    const connectionCard = (title, description, status, actionLabel, renderer, tone = "") => {
      const card = el("div", "connection-card");

      const top = el("div", "connection-card-top");
      const copy = el("div", "connection-card-copy");
      append(
        copy,
        el("h4", "", title),
        el("p", "muted", description)
      );

      const badge = el("span", `connection-badge ${tone}`, status);
      append(top, copy, badge);

      const open = el("button", "connection-action", actionLabel + " →");
      open.type = "button";

      const detail = el("div", "connection-detail");
      detail.hidden = true;

      let rendered = false;

      open.addEventListener("click", () => {
        const opening = detail.hidden;

        document.querySelectorAll(".connection-detail").forEach(node => {
          node.hidden = true;
        });

        document.querySelectorAll(".connection-action").forEach(node => {
          if (node !== open) node.textContent = node.dataset.label + " →";
        });

        if (opening) {
          if (!rendered && renderer) {
            const content = renderer();
            if (content) detail.append(content);
            rendered = true;
          }

          detail.hidden = false;
          open.textContent = "Close ↑";
        } else {
          detail.hidden = true;
          open.textContent = actionLabel + " →";
        }
      });

      open.dataset.label = actionLabel;

      append(card, top, open, detail);
      return card;
    };

    connectionGrid.append(
      connectionCard(
        "Email",
        "Receive alerts and incident notifications by email.",
        "Not configured",
        "Configure",
        window.renderEmailSettings
          ? () => window.renderEmailSettings()
          : null,
        "attention"
      ),

      connectionCard(
        "WhatsApp · EzzeSend",
        "Receive important alerts directly on WhatsApp.",
        "Not connected",
        "Connect",
        window.renderEzzeSendLink
          ? () => window.renderEzzeSendLink()
          : null,
        "attention"
      ),

      connectionCard(
        "AI Assistant",
        "Optional evidence analysis using your own provider.",
        data.ai_provider?.enabled ? "Connected" : "Disabled",
        "Configure",
        window.renderAISettings
          ? () => window.renderAISettings(data)
          : null,
        data.ai_provider?.enabled ? "connected" : ""
      )
    );

    connections.append(connectionGrid);
    panes.general.append(connections);

    panes.alerts.append(
      sectionTitle(
        "Alerts",
        "Define when an alert starts, how it escalates and where notifications should be delivered."
      )
    );

    if (window.renderResourceSettings)
      panes.alerts.append(window.renderResourceSettings(state.serverId));

    if (window.renderRoutingSettings)
      panes.alerts.append(window.renderRoutingSettings(state.serverId));

    panes.security.append(
      sectionTitle(
        "Security",
        "Configure Black Box protection and operator-controlled deception."
      )
    );

    if (window.renderCanarySettings)
      panes.security.append(window.renderCanarySettings(state.serverId));

    panes.advanced.append(
      sectionTitle(
        "Advanced",
        "Technical provider and integration controls for administrators."
      )
    );

    if (window.renderNotificationSettings)
      panes.advanced.append(window.renderNotificationSettings());

    panes.advanced.append(
      evidencePanel(
        "Workspace details",
        "Protected account and workspace metadata",
        data
      )
    );

    let initial = "general";
    try {
      const saved = sessionStorage.getItem("ezzesecure-settings-tab");
      if (saved && panes[saved]) initial = saved;
    } catch (_) {}

    activate(initial);

    root.append(header, tabs, content);
    return root;
  }
  const data = await api(`/api/${route}`);
  if (route === "incidents" && window.renderInvestigations) {
    const detail = state.serverId ? await api(`/api/servers/${encodeURIComponent(state.serverId)}`) : {};
    return window.renderInvestigations((data.items || []).filter(item => item.server_id === state.serverId), detail.incident_timeline || []);
  }
  if (route === "approvals") { const items = (data.items || []).filter(item => item.server_id === "local-demo"); if (!items.length) return append(panel("Demo approval queue", "Real Community agents do not execute remote actions"), empty("No demo approvals to review", "Propose a simulated action in the command center to create an approval."), link("Open command center ↗", "commands")); const stack = el("div", "stack"); items.forEach(item => stack.append(approvalCard(item))); return stack; }
  const items = (data.items || []).filter(item => !item.server_id || item.server_id === state.serverId);
  const content = el("div", "stack");
  if (route === "analyses" && window.renderAIReview) content.append(window.renderAIReview(state.serverId));
  return append(content, dataRecords(items, views.find(v => v[1] === route)?.[3] || human(route), "Records for the selected server"));
}
function listOrFields(data) {
  if (Array.isArray(data)) { if (!data.length) return empty("No observations", "The latest snapshot contains no records for this category."); const list = el("div", "stack"); data.forEach((row) => list.append(record(row))); return list; }
  return fields(data);
}
function updateSnapshot(data) { state.data = data; $("last-observed").textContent = `Observed ${date(data.snapshot?.observed_at || data.server?.last_seen)}`; }
async function renderRoute() {
  if (!state.user) return;
  const requested = location.hash.slice(1) || "overview";
  const valid = views.some((v) => v[1] === requested) || requested === "add-server" || /^server\/[a-zA-Z0-9_-]+$/.test(requested);
  if (!valid) { location.hash = "overview"; return; }
  state.route = requested; const id = ++state.request; const view = views.find((v) => v[1] === requested) || (requested === "add-server" ? ["", requested, "", "Add server", "Connect a read-only Linux agent."] : null) || ["", requested, "", "Server details", "Current evidence, resource history, and registered server details."];
  $("page-title").textContent = view[3]; $("breadcrumb-current").textContent = view[3]; $("page-description").textContent = view[4]; document.title = `${view[3]} · EzzeSecure Community`; applyMode();
  document.querySelectorAll(".nav-link").forEach((node) => { const active = node.dataset.route === requested || (requested.startsWith("server/") && node.dataset.route === "servers"); node.classList.toggle("active", active); if (active) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current"); });
  $("sidebar").classList.remove("open"); $("menu-toggle").setAttribute("aria-expanded", "false");
  $("content").replaceChildren(el("div", "loading", "Loading local evidence…"));
  try { const content = await viewContent(requested); if (id === state.request && state.user) $("content").replaceChildren(content); }
  catch (error) { if (id === state.request && state.user) $("content").replaceChildren(append(panel("Unable to load this view", error.message), button("Try again", "secondary", renderRoute))); }
}

views.forEach(([group, route, icon, title]) => {
  if (group) $("navigation").append(el("div", "nav-group", group));
  const a = el("a", "nav-link"); a.href = `#${route}`; a.dataset.route = route; const symbol = el("span", "nav-icon", icon); symbol.setAttribute("aria-hidden", "true"); append(a, symbol, el("span", "", title)); $("navigation").append(a);
});
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const submit = event.currentTarget.querySelector("button"); submit.disabled = true; $("login-error").textContent = "";
  try { await establishSession(await post("/api/login", { username: $("username").value.trim(), password: $("password").value })); }
  catch (error) { $("login-error").textContent = error.message; $("password").value = ""; }
  finally { submit.disabled = false; }
});
$("logout").addEventListener("click", (event) => busy(event.currentTarget, async () => { await post("/api/logout", {}); showLogin(); $("content").replaceChildren(); message(""); }));
$("menu-toggle").addEventListener("click", () => { const open = $("sidebar").classList.toggle("open"); $("menu-toggle").setAttribute("aria-expanded", String(open)); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape") { $("sidebar").classList.remove("open"); $("menu-toggle").setAttribute("aria-expanded", "false"); } });
$("collect").addEventListener("click", (event) => busy(event.currentTarget, async () => { if (state.serverId === "local-demo") { const data = await post("/api/collect", {}); updateSnapshot(data); await renderRoute(); message("A fresh local demo snapshot has been collected."); } else { await refreshServers(); await renderRoute(); message("Latest saved evidence refreshed. The agent sends new observations on its regular schedule."); } }));
$("brief").addEventListener("click", (event) => busy(event.currentTarget, async () => { const result = await post("/api/brief", {server_id: state.serverId}); message(result.message || "Daily brief generated from local evidence."); const brief = panel("Daily operations brief", "Generated from recorded observations for the selected server"); brief.append(typeof result.brief === "object" ? fields(result.brief) : el("p", "insight-copy", result.brief || "No brief content returned.")); $("content").prepend(brief); brief.classList.add("section-spacer"); brief.scrollIntoView({ behavior: "smooth", block: "start" }); }));
$("scenario").addEventListener("change", (event) => { const selector = event.currentTarget; if (!selector.value) return; busy(selector, async () => { const label = selector.options[selector.selectedIndex].textContent; const data = await post("/api/demo/scenario", { scenario: selector.value }); updateSnapshot(data); await renderRoute(); message(`${label} simulation loaded. All changes apply only to local demo fixtures.`); }).finally(() => { selector.value = ""; }); });
window.addEventListener("hashchange", () => { message(""); renderRoute(); });
$("server-selector").addEventListener("change", event => { state.serverId = event.target.value; message(""); if (state.route.startsWith("server/")) location.hash = `server/${state.serverId}`; else renderRoute(); });
api("/api/session").then(establishSession).catch(() => showLogin());
