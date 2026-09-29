"use strict";
(() => {
  const node = (tag, text) => { const n = document.createElement(tag); if (text) n.textContent = text; return n; };
  const field = (label, input) => { const n = node("label", label); n.append(input); return n; };
  const input = type => { const n = node("input"); n.type = type; n.autocomplete = "off"; return n; };
  const select = values => { const n = node("select"); for (const [value, label] of values) { const o = node("option", label); o.value = value; n.append(o); } return n; };
  window.renderNotificationSettings = () => {
    const box = node("details");
    box.className = "notification-advanced whatsapp-advanced";

    const summary = node("summary", "Advanced WhatsApp integration");
    const intro = node("p", "Technical connection settings for manual/provider integration.");
    intro.className = "helper-text";

    const form = node("form");
    form.className = "form-stack";

    box.append(summary, intro);
    const enabled = select([["false", "Disabled"], ["true", "Enabled"]]);
    const url = input("url"); url.placeholder = "https://your-ezzesend.example/api/integrations/ezzesecure"; url.maxLength = 500;
    const token = input("password"); token.autocomplete = "new-password";
    const severity = select([["MEDIUM", "Medium"], ["HIGH", "High"], ["CRITICAL", "Critical"]]); severity.value = "HIGH";
    const cooldown = input("number"); cooldown.min = "300"; cooldown.max = "86400"; cooldown.value = "1800";
    const events = node("fieldset"); events.append(node("legend", "Notify on"));
    const checks = {}, wrappers = {};
    const v2 = new Set(["resource_escalation", "resource_recovery", "canary_triggered", "evidence_gap"]);
    for (const [id, label] of Object.entries({security_incident:"Security incidents", server_offline:"Server offline", service_failure:"Service failure", disk_critical:"Disk critical (legacy v1)", resource_pressure:"Resource escalation (legacy v1)", integrity_finding:"Integrity findings",resource_escalation:"Resource escalation",resource_recovery:"Resource recovery",canary_triggered:"Canary triggered",evidence_gap:"Evidence stream gap"})) {
      checks[id] = input("checkbox"); checks[id].checked = true; wrappers[id] = field(label, checks[id]); events.append(wrappers[id]);
    }
    const status = node("p"); status.setAttribute("role", "status");
    const mask = node("p"); const history = node("div");
    const controls = node("div"); controls.className = "button-row";
    let contractVersion = 1;
    const paint = s => {enabled.value=String(s.enabled);url.value=s.api_url;severity.value=s.minimum_severity;cooldown.value=s.cooldown;token.value="";contractVersion=s.contract_version || 1;mask.textContent=`Stored token: ${s.token_mask} · Provider contract v${contractVersion}`;Object.entries(checks).forEach(([id,c])=>{c.checked=s.event_types.includes(id);wrappers[id].hidden=v2.has(id)&&contractVersion!==2;});if(!s.available)status.textContent="Install the optional notifications encryption dependency before saving.";};
    const refresh = async () => { const result = await api("/api/notifications/settings"); paint(result.settings); history.replaceChildren(node("h3", "Recent delivery attempts")); for (const d of result.deliveries) history.append(node("p", `${new Date(d.created_at*1000).toISOString()} · ${d.status} · ${d.attempts} attempt(s)${d.reason ? " · " + d.reason : ""}`)); if(!result.deliveries.length)history.append(node("p", "No delivery attempts.")); };
    const perform = async action => {
      controls.querySelectorAll("button").forEach(b=>{b.disabled=true;});
      try {
        if(action === "refresh") {await refresh(); status.textContent="Delivery records refreshed."; return;}
        const data = action === "save" ? {enabled:enabled.value==="true",api_url:url.value.trim(),token:token.value,minimum_severity:severity.value,event_types:Object.keys(checks).filter(k=>checks[k].checked && (!v2.has(k) || contractVersion===2)),cooldown:Number(cooldown.value),contract_version:contractVersion} : {};
        const result = await post(`/api/notifications/${action}`, data);
        await refresh(); status.textContent=result.message || `${result.status}${result.reason ? " · " + result.reason : ""}`;
      } catch(error) {status.textContent=error.message;}
      finally {token.value="";controls.querySelectorAll("button").forEach(b=>{b.disabled=false;});}
    };
    for (const [action,label] of [["save","Save"],["test-connection","Test saved connection (no message)"],["test-notification","Send test notification"],["refresh","Refresh delivery status"],["disable","Disable and forget token"]]) {
      const b=node("button",label);b.type="button";b.className="button secondary";b.addEventListener("click",()=>perform(action));controls.append(b);
    }
    form.addEventListener("submit", e=>e.preventDefault());
    form.append(field("Enabled",enabled),field("Integration API URL",url),field("Integration credential",token),mask,field("Minimum severity",severity),events,field("Cooldown in seconds",cooldown),node("p","Save before testing. Send test notification sends one fixed test alert to the EzzeSend allowlist. Accepted means queued by EzzeSend, not confirmed delivered by WhatsApp. INFO and LOW remain dashboard-only."),controls,status,history);
    box.append(form);refresh().catch(e=>{status.textContent=e.message;});return box;
  };
})();
