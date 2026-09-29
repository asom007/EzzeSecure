"use strict";
(() => {
  const element = (tag, copy, className) => { const item = document.createElement(tag); if (copy !== undefined) item.textContent = String(copy); if (className) item.className = className; return item; };
  const labelled = (name, control) => { const wrapper = element("label", name); wrapper.append(control); return wrapper; };
  const number = (value, min, max) => { const control = element("input"); control.type = "number"; control.min = String(min); control.max = String(max); control.value = String(value); return control; };
  const choice = (options, selected) => { const control = element("select"); options.forEach(([value, title]) => { const option = element("option", title); option.value = value; control.append(option); }); control.value = selected; return control; };
  const action = (title, callback) => { const control = element("button", title, "button secondary"); control.type = "button"; control.addEventListener("click", callback); return control; };
  const statusText = (target, value) => { target.textContent = value; target.setAttribute("role", "status"); };
  const readable = (value) => String(value || "Unknown").replaceAll("_", " ").replace(/^./, part => part.toUpperCase());

  window.renderResourceSettings = serverId => {
    const box = panel(
      "Resource thresholds",
      "Set when resource pressure starts, escalates and recovers."
    );

    const body = element("div", undefined, "resource-policy-compact");
    box.append(body);

    if (!serverId || serverId === "local-demo") {
      body.append(element("p", "Select a real server to configure resource alerts."));
      return box;
    }

    api(`/api/resource-policies/${encodeURIComponent(serverId)}`).then(result => {
      const items = result.items || {};
      const resources = Object.entries(items);

      if (!resources.length) {
        body.append(element("p", "No resource policies are available."));
        return;
      }

      const intro = element("div", undefined, "resource-policy-summary");
      intro.append(
        element("strong", "Default policy"),
        element(
          "span",
          "70% start · +5% escalation · 60% recovery · 2 min confirmation",
          "helper-text"
        )
      );
      body.append(intro);

      const tableWrap = element("div", undefined, "resource-policy-table-wrap");
      const table = element("table", undefined, "resource-policy-table");

      const head = element("thead");
      const header = element("tr");
      for (const title of ["Resource", "Start", "Step", "Recovery", "Confirm", ""]) {
        header.append(element("th", title));
      }
      head.append(header);
      table.append(head);

      const tbody = element("tbody");
      const rows = [];

      for (const [resource, policy] of resources) {
        const tr = element("tr");
        const controls = {
          start_threshold: number(policy.start_threshold, 1, 100),
          escalation_step: number(policy.escalation_step, 1, 20),
          recovery_threshold: number(policy.recovery_threshold, 0, 99),
          minimum_duration_seconds: number(policy.minimum_duration_seconds, 0, 86400)
        };

        controls.start_threshold.setAttribute("aria-label", `${readable(resource)} start threshold`);
        controls.escalation_step.setAttribute("aria-label", `${readable(resource)} escalation step`);
        controls.recovery_threshold.setAttribute("aria-label", `${readable(resource)} recovery threshold`);
        controls.minimum_duration_seconds.setAttribute("aria-label", `${readable(resource)} confirmation seconds`);

        const resourceCell = element("td");
        resourceCell.append(
          element("strong", readable(resource)),
          element(
            "span",
            resource === "ram" ? "Memory" :
            resource === "cpu" ? "Processor" :
            resource === "disk" ? "Storage" :
            "System load",
            "resource-policy-caption"
          )
        );

        const startCell = element("td");
        startCell.append(controls.start_threshold, element("span", "%", "resource-unit"));

        const stepCell = element("td");
        stepCell.append(controls.escalation_step, element("span", "%", "resource-unit"));

        const recoveryCell = element("td");
        recoveryCell.append(controls.recovery_threshold, element("span", "%", "resource-unit"));

        const durationCell = element("td");
        durationCell.append(controls.minimum_duration_seconds, element("span", "sec", "resource-unit"));

        const status = element("td", "", "resource-save-state");

        tr.append(resourceCell, startCell, stepCell, recoveryCell, durationCell, status);
        tbody.append(tr);

        rows.push({ resource, controls, status });
      }

      table.append(tbody);
      tableWrap.append(table);
      body.append(tableWrap);

      const footer = element("div", undefined, "resource-policy-footer");
      const note = element(
        "p",
        "Changes apply to future observations. Existing incident history is preserved.",
        "helper-text"
      );

      const save = action("Save thresholds", async () => {
        save.disabled = true;
        let failed = false;

        for (const row of rows) {
          row.status.textContent = "";

          const values = Object.fromEntries(
            Object.entries(row.controls).map(([key, control]) => [key, Number(control.value)])
          );

          try {
            await post(
              `/api/resource-policies/${encodeURIComponent(serverId)}`,
              { resource: row.resource, policy: values }
            );
            row.status.textContent = "Saved";
            row.status.classList.remove("error");
          } catch (error) {
            failed = true;
            row.status.textContent = "Error";
            row.status.classList.add("error");
          }
        }

        statusText(
          note,
          failed
            ? "Some thresholds could not be saved. Review the marked rows."
            : "Thresholds saved. Future samples will use this policy."
        );

        save.disabled = false;
      });

      footer.append(note, save);
      body.append(footer);
    }).catch(error => body.append(element("p", error.message)));

    return box;
  };

  window.renderBlackBox = (evidence, timeline) => {
    const box = panel("Black Box evidence", "Sampled Agent and Control Plane receipts, ordered by collection and receipt time.");
    const status = evidence?.integrity?.status || "UNAVAILABLE";
    box.append(element("p", `Agent chain integrity: ${readable(status)}. Last chain receipt: ${evidence?.integrity?.last_verified_at ? date(evidence.integrity.last_verified_at) : "unavailable"}.`));
    for (const stream of evidence?.stream_integrity || []) box.append(element("p", `${stream.source}: ${readable(stream.status)} (${stream.count} receipts).`));
    box.append(element("p", evidence?.limitation || "No forensic evidence available.", "helper-text"));
    const entries = Array.isArray(evidence?.events) ? evidence.events : [];
    if (!entries.length) { box.append(empty("No forensic receipts", "Enable and configure the Agent Black Box collector. Missing evidence does not prove that no activity occurred.")); return box; }
    for (const item of entries.slice(0, 30)) {
      const row = element("article", undefined, "record");
      row.append(element("h3", readable(item.event_type)));
      row.append(element("p", `Observed ${date(item.observed_at)} · Received ${date(item.received_at)} · ${readable(item.integrity)}`));
      const details = element("details", undefined, "advanced-evidence"); details.append(element("summary", "Technical details"));
      const list = element("dl", undefined, "fields");
      for (const [key, value] of Object.entries({ sequence: item.sequence, source: item.source, ...item.details })) {
        if (value === null || value === undefined || typeof value === "object") continue;
        list.append(element("dt", readable(key)), element("dd", value));
      }
      details.append(list); row.append(details); box.append(row);
    }
    if (entries.length > 30) box.append(element("p", "Showing the 30 most recent receipts. Earlier saved evidence remains in the Control Plane."));
    return box;
  };

  window.renderInvestigations = (items, timeline) => {
    const layout = element("div", undefined, "stack");
    if (!items.length) return append(layout, panel("Incidents", "Conditions requiring investigation"), empty("No incidents recorded", "No incident is open for this server in saved evidence."));
    for (const incident of items) {
      const box = panel(incident.title || "Incident", `${readable(incident.severity)} · ${readable(incident.status)}`);
      box.append(element("p", incident.assessment || "Cause not established from available evidence."));
      box.append(element("p", `First observed ${date(incident.first_seen)} · Last observed ${date(incident.last_seen)}.`));
      if (incident.current_value !== undefined) box.append(element("p", `Current ${num(incident.current_value, 1)}% · Threshold ${num(incident.threshold_value, 1)}% · Peak ${num(incident.peak_value, 1)}% · Duration ${num(incident.duration_seconds / 60, 1)} minutes.`));
      if (incident.probable_explanation) box.append(element("p", `Explanation: ${incident.probable_explanation}`));
      if (incident.confidence) box.append(element("p", `Confidence: ${incident.confidence}`));
      for (const suggestion of incident.recommendations || []) box.append(element("p", `Recommendation: ${suggestion}`));
      for (const gap of incident.evidence_gaps || []) box.append(element("p", `Evidence gap: ${gap}`));
      const entries = (timeline || []).filter(row => row.incident_id === incident.id).slice(0, 30);
      if (entries.length) {
        box.append(element("h3", "Timeline"));
        for (const entry of entries) box.append(element("p", `${date(entry.observed_at)} · ${entry.summary} Confidence: ${entry.confidence}.`));
      }
      const technical = element("details", undefined, "advanced-evidence"); technical.append(element("summary", "Technical details"));
      technical.append(element("p", `Incident ID: ${incident.id} · Correlation key: ${incident.correlation_key}.`));
      box.append(technical); layout.append(box);
    }
    return layout;
  };

  window.renderEmailSettings = () => {
    const box = element("div", undefined, "notification-channel");
    const head = element("div", undefined, "notification-channel-head");
    const copy = element("div");
    copy.append(element("h3", "Email"), element("p", "Receive server and security alerts directly by email.", "helper-text"));
    const state = element("span", "Not configured", "connection-state");
    head.append(copy, state);

    const form = element("form", undefined, "form-stack");
    const notice = element("p", "", "helper-text");
    const enabled = choice([["false","Disabled"],["true","Enabled"]], "false");
    const recipient = element("input"); recipient.type="email"; recipient.placeholder="you@example.com";
    const sender = element("input"); sender.type="email"; sender.placeholder="alerts@example.com";

    const host = element("input"); host.placeholder="smtp.example.org";
    const port = number(587,1,65535);
    const mode = choice([["local","Local mail server"],["starttls","External SMTP · STARTTLS"],["ssl","External SMTP · TLS"]],"local");

    const advanced = element("details", undefined, "notification-advanced");
    advanced.append(element("summary","Advanced delivery settings"));
    const advancedBody = element("div", undefined, "notification-advanced-body");
    advancedBody.append(
      labelled("Delivery method",mode),
      labelled("SMTP host",host),
      labelled("Port",port)
    );
    advanced.append(advancedBody);

    const history = element("div");

    const refresh = async () => {
      const data=await api("/api/email/settings"), settings=data.settings;
      enabled.value=String(settings.enabled);
      host.value=settings.host || "";
      port.value=String(settings.port || 587);
      mode.value=settings.tls_mode || "local";
      sender.value=settings.sender || "";
      recipient.value=settings.recipient || "";
      state.textContent=settings.enabled && settings.recipient ? "Connected" : "Not configured";

      history.replaceChildren(element("h4","Recent email delivery"));
      for(const row of data.deliveries || [])
        history.append(element("p",`${date(row.created_at)} · ${readable(row.event_class)} · ${readable(row.status)}.`));
      if(!data.deliveries.length)
        history.append(element("p","No email attempts recorded."));
    };

    const controls=element("div",undefined,"button-row");
    controls.append(
      action("Save",async()=>{
        try{
          await post("/api/email/save",{
            enabled:enabled.value==="true",
            host:host.value.trim(),
            port:Number(port.value),
            tls_mode:mode.value,
            sender:sender.value.trim(),
            recipient:recipient.value.trim()
          });
          statusText(notice,"Email settings saved.");
          await refresh();
        }catch(error){statusText(notice,error.message);}
      }),
      action("Send test",async()=>{
        try{
          const data=await post("/api/email/test",{});
          statusText(notice,data.queued ? "Test email queued." : "Enable email and enter a recipient first.");
          await refresh();
        }catch(error){statusText(notice,error.message);}
      })
    );

    form.append(
      labelled("Email notifications",enabled),
      labelled("Send alerts to",recipient),
      labelled("From address",sender),
      advanced,
      controls,
      notice,
      history
    );
    form.addEventListener("submit",e=>e.preventDefault());
    box.append(head,form);
    refresh().catch(error=>statusText(notice,error.message));
    return box;
  };

  window.renderRoutingSettings = serverId => {
    const box=element("div",undefined,"notification-routing");
    box.append(element("h3","Alert routing"),element("p","Choose which alerts should reach you and when.","helper-text"));

    const note=element("p","","helper-text");
    const rows=element("div",undefined,"notification-routing-list");
    const eventClass=choice([
      ["resource","Resource escalation"],
      ["security","Security incidents"],
      ["agent_lost","Server offline"],
      ["canary","Canary triggered"],
      ["recovery","Recovery"]
    ],"resource");
    const minimum=choice(
      ["INFO","WARNING","ELEVATED","HIGH","CRITICAL","SEVERE","EMERGENCY"].map(v=>[v,readable(v)]),
      "WARNING"
    );
    const enabled=choice([["true","Enabled"],["false","Disabled"]],"true");

    const refresh=async()=>{
      const data=await api("/api/email/settings");
      rows.replaceChildren();
      for(const route of data.routes || []){
        rows.append(element(
          "div",
          `${readable(route.event_class)} · Email · ${readable(route.min_severity)} and above · ${route.enabled?"Enabled":"Disabled"}`,
          "notification-routing-row"
        ));
      }
      if(!data.routes.length) rows.append(element("p","No alert routes configured."));
    };

    const advanced=element("details",undefined,"notification-advanced");
    advanced.append(element("summary","Configure alert routing"));
    const body=element("div",undefined,"notification-advanced-body");
    body.append(
      labelled("Alert type",eventClass),
      labelled("Minimum severity",minimum),
      labelled("Status",enabled),
      action("Save route",async()=>{
        try{
          if(!serverId || serverId==="local-demo") throw new Error("Select a real server first.");
          await post("/api/email/route",{
            server_id:serverId,
            channel:"email",
            event_class:eventClass.value,
            min_severity:minimum.value,
            enabled:enabled.value==="true"
          });
          statusText(note,"Route saved.");
          await refresh();
        }catch(error){statusText(note,error.message);}
      }),
      note
    );
    advanced.append(body);
    box.append(rows,advanced);
    refresh().catch(error=>statusText(note,error.message));
    return box;
  };

  window.renderCanarySettings = serverId => {
    const box = panel("Operator-controlled canary URL", "Place this URL only in infrastructure you control. A request records the connection peer; it does not identify a visitor or reveal physical location.");
    const label = element("input"); label.maxLength = 80; label.placeholder = "Administrative decoy";
    const note = element("p", "", "helper-text"); const rows = element("div");
    const refresh = async () => { const data = await api("/api/canaries"); rows.replaceChildren();
      for (const item of data.items || []) rows.append(element("p", `${item.label} · ${item.server_id} · ${item.enabled ? "Enabled" : "Disabled"}`));
      if (!data.items.length) rows.append(element("p", "No canaries created.")); };
    box.append(labelled("Label", label), action("Create canary", async () => {
      try { if (!serverId || serverId === "local-demo") throw new Error("Select a real server first.");
        const result = await post("/api/canaries/create", { server_id: serverId, label: label.value.trim() });
        statusText(note, `Copy this path now; it will not be shown again: ${result.path}`); await refresh(); }
      catch (error) { statusText(note, error.message); }
    }), note, rows);
    refresh().catch(error => statusText(note, error.message)); return box;
  };

  window.renderEzzeSendLink = () => {
    const box = panel("WhatsApp · Connect EzzeSend", "Optional account linking. A phone number identifies an account but never authenticates it.");
    const status = element("p", "Checking provider support…", "helper-text"); box.append(status);
    const phone = element("input"); phone.type = "tel"; phone.autocomplete = "tel"; phone.placeholder = "+ country code and verified number";
    const code = element("input"); code.autocomplete = "off"; code.placeholder = "One-time authorization code from EzzeSend";
    let challenge = null;
    const connect = action("Request verified link", async () => {
      try { const result = await post("/api/ezzesend/link/start", { phone: phone.value.trim() });
        challenge = { id: result.challenge_id, state: result.state };
        phone.value = ""; statusText(status, result.message); }
      catch (error) { phone.value = ""; statusText(status, error.message); }
    });
    const finish = action("Complete verified link", async () => {
      try { if (!challenge) throw new Error("Request a verified link first.");
        const result = await post("/api/ezzesend/link/complete", { challenge_id: challenge.id, state: challenge.state, grant_code: code.value.trim() });
        challenge = null; code.value = ""; statusText(status, result.status === "linked" ? "EzzeSend linked. Scoped notification credential saved privately." : "Linking remains unavailable."); }
      catch (error) { code.value = ""; statusText(status, error.message); }
    });
    api("/api/ezzesend/link/status").then(result => {
      statusText(status, result.status); connect.disabled = finish.disabled = !result.available;
      if (result.available) box.append(labelled("Registered phone number", phone), connect, labelled("EzzeSend one-time authorization code", code), finish);
    }).catch(error => statusText(status, error.message));
    return box;
  };
})();
