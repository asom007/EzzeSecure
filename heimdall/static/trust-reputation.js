"use strict";

(() => {
  const node = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = String(text);
    if (cls) n.className = cls;
    return n;
  };

  const metric = (label, value, note) => {
    const card = node("div", null, "trust-metric");
    card.append(
      node("span", label, "trust-metric-label"),
      node("strong", value, "trust-metric-value"),
      node("small", note, "muted")
    );
    return card;
  };

  const emptyState = (title, copy) => {
    const box = node("div", null, "trust-empty");
    box.append(node("strong", title), node("p", copy, "muted"));
    return box;
  };

  const badge = (text, tone = "") =>
    node("span", text, `trust-badge ${tone}`.trim());

  const renderRules = async target => {
    const data = await api("/api/trust/rules");
    target.replaceChildren();

    const toolbar = node("div", null, "trust-toolbar");
    toolbar.append(
      node("div", "Allow trusted sources, watch uncertain ones, and block known abuse.", "muted")
    );

    const form = node("form", null, "trust-rule-form");

    const listType = node("select");
    [
      ["allow", "Allowlist"],
      ["watch", "Watchlist"],
      ["block", "Blocklist"]
    ].forEach(([value, label]) => {
      const option = node("option", label);
      option.value = value;
      listType.append(option);
    });

    const kind = node("select");
    [
      ["domain", "Domain"],
      ["email", "Email"],
      ["ip", "IP / network"],
      ["pattern", "Text pattern"]
    ].forEach(([value, label]) => {
      const option = node("option", label);
      option.value = value;
      kind.append(option);
    });

    const value = node("input");
    value.placeholder = "example.com, user@example.com, 192.0.2.0/24…";

    const reason = node("input");
    reason.placeholder = "Reason (optional)";

    const add = node("button", "Add rule", "button secondary");
    add.type = "submit";

    const status = node("p", "", "helper-text");

    form.append(listType, kind, value, reason, add);

    form.addEventListener("submit", async event => {
      event.preventDefault();
      add.disabled = true;
      try {
        await post("/api/trust/rules/add", {
          list_type: listType.value,
          kind: kind.value,
          value: value.value.trim(),
          reason: reason.value.trim()
        });
        value.value = "";
        reason.value = "";
        status.textContent = "Rule saved.";
        await renderRules(target);
      } catch (error) {
        status.textContent = error.message;
      } finally {
        add.disabled = false;
      }
    });

    target.append(toolbar, form, status);

    const grid = node("div", null, "trust-rule-columns");

    for (const type of ["allow", "watch", "block"]) {
      const card = node("section", null, "trust-rule-column");
      const title = type === "allow" ? "Allowlist" : type === "watch" ? "Watchlist" : "Blocklist";
      const tone = type === "allow" ? "good" : type === "watch" ? "warn" : "bad";

      card.append(
        node("div", null, "trust-rule-heading")
      );
      card.firstChild.append(
        node("h3", title),
        badge(
          `${(data.items || []).filter(r => r.list_type === type).length} rules`,
          tone
        )
      );

      const rows = (data.items || []).filter(r => r.list_type === type);

      if (!rows.length) {
        card.append(
          emptyState(
            `No ${title.toLowerCase()} rules`,
            "Add a domain, email, IP/network or bounded text pattern."
          )
        );
      }

      rows.forEach(rule => {
        const row = node("div", null, "trust-rule-row");
        const copy = node("div");
        copy.append(
          node("strong", rule.value),
          node("small", `${rule.kind}${rule.reason ? " · " + rule.reason : ""}`, "muted")
        );

        const remove = node("button", "Remove", "trust-link-button");
        remove.type = "button";
        remove.addEventListener("click", async () => {
          remove.disabled = true;
          try {
            await post("/api/trust/rules/remove", { id: rule.id });
            await renderRules(target);
          } catch (error) {
            status.textContent = error.message;
            remove.disabled = false;
          }
        });

        row.append(copy, remove);
        card.append(row);
      });

      grid.append(card);
    }

    target.append(grid);
  };

  const renderIntegrations = async target => {
    const data = await api("/api/form-shield/credentials");

    const section = node("section", null, "form-shield-integrations");

    const heading = node("div", null, "trust-section-heading");
    heading.append(
      node("h3", "Website integrations"),
      node(
        "p",
        "Create a scoped credential for each website that sends form submissions to Form Shield.",
        "muted"
      )
    );

    const form = node("form", null, "form-shield-integration-form");
    const label = node("input");
    label.type = "text";
    label.maxLength = 80;
    label.placeholder = "Website name, e.g. Company website";

    const create = node("button", "Create integration", "button secondary");
    create.type = "submit";

    const status = node("p", "", "helper-text");

    form.append(label, create);
    section.append(heading, form, status);

    const secretBox = node("div", null, "integration-secret-box");
    secretBox.hidden = true;

    const secretTitle = node("strong", "Save this credential now");
    const secretNote = node(
      "p",
      "This secret is shown once. EzzeSecure stores only its hash. If it is lost, revoke it and create a new integration.",
      "muted"
    );

    const secretRow = node("div", null, "integration-secret-row");
    const secretValue = node("input");
    secretValue.type = "text";
    secretValue.readOnly = true;
    secretValue.autocomplete = "off";

    const copy = node("button", "Copy", "button secondary");
    copy.type = "button";

    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(secretValue.value);
        copy.textContent = "Copied";
      } catch (_) {
        secretValue.focus();
        secretValue.select();
        copy.textContent = "Select & copy";
      }
    });

    secretRow.append(secretValue, copy);
    secretBox.append(secretTitle, secretNote, secretRow);
    section.append(secretBox);

    const list = node("div", null, "integration-list");

    const paint = items => {
      list.replaceChildren();

      if (!items?.length) {
        list.append(
          emptyState(
            "No website integrations",
            "Create one credential per website or application that should use Form Shield."
          )
        );
        return;
      }

      items.forEach(item => {
        const row = node("article", null, "integration-row");

        const copyBlock = node("div");
        copyBlock.append(
          node("strong", item.label),
          node(
            "small",
            item.enabled
              ? `Active · Created ${item.created_at}${item.last_used_at ? " · Last used " + item.last_used_at : ""}`
              : `Revoked${item.revoked_at ? " · " + item.revoked_at : ""}`,
            "muted"
          )
        );

        const actions = node("div", null, "integration-row-actions");
        actions.append(
          badge(item.enabled ? "Active" : "Revoked", item.enabled ? "good" : "neutral")
        );

        if (item.enabled) {
          const revoke = node("button", "Revoke", "trust-link-button");
          revoke.type = "button";

          revoke.addEventListener("click", async () => {
            revoke.disabled = true;
            status.textContent = "Revoking integration…";

            try {
              const result = await post(
                "/api/form-shield/credentials/revoke",
                { id: item.id }
              );

              status.textContent = "Integration revoked.";
              paint(result.items || []);
            } catch (error) {
              status.textContent = error.message;
              revoke.disabled = false;
            }
          });

          actions.append(revoke);
        }

        row.append(copyBlock, actions);
        list.append(row);
      });
    };

    paint(data.items || []);

    form.addEventListener("submit", async event => {
      event.preventDefault();

      const value = label.value.trim();

      if (!value) {
        status.textContent = "Enter a website or integration name.";
        return;
      }

      create.disabled = true;
      status.textContent = "Creating scoped credential…";

      try {
        const result = await post(
          "/api/form-shield/credentials/create",
          { label: value }
        );

        label.value = "";
        secretValue.value = result.credential.secret;
        secretBox.hidden = false;
        copy.textContent = "Copy";

        status.textContent =
          "Integration created. Save the credential before leaving this page.";

        paint(result.items || []);
      } catch (error) {
        status.textContent = error.message;
      } finally {
        create.disabled = false;
      }
    });

    section.append(list);
    target.prepend(section);
  };

  const renderEvents = async target => {
    const data = await api("/api/abuse/events");
    target.replaceChildren();

    const events = data.items || [];
    const quarantined = events.filter(x => x.status === "quarantined");
    const blocked = events.filter(x => x.status === "block" || x.status === "blocked");

    const metrics = node("div", null, "trust-metrics");
    metrics.append(
      metric("Protection", "Active", "Deterministic local evaluation"),
      metric("Quarantined", quarantined.length, "Needs review"),
      metric("Blocked", blocked.length, "High-confidence abuse"),
      metric("Recorded", events.length, "Recent local decisions")
    );
    target.append(metrics);

    if (!events.length) {
      target.append(
        emptyState(
          "No abuse decisions recorded",
          "Form Shield evidence will appear here when an integration submits bounded form metadata for evaluation."
        )
      );
      return;
    }

    const list = node("div", null, "trust-event-list");

    events.forEach(item => {
      const row = node("article", null, "trust-event");
      const head = node("div", null, "trust-event-head");

      const tone =
        item.decision === "block" ? "bad" :
        item.decision === "quarantine" ? "warn" : "good";

      const copy = node("div");
      copy.append(
        node("strong", `${item.intent.replaceAll("_", " ")} · risk ${item.risk_score}`),
        node("small", `${item.source} · ${item.created_at}`, "muted")
      );

      head.append(copy, badge(item.decision, tone));
      row.append(head);

      if (item.evidence?.length) {
        const evidence = node("ul", null, "trust-evidence");
        item.evidence.forEach(text => evidence.append(node("li", text)));
        row.append(evidence);
      }

      if (item.status === "quarantined") {
        const actions = node("div", null, "button-row");

        for (const [action, label] of [
          ["release", "Release"],
          ["block", "Block"]
        ]) {
          const button = node("button", label, "button secondary");
          button.type = "button";
          button.addEventListener("click", async () => {
            button.disabled = true;
            try {
              await post(`/api/abuse/events/${action}`, { id: item.id });
              await renderEvents(target);
            } catch (error) {
              button.disabled = false;
            }
          });
          actions.append(button);
        }

        row.append(actions);
      }

      list.append(row);
    });

    target.append(list);
  };

  const renderReputation = async target => {
    const data = await api("/api/reputation/findings");
    target.replaceChildren();

    const intro = node("div", null, "trust-reputation-intro");
    intro.append(
      node("h3", "Domain reputation evidence"),
      node(
        "p",
        "Track DNS, MX, SPF, DMARC, TLS and other observed reputation findings. EzzeSecure reports evidence rather than inventing a universal reputation score.",
        "muted"
      )
    );
    target.append(intro);

    const scanForm = node("form", null, "reputation-scan-form");
    const domain = node("input");
    domain.type = "text";
    domain.placeholder = "example.com";
    domain.autocomplete = "off";
    domain.maxLength = 253;

    const scan = node("button", "Scan domain", "button secondary");
    scan.type = "submit";

    const scanStatus = node("p", "", "helper-text");

    scanForm.append(domain, scan);

    scanForm.addEventListener("submit", async event => {
      event.preventDefault();

      const value = domain.value.trim();
      if (!value) {
        scanStatus.textContent = "Enter a domain to scan.";
        return;
      }

      scan.disabled = true;
      scan.textContent = "Scanning…";
      scanStatus.textContent = "Checking DNS, TLS and mail authentication evidence…";

      try {
        const result = await post("/api/reputation/scan", {
          domain: value
        });

        scanStatus.textContent = result.mail_service_detected
          ? `Scan complete for ${result.domain}. Email service detected.`
          : `Scan complete for ${result.domain}. No email service detected; email checks are not applicable.`;

        domain.value = result.domain;

        setTimeout(() => {
          renderReputation(target).catch(() => {});
        }, 350);
      } catch (error) {
        scanStatus.textContent = error.message;
        scan.disabled = false;
        scan.textContent = "Scan domain";
      }
    });

    target.append(scanForm, scanStatus);

    if (!(data.items || []).length) {
      target.append(
        emptyState(
          "No reputation baseline recorded yet",
          "No DNS, mail-authentication or TLS reputation findings have been recorded for this workspace."
        )
      );
      return;
    }

    const items = data.items || [];

    // Keep only the newest finding for each domain + evidence kind.
    const latest = new Map();
    for (const item of items) {
      const key = `${item.domain}::${item.kind}`;
      if (!latest.has(key)) latest.set(key, item);
    }

    const domains = new Map();
    for (const item of latest.values()) {
      if (!domains.has(item.domain)) domains.set(item.domain, []);
      domains.get(item.domain).push(item);
    }

    const latestHeading = node("div", null, "trust-section-heading");
    latestHeading.append(
      node("h3", "Latest assessment"),
      node("p", "Newest observed evidence for each domain.", "muted")
    );
    target.append(latestHeading);

    const domainGrid = node("div", null, "reputation-domain-grid");

    const order = {
      dns: 1,
      tls: 2,
      mx: 3,
      spf: 4,
      dmarc: 5,
      mail: 6,
      blocklist: 7
    };

    for (const [domainName, findings] of domains.entries()) {
      const card = node("section", null, "reputation-domain-card");

      const head = node("div", null, "reputation-domain-head");
      const title = node("div");
      title.append(
        node("h3", domainName),
        node("small", "Latest collected evidence", "muted")
      );
      head.append(title);
      card.append(head);

      const rows = node("div", null, "reputation-finding-list");

      findings
        .sort((a, b) => (order[a.kind] || 99) - (order[b.kind] || 99))
        .forEach(item => {
          const tone =
            item.status === "healthy" ? "good" :
            item.status === "critical" ? "bad" :
            item.status === "attention" ? "warn" :
            item.status === "not_applicable" ? "neutral" : "";

          const statusLabel =
            item.status === "not_applicable"
              ? "Not applicable"
              : item.status;

          const row = node("div", null, "reputation-finding-row");

          const copy = node("div", null, "reputation-finding-copy");
          copy.append(
            node("strong", item.kind.toUpperCase()),
            node("span", item.summary || "No summary supplied.", "muted")
          );

          row.append(copy, badge(statusLabel, tone));
          rows.append(row);
        });

      card.append(rows);
      domainGrid.append(card);
    }

    target.append(domainGrid);

    const history = node("details", null, "reputation-history");
    const summary = node(
      "summary",
      `Scan history · ${items.length} recorded findings`
    );
    history.append(summary);

    const historyList = node("div", null, "reputation-history-list");

    items.forEach(item => {
      const row = node("div", null, "reputation-history-row");

      const copy = node("div");
      copy.append(
        node("strong", `${item.domain} · ${item.kind.toUpperCase()}`),
        node("small", item.observed_at, "muted")
      );

      const statusLabel =
        item.status === "not_applicable"
          ? "Not applicable"
          : item.status;

      const tone =
        item.status === "healthy" ? "good" :
        item.status === "critical" ? "bad" :
        item.status === "attention" ? "warn" :
        item.status === "not_applicable" ? "neutral" : "";

      row.append(copy, badge(statusLabel, tone));
      historyList.append(row);
    });

    history.append(historyList);
    target.append(history);
  };

  window.renderTrustReputation = async () => {
    const root = node("div", null, "trust-shell");

    const header = node("section", null, "trust-hero");
    header.append(
      node("div", "TRUST & ABUSE", "settings-eyebrow"),
      node("h2", "Protect what reaches your business"),
      node(
        "p",
        "Filter automated abuse and unsolicited submissions before they become inbox noise, while keeping reputation evidence visible and reviewable.",
        "muted"
      )
    );

    const tabs = node("div", null, "trust-tabs");
    const content = node("div", null, "trust-tab-content");

    const panes = {
      shield: node("div", null, "trust-pane"),
      rules: node("div", null, "trust-pane"),
      reputation: node("div", null, "trust-pane")
    };

    Object.values(panes).forEach(p => content.append(p));

    const activate = async id => {
      [...tabs.children].forEach(button => {
        button.classList.toggle("active", button.dataset.tab === id);
      });

      Object.entries(panes).forEach(([key, pane]) => {
        pane.hidden = key !== id;
      });

      if (id === "shield") {
        await renderEvents(panes.shield);
        await renderIntegrations(panes.shield);
      }
      if (id === "rules") await renderRules(panes.rules);
      if (id === "reputation") await renderReputation(panes.reputation);
    };

    [
      ["shield", "Form Shield"],
      ["rules", "Lists & Rules"],
      ["reputation", "Reputation"]
    ].forEach(([id, label]) => {
      const button = node("button", label, "trust-tab");
      button.type = "button";
      button.dataset.tab = id;
      button.addEventListener("click", () => activate(id));
      tabs.append(button);
    });

    root.append(header, tabs, content);
    await activate("shield");

    return root;
  };
})();
