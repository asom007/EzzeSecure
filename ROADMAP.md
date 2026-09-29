# EzzeSecure Roadmap

Roadmap is directional and may change based on Community feedback, technical validation, and security review.

Items under planned releases and future exploration are not currently available. No release dates are promised.

## v0.1.0 — Community Preview

**Released / completed.** The Community Preview established:

- Read-only Linux server monitoring with resource, service, and traffic evidence.
- Incident investigation and optional Black Box forensic evidence.
- Resource policies and notifications.
- Optional bring-your-own-key (BYOK) AI evidence review.
- Trust & Reputation checks with DNS, TLS, MX, SPF, and DMARC evidence.
- Form Shield with Allowlist, Watchlist, Blocklist, and Quarantine workflows.
- Scoped website integration credentials.
- Documentation and product screenshots.

## v0.2.0 — Intelligent Watchdog

**Planned.** This release focuses on safe visibility and investigation, without modifying servers:

- A WhatsApp entry point using `server` / `سيرفر` that identifies the authorized user from their verified WhatsApp identity, discovers only servers that identity may access, and offers interactive server selection.
- A selected server's health summary: CPU, RAM, disk, load, uptime, service and application status, traffic, incident and security summaries, and Form Shield statistics.
- Domain reputation queries and natural-language infrastructure questions, including evidence-supported investigation questions such as “Why is this server under load?”
- Better environment auto-detection, broader multi-server support, and hosting/control-panel adapters where technically appropriate.

**WhatsApp operations in v0.2.0 are planned as read-only.**

## v0.3.0 — Secure Remote Operations

**Planned.** Controlled server actions would follow this lifecycle:

Request → Assess → Recommend → Explicit Approval → Execute Allowlisted Action → Verify → Report

Potential actions include restarting an approved service, rebooting an approved server, clearing approved caches, certificate renewal workflows, and blocking an IP through an approved policy.

Security principles for these planned actions:

- No arbitrary shell from WhatsApp; allowlisted actions only.
- Explicit confirmation with one-time, expiring approvals bound to the identity, server, and exact action.
- Role-based access control (RBAC) and authorization.
- Full audit history, post-action verification, and results reported back to the operator.

## Engineering priorities

These priorities have no promised release dates:

- Fix Python packaging so standard installation is cleaner.
- Broaden environment detection.
- Improve multi-agent and multi-server architecture beyond current preview limitations.
- Decide and publish an explicit software license.
- Expand automated testing.
- Improve deployment and service documentation.
- Expand reputation evidence safely.

## Future exploration

- Richer infrastructure integrations.
- Additional notification and interaction channels.
- Deeper investigation workflows.
- Broader application observability.
- Additional reputation evidence providers.
