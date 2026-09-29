# EzzeSecure

### AI Operations & Security Assistant for Linux Servers

**Self-hosted Linux server monitoring, security investigation, incident analysis, infrastructure visibility, domain reputation, and abuse protection — built around evidence, not noise.**

**EzzeSecure Community v0.1.0 — Community Preview**

`Self-Hosted` · `Linux Server Monitoring` · `Security Monitoring` · `DevOps` · `SRE` · `Incident Investigation` · `Root Cause Analysis` · `Infrastructure Monitoring` · `Python 3.11+`

---

## Why EzzeSecure?

Most monitoring tools can tell you that CPU is high, memory is running low, or a service stopped. EzzeSecure is designed around the harder questions: **What happened? Why did it happen? What evidence supports the finding? What should be investigated next?**

EzzeSecure combines operational telemetry, security observations, incidents, forensic evidence, reputation checks, and optional AI-assisted analysis in one investigation-oriented workspace.

**Observe → Understand → Investigate → Explain → Alert → Recommend**

Real-server monitoring in the Community Preview is read-only.

---

## Highlights

- Linux VPS, cloud and dedicated server monitoring
- CPU, RAM, disk, load and capacity evidence
- Service and application health
- Traffic and network observations
- Incident detection and investigation
- Evidence timelines and Black Box forensic streams
- Resource policies and alert escalation
- Security observations and audit history
- Trust & Reputation monitoring
- DNS, TLS, MX, SPF and DMARC evidence
- Form Shield anti-spam and abuse protection
- Allowlist, Watchlist and Blocklist
- Quarantine and abuse evidence
- Scoped per-site integration credentials
- Optional BYOK AI evidence review

---

## Screenshots

Real product screenshots are being prepared for the repository. Planned views include:

- Overview dashboard
- Server details and health
- Incident investigation
- Security evidence
- Trust & Reputation
- Form Shield

Suggested repository paths:

```text
docs/images/overview.png
docs/images/server-detail.png
docs/images/incidents.png
docs/images/trust-reputation.png
```

---

## Server Health & Infrastructure Monitoring

EzzeSecure provides a unified view of Linux infrastructure and collected evidence, including CPU utilization, memory usage, disk utilization, system load, service state, application health, network observations, traffic behavior, capacity signals, availability, and agent heartbeat continuity.

It is designed for operators who need self-hosted server monitoring without deploying a large observability stack.

---

## Incident Investigation & Root Cause Analysis

EzzeSecure is built to move beyond isolated threshold alerts. It correlates observations into incidents and preserves investigation context so operators can inspect what was observed, when it started, how conditions changed, which evidence contributed to the finding, and whether the condition escalated or recovered.

The goal is not another alert feed. The goal is faster, evidence-based investigation.

---

## Black Box Forensic Evidence

Connected agents can maintain bounded, sequence-aware forensic evidence. EzzeSecure uses this evidence to preserve useful context around operational and security events and to detect evidence gaps.

This creates a stronger foundation for incident investigation than disconnected alerts alone.

---

## Traffic & Security Visibility

Depending on the evidence available from the monitored host, EzzeSecure can surface:

- unusual traffic behavior
- authentication-related observations
- source concentration
- HTTP error behavior
- network changes
- security events
- evidence gaps
- canary activity

EzzeSecure reports what the available evidence supports and identifies limitations when evidence is incomplete.

---

## Trust & Reputation

The Trust & Reputation workspace helps infrastructure and website operators inspect observable configuration and trust signals.

### Domain and email evidence

EzzeSecure can inspect:

- DNS resolution
- TLS certificate health
- MX records
- SPF records
- DMARC policy
- whether email checks are applicable to the domain

EzzeSecure reports individual findings rather than inventing a universal reputation score.

---

## Form Shield — Anti-Spam & Abuse Protection

Public forms often become targets for automated submissions, generated garbage, SEO solicitations, suspicious links, duplicate messages, and unwanted vendor outreach.

Form Shield provides a deterministic abuse-evaluation layer that can sit in front of website workflows.

A website sends bounded submission metadata and receives one of three decisions:

```text
ALLOW
QUARANTINE
BLOCK
```

This allows an application to stop unwanted submissions **before** they become support tickets, CRM records, inbox messages, or notifications.

Form Shield supports scoped website credentials, allowlists, watchlists, blocklists, quarantine, duplicate-content signals, suspicious-link signals, solicitation detection, buyer-versus-vendor intent signals, and bounded risk scoring.

---

## Optional AI / BYOK

AI is optional. Core monitoring and deterministic analysis do not require an external AI service.

Operators who want additional evidence interpretation can configure their own supported provider credentials.

```bash
pip install -r requirements-ai.txt
```

The monitoring foundation remains useful without AI.

---

## Architecture

EzzeSecure uses a Control Plane plus a lightweight authenticated Linux Agent.

```text
┌─────────────────────────┐
│   EzzeSecure Console    │
│      Control Plane      │
└────────────┬────────────┘
             │
    authenticated telemetry
             │
┌────────────▼────────────┐
│   EzzeSecure Agent      │
│      Linux Server       │
└─────────────────────────┘
```

The agent collects bounded operational and security evidence. The Control Plane stores, correlates, investigates, explains, and presents that evidence.

---

## Security Model

EzzeSecure Community is intentionally conservative with server access.

The Community Preview focuses on observation, investigation, explanation, alerting, and recommendations. It does **not** expose arbitrary remote shell access to real servers.

The architecture includes authenticated agents, enrollment tokens, scoped identities, session protection, CSRF protection, nonce/replay protection, bounded request bodies, audit history, secret redaction, and scoped integration credentials.

---

## Quick Start

### Requirements

- Linux
- Python 3.11+
- SQLite
- `dig` recommended for DNS and mail reputation checks
- HTTPS reverse proxy or secure tunnel recommended for remote access

### 1. Clone EzzeSecure

```bash
git clone https://github.com/asom007/EzzeSecure.git
cd EzzeSecure
```

### 2. Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install

```bash
pip install -e .
```

### 4. Prepare local configuration

```bash
cp config/local.example.json config/local.json
```

Review the local configuration before exposing the Control Plane.

### 5. Start EzzeSecure

```bash
python -m heimdall serve --port 8787 --state-dir ./data
```

Keep the Control Plane behind an appropriate secure access layer when remote access is required.

---

## Add Your First Linux Server

The general enrollment workflow is:

```text
Start the Control Plane
        ↓
Sign in to EzzeSecure
        ↓
Add a server
        ↓
Generate an enrollment token
        ↓
Install/start the EzzeSecure Agent
        ↓
Enroll the agent
        ↓
Wait for the first authenticated heartbeat
        ↓
Inspect server evidence
```

Available evidence depends on host permissions. VPS and dedicated Linux environments generally provide broader infrastructure visibility than restricted shared hosting.

---

## Community Preview Capabilities

| Area | Capability |
| --- | --- |
| Infrastructure | Linux server monitoring |
| Resources | CPU, RAM, disk, load and capacity evidence |
| Services | Service and application observations |
| Network | Traffic and network evidence |
| Security | Security observations and incident correlation |
| Investigation | Incident timeline and supporting evidence |
| Forensics | Black Box evidence streams |
| Alerts | Resource policies and notification routing |
| Reputation | DNS, TLS, MX, SPF and DMARC |
| Abuse Protection | Form Shield |
| Trust Controls | Allowlist, Watchlist and Blocklist |
| AI | Optional BYOK evidence review |
| Audit | Recorded operational and security history |

---

## Designed For

EzzeSecure may be useful for Linux server administrators, DevOps engineers, SRE teams, cybersecurity teams, MSPs, hosting providers, SaaS operators, agencies managing client infrastructure, and self-hosted application operators.

---

## Community Edition Philosophy

EzzeSecure Community is designed to remain useful on its own. It does not require a commercial license, mandatory registration, EzzeSend, EzzeMedia services, or a mandatory AI provider.

Optional integrations can extend the platform while the monitoring foundation remains self-hosted.

---

## What EzzeSecure Is Not

EzzeSecure Community Preview is not an unrestricted remote shell, a replacement for backups, endpoint protection, or a guarantee that every incident can be detected from limited evidence.

It is an operations and security investigation layer built around the evidence available from connected infrastructure.

---

## Roadmap

Planned areas include:

- broader environment auto-detection
- additional Linux and hosting/control-panel adapters
- expanded website and application observations
- richer reputation evidence
- WhatsApp read-only server operations
- natural-language infrastructure queries
- secure allowlisted remote actions
- explicit action approval
- post-action verification
- expanded incident investigation workflows

The planned approved-action lifecycle is:

```text
Request
→ Assess
→ Recommend
→ Explicit Approval
→ Execute Allowlisted Action
→ Verify
→ Report
```

Arbitrary shell execution is not the design goal.

---

## Community Preview

EzzeSecure `v0.1.0` is an early Community Preview intended for testing, technical evaluation, and feedback.

Do not treat preview software as your only monitoring or security control. Test deployment and access configuration carefully before exposing the Control Plane outside a trusted environment.

---

## Discoverability

Linux Server Monitoring · Self-Hosted Monitoring · AI Server Monitoring · Infrastructure Monitoring · Security Monitoring · DevOps · SRE · Incident Investigation · Root Cause Analysis · Server Health Monitoring · VPS Monitoring · Cybersecurity · Domain Reputation · SPF · DMARC · Anti-Spam · Form Protection · Website Security · Self-Hosted Infrastructure

---

## Project

**EzzeSecure — AI Operations & Security Assistant**

Developed by **EzzeMedia**.

If EzzeSecure is useful to you, follow the project, test the Community Preview, and share technical feedback.
