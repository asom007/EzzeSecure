# EzzeSecure Community

**AI Operations & Security Assistant**

EzzeSecure Community is a self-hosted Linux operations and security monitoring platform focused on evidence, investigation, alerting and explainable findings.

**Version:** v0.1.0 Community Preview

## Highlights

- Linux server monitoring
- CPU, memory, disk and load observations
- Services, applications and traffic visibility
- Incident detection and investigation
- Resource alert policies
- Black Box forensic evidence
- Security observations and audit trail
- Optional BYOK AI evidence review
- Email and optional WhatsApp notification integration
- Trust & Reputation monitoring
- DNS, TLS, MX, SPF and DMARC evidence
- Form Shield anti-spam and abuse protection
- Allowlist, Watchlist and Blocklist
- Quarantine and abuse evidence
- Scoped website integration credentials

## Security model

Real-server monitoring is read-only in this Community Preview.

EzzeSecure does not expose arbitrary remote shell access. Sensitive evidence is bounded and redacted, and integration secrets are not returned after storage.

## Requirements

- Linux
- Python 3.11+
- SQLite
- `dig` recommended for DNS/mail reputation checks
- HTTPS reverse proxy or secure tunnel for remote access

## Quick start

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .
    python -m heimdall serve --port 8787 --state-dir ./data

## Optional AI

AI is not required.

    pip install -r requirements-ai.txt

## Architecture

EzzeSecure uses a Control Plane with a lightweight authenticated Linux Agent. Available evidence depends on host permissions.

## Roadmap

Planned work includes broader environment detection, hosting adapters, WhatsApp read-only operations, and explicitly approved allowlisted remote actions with post-action verification.

## Status

Community Preview. Review your deployment and security configuration before exposing the Control Plane publicly.
