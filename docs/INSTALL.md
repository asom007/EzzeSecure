# Install EzzeSecure Community

These instructions describe the v0.1.0 source checkout. The control plane can run a local simulator for evaluation. A real monitored host needs a Linux agent and a reachable control-plane origin.

## Prerequisites

- Python 3.11+ and `venv`/`pip`.
- Linux for real agent collection. The control plane uses Python's standard library and SQLite; there is no separate database service.
- `dig` for MX, SPF, and DMARC lookups. Without it, those lookups may be unavailable.
- An HTTPS reverse proxy or secure tunnel if browsers or agents must connect from other machines.

## Install and start a local evaluation

```bash
git clone https://github.com/asom007/EzzeSecure.git
cd EzzeSecure
python3 -m venv .venv
source .venv/bin/activate
python -m heimdall serve --port 8787 --state-dir ./.local
```

The command stays in the foreground and listens on `127.0.0.1:8787`. In another terminal:

```bash
curl --fail http://127.0.0.1:8787/api/health
```

Expect `{"status":"ok"}`. Open `http://127.0.0.1:8787`.

Run the Python modules from the checkout directory. No `pip` step is required for core monitoring. The current `pyproject.toml` declares multiple top-level directories without explicit package discovery, so `pip install -e .` fails with setuptools; this preview does not provide a working installable package.

## Configuration and first login

`config/local.example.json` is a first-run template that the code reads automatically. It is **not** copied to `config/local.json`; that file is not loaded. The control plane creates `<state-dir>/config.json` and `<state-dir>/heimdall.sqlite3` with private permissions.

The example starts in `local-demo` mode with a simulated server. Its organization is `Local Operations` and username is `operator`. Change supported settings through process environment variables (or a repository-root `.env` that remains untracked) **before first initialization**. Identity values already persisted in state are not silently replaced later. Useful variables:

| Variable | Use |
| --- | --- |
| `EZZESECURE_ORGANIZATION` | First-run organization label. |
| `EZZESECURE_USERNAME` | First-run owner username. |
| `EZZESECURE_PORT` | Default listening port; `--port` also sets it. |
| `EZZESECURE_MODE` | Set to `production` for a remote, demo-free deployment. |
| `EZZESECURE_CONTROL_PLANE_URL` | Public HTTPS origin required in production. |
| `EZZESECURE_DEMO_ENABLED` | Must be false in production. |
| `EZZESECURE_DEBUG` | Must be false in production. |

On first **local-demo** startup, the CLI prints a generated username and initial password once. Sign in through the browser. Use `python -m heimdall reset-password --state-dir ./.local` to set a new password later; it prompts privately and invalidates sessions.

Production initialization is explicit and needs **new, demo-free state**. Set the production environment values, then run `python -m heimdall init --state-dir ../ezzesecure-production-state --bootstrap-file ../ezzesecure-bootstrap.json`. The bootstrap file must not already exist; the CLI writes it with owner-only permissions. Retrieve the generated credential, store it securely, and remove the transient copy using your normal secret-handling process. Start with `python -m heimdall serve --state-dir ../ezzesecure-production-state`. Keep both state and bootstrap files outside the Git checkout or in ignored locations. Production mode requires an HTTPS `EZZESECURE_CONTROL_PLANE_URL` and disables demo/debug.

## Remote access

The built-in server always binds `127.0.0.1`. Terminate HTTPS at a reverse proxy or secure tunnel on the control-plane host and forward to the loopback port. Set the public origin exactly to the browser/agent HTTPS origin; Host and Origin validation uses it. Protect the proxy and use access controls appropriate to your deployment. Cloudflare is optional. A separate Linux agent accepts HTTPS origins, or HTTP only for literal loopback addresses.

## Optional dependencies

```bash
python -m pip install -r requirements-ai.txt
```

This installs `cryptography` for optional encrypted BYOK and EzzeSend notification credentials. Core monitoring has no required third-party dependency. SMTP email uses the standard library; authenticated SMTP credentials come from `EZZESECURE_SMTP_USERNAME` and `EZZESECURE_SMTP_PASSWORD` in the control-plane process environment.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No initial password appears | Credentials print only when the first owner is created. Use `reset-password` against the same state directory. |
| Browser cannot connect | Verify the foreground process is running and use `127.0.0.1` on the same machine. Remote access needs a proxy or tunnel. |
| Production refuses to start | Use a fresh state directory without the simulated server; set the HTTPS public origin and disable demo/debug. |
| Reputation mail checks show unavailable or Not Applicable unexpectedly | Install `dig` and confirm the host can perform DNS lookups. The scanner may report Not Applicable when no mail evidence is available, including failed/unavailable lookups. |
| Agent enrollment fails | See [Agent](AGENT.md): check origin, token age, one-active-agent limit, and owner-only credential path. |

The default local demo is for evaluation. Keep production state and provider credentials private, and consult [Security](SECURITY.md) before remote exposure.
