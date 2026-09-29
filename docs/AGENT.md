# Linux Agent

The Community Linux Agent collects read-only, bounded observations and sends them **outbound** to the EzzeSecure Control Plane. The control plane investigates and presents the received evidence. There is no inbound listener or remote shell in the real agent.

## Enroll a host

1. Start the [Control Plane](INSTALL.md) and sign in as owner.
2. In **Servers → Add server**, name the Linux host. The control plane creates a server record and displays a one-use token, expiry, and origin. Registration does not install anything on the host.
3. Install the same EzzeSecure checkout on the Linux host:

   ```bash
   git clone https://github.com/asom007/EzzeSecure.git
   cd EzzeSecure
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. From that checkout, run the agent. This example assumes control plane and agent share a host:

   ```bash
   python -m ezzesecure.agent --state-dir .local/agent enroll \
     --url http://127.0.0.1:8787 \
     --credentials .local/agent/credentials.json
   ```

   Enter the token at the protected terminal prompt. For a separate host, replace the URL with the configured HTTPS control-plane origin. The token is valid for 600 seconds and is consumed once. Re-enrollment revokes the prior identity. Community supports **one active monitored agent**.

5. Send the first observation:

   ```bash
   python -m ezzesecure.agent --state-dir .local/agent poll \
     --url http://127.0.0.1:8787 \
     --credentials .local/agent/credentials.json --once
   ```

   The agent returns `{"telemetry_sent":true,"results":[]}` on success. In the UI the server is **enrolled** until the first accepted snapshot, then **online** while its last heartbeat is recent (within 90 seconds).

6. For continuous polling, run the same command without `--once`. The default interval is 30 seconds; `--interval` accepts 1–3600 seconds. Run it with your own process supervisor for persistence. This checkout contains no systemd service installer or unit.

The UI may display a command using `/opt/ezzesecure-agent/agent.pyz`. That packaged artifact is not present in this repository checkout. Run the module commands above from the checkout directory; the current packaging metadata does not support `pip install -e .`.

## Authentication and local files

Enrollment returns an agent ID and secret stored in the owner-only credentials JSON. The agent signs each telemetry request with HMAC-SHA256 over method, path, timestamp, nonce, and body hash. The server checks a five-minute timestamp window and rejects reused nonces. Keep the credential file private; never paste the secret into commands, issues, or logs. Revoking a server disables its identity and stops new telemetry.

The `--url` origin is validated: remote agents must use HTTPS; only literal loopback addresses can use HTTP. For a saved private origin, use `python -m ezzesecure.agent configure --url https://monitor.example.org --connection /private/path/connection.json`, then pass `--connection` for enrollment and polling. That file must be owner-only. Optional Cloudflare Access client credentials can be entered at protected prompts with `--cloudflare-access`; they are not required.

## What the agent observes

| Source | Evidence |
| --- | --- |
| Default Linux collector | `/proc` CPU, memory, load, uptime, network and disk I/O counters; filesystem usage; bounded process sample and listening/bound ports. CPU percentage and rates require two samples. |
| Optional `systemd` config | Status of explicitly listed units via `systemctl`. |
| Optional `laravel` config | Laravel file presence and an explicitly supplied, recent health JSON file; optional integrity comparisons. It does not infer queue or database health without probe evidence. |
| Optional `logs` config | Bounded web access and auth log tails summarized into traffic/security observations. |
| Optional `sites` config | Read-only discovery from configured nginx/Apache paths and bounded traffic attribution from configured logs. |
| Optional `integrity_files` | Comparison against an operator-created file hash baseline. |
| Optional `black_box` | Sampled auth activity, selected file changes, process and network events, with a bounded private outbox. |

Without optional config, service, application, site, and log-derived traffic fields are unavailable rather than healthy. Host permissions and namespaces determine what the collector can see. To inspect a single local snapshot, run `python -m ezzesecure.agent collect` on Linux; it does not enroll or transmit.

A trusted local JSON file can be passed with `--config /absolute/path/agent-config.json` before the subcommand. For example:

```json
{
  "systemd": {"units": ["nginx.service"]},
  "logs": {"access": "/var/log/nginx/access.log", "auth": "/var/log/auth.log"},
  "black_box": {"enabled": true, "auth_log": "/var/log/auth.log"}
}
```

Only configure paths the agent account may read. Black Box and file integrity need deliberate scope and review of the initial baseline. The agent rejects `commands`, `systemd.allow_restart`, and `laravel.allow_actions` in Community mode. Its transport sends telemetry only and does not fetch pending actions.

## Black Box integrity limits

The agent retains at most 1,000 pending Black Box events and sends bounded batches. The control plane checks increasing sequences and stores an event hash chain; it can detect a receipt gap or subsequent local alteration. The first scan does not invent historical events. These checks cannot prove the source host told the truth or replace a complete audit system.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Enrollment rejected | Token may be older than 10 minutes, consumed, or another active agent may exist. Re-enroll/revoke in the UI and retry with a new token. |
| Credential file error | Use a new path under a private, owner-controlled directory. Enrollment deliberately refuses to overwrite an identity. |
| Agent is enrolled but not online | Run `poll --once`; verify origin, network reachability, and host clock. |
| Some fields unavailable | Check Linux `/proc`, file permissions, optional config paths, and whether two samples have been collected. |
| Black Box gap | Inspect the incident timeline and collector status; long offline periods can exceed the bounded outbox. |

See [Security](SECURITY.md) for network and secret-handling guidance.
