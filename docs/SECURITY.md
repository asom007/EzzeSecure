# Security model

EzzeSecure Community v0.1.0 is a preview for self-hosted investigation. Its trust boundary includes an operator browser, a loopback control plane with local SQLite state, optional outbound providers, and an agent on a Linux host. An agent host or the control-plane machine can be compromised independently; a signed request authenticates the agent identity, not the truth of every host observation.

## Operator access and HTTP boundary

- The built-in HTTP server binds to `127.0.0.1` only. Remote exposure requires an operator-managed HTTPS reverse proxy or secure tunnel.
- The server validates `Host` and, when supplied, `Origin`. Production mode requires a configured HTTPS public origin and demo/debug disabled.
- The first owner password is randomly generated. Local demo startup prints it once; production initialization requires an exclusive owner-only bootstrap file. Passwords use scrypt hashes. The CLI can reset the password and invalidate sessions.
- Login has a per-client attempt limit. Session tokens are stored as hashes; sessions expire after eight hours. Cookies are `HttpOnly` and `SameSite=Strict`, with `Secure` set in production mode.
- Authenticated POST routes require the session CSRF token. The form integration uses its separate bearer credential, not a browser session.
- JSON request bodies are limited to 256 KiB. The service rejects unsupported transfer encoding and query parameters. Responses set cache and browser security headers.

## Agents and enrollment

- An owner creates an enrollment token valid for 600 seconds. Successful enrollment consumes it and returns a separate agent ID/secret. Community accepts one active monitored agent.
- Agents connect outbound over HTTPS, or literal loopback HTTP for a same-host evaluation. Agent credentials and optional connection settings are kept in owner-only local files.
- Telemetry requests use HMAC-SHA256 over method, path, timestamp, nonce, and body hash. The server checks a five-minute timestamp window, valid nonce format, signature, and nonce reuse. Revocation disables the agent identity.
- Real Linux agents do not fetch actions from the control plane. Community agent configuration rejects mutating command options; `LinuxAgent.execute` rejects execution. Demo actions change only project-local simulated state.

## Evidence and audit

Collectors sample bounded host evidence. Unavailable evidence is identified; a missing observation is not proof of health. Optional Black Box events carry increasing sequence numbers. The control plane hashes received events into a local chain, checks gaps and later local mutation, and can correlate these into incidents. This does **not** authenticate the source host's honesty, prove comprehensive capture, or withstand an administrator rewriting both the database and all hashes.

The control plane records security and operational audit entries. Redaction filters common credential, token, contact, payload, and private-key patterns; do not assume redaction can make arbitrary submitted personal data safe to publish. Keep state, logs, screenshots, and support bundles private.

## Integration and provider secrets

Form Shield credentials are generated per integration, stored as hashes, shown only once, and scoped to an organization. Bearer credentials belong on a website backend, never in browser code. Rule evaluation and decisions are deterministic.

Core monitoring requires no AI provider. Optional BYOK provider credentials and EzzeSend notification tokens require `cryptography` and are stored encrypted under private local vault keys. A provider receives bounded deterministic evidence selections, not raw logs or a remote-action request. SMTP authentication, if used, reads `EZZESECURE_SMTP_USERNAME` and `EZZESECURE_SMTP_PASSWORD` from the process environment rather than SQLite. Protect the host, state directory, environment, and backups; encryption at rest does not protect against a fully compromised running process.

## Safe network exposure

Keep the control-plane loopback listener behind HTTPS termination and appropriate access controls. Configure `EZZESECURE_CONTROL_PLANE_URL` to the exact public HTTPS origin in production. Ensure proxy forwarding preserves the expected Host and scheme, restrict who can reach login and enrollment routes, and monitor proxy and host security separately. Cloudflare Access is optional, not a requirement. Avoid placing state or credentials in the web document root or Git.

## Community read-only boundary

Real monitored servers support observation and authenticated telemetry only. Arbitrary shell access, service restarts, deployment actions, and WhatsApp server operations are not available in this preview. The local simulated server has demonstration actions that do not change a real host.

## Reporting a vulnerability

Please do **not** post exploit details, credentials, or customer data in a public GitHub issue. The project owner should add a private vulnerability-reporting channel to this document and the repository's GitHub security settings before soliciting public security reports. Until then, use an existing private contact channel with the maintainer if one is available.
