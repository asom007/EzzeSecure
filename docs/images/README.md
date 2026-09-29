# Screenshot plan

No screenshots are published yet. Capture the actual Community v0.1.0 UI, verify that each image reflects implemented functionality, and review every visible field before adding PNGs here.

| File | Recommended page | Show | Redact before publishing | Crop |
| --- | --- | --- | --- | --- |
| `overview.png` | Overview | Server selector, status, summary cards, and recent evidence. | Hostnames, server IDs, addresses, user names, timestamps if identifying, provider details. | Wide 16:9 or 3:2 desktop crop; include page title and main cards. |
| `server-detail.png` | Servers → selected server | Online state, resource chart, and configured service or site evidence. | Agent/server IDs, hostnames, paths, domains, addresses, process details that identify a customer. | Wide 16:9; show one complete evidence group. |
| `incidents.png` | Incidents | One incident, severity, first/last observation, timeline, and evidence context. | Host/customer identifiers, log-derived content, paths, IPs, canary URLs. | Wide 16:9 or 3:2; keep timeline labels readable. |
| `trust-reputation.png` | Trust & Reputation | A domain scan with DNS/TLS/MX/SPF/DMARC findings and mail applicability. | Private domains, account labels, integration credential values, email addresses, IPs. | Wide 16:9; focus on findings rather than empty space. |

Use a demo or explicitly approved test environment. Never capture a displayed one-time enrollment token, Form Shield credential, BYOK key, or production customer data. Once real PNGs exist, replace the README's text-only screenshot table with image references.
