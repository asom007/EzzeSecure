# Form Shield integration

Form Shield is a deterministic, server-side evaluation API for website form submissions. It returns a decision and evidence. Your website decides whether to create a ticket, lead, order inquiry, or other business record.

```text
Website form → website backend → EzzeSecure Form Shield → allow / quarantine / block
                    |
                    └── backend applies its own business workflow
```

## Create a scoped credential

Sign in as the owner. In **Trust & Reputation → Form Shield Integrations**, create a labeled credential for each website/application and save its secret when displayed. The secret is shown only at creation; the list later shows metadata, not the token. You can revoke a credential there. A credential is scoped to its EzzeSecure organization; a client-supplied `org_id` is ignored. A per-site label identifies the source of recorded events. These credentials do not grant general browser session access.

Keep the token on your website backend. Do not embed it in client-side JavaScript, HTML, a public repository, or an issue. Use HTTPS between separate machines. The control plane itself binds to loopback, so remote sites need a protected HTTPS proxy or tunnel.

## Endpoint

`POST /api/integrations/form-shield/evaluate`

Headers:

```text
Content-Type: application/json
Authorization: Bearer <form-shield-credential>
```

The endpoint accepts a JSON object with these evaluation fields:

| Field | Type | Use |
| --- | --- | --- |
| `name` | string | Sender name; cleaned and capped at 120 characters. |
| `email` | string | Sender email; cleaned, lowercased, capped at 255 characters. |
| `message` | string | Submission text; cleaned and capped at 10,000 characters. |
| `ip` | string | Source IP for an IP/network rule match; capped at 80 characters. |
| `website` | string | Optional website/link field; capped at 500 characters. |
| `elapsed_seconds` | number | Time between showing and submitting the form; values below 2 seconds add risk. |
| `honeypot` | string | Hidden field; a nonempty value adds high risk. |

The HTTP server caps the full request body at 256 KiB. The integration overwrites `source` with the credential label and ignores a supplied `org_id`.

Example from a website **backend** after retrieving its token from a private secret store:

```bash
curl --fail-with-body https://monitor.example.org/api/integrations/form-shield/evaluate \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${FORM_SHIELD_TOKEN}" \
  --data '{"name":"Example Visitor","email":"visitor@example.org","message":"I need help with a project.","elapsed_seconds":18,"honeypot":""}'
```

Do not use a real submission or credential when sharing examples. The endpoint records an abuse event even for an `allow` decision; test with synthetic data in a private environment.

Example response shape (values are illustrative):

```json
{
  "decision": "allow",
  "risk_score": 0,
  "intent": "buyer",
  "evidence": [],
  "matched_rules": [],
  "event_id": "<generated-event-id>"
}
```

`decision` is lowercase `allow`, `quarantine`, or `block`; `risk_score` is bounded to 0–100. The response can include evidence strings and matching rule metadata. The event ID lets an operator locate the review record. The response does not create a business record in your application.

## Decisions and review

The evaluator adds risk for explicit block matches, a populated honeypot, very fast submission, certain message patterns, vendor solicitation, unrelated links, recent duplicate content, and watch matches. An explicit block or score of at least 75 returns `block`; score 35–74 returns `quarantine`; lower scores return `allow`.

Your application should make its own policy for each decision. For example, create a lead only for `allow`, send `quarantine` to a private review queue, and reject `block`. If EzzeSecure is unavailable, **your application** decides whether to fail open, fail closed, or hold the submission. EzzeSecure does not make that downstream choice.

EzzeSecure records reviewable events. An operator can mark a quarantined event released or blocked in the console. That changes the event status in EzzeSecure; it does not replay the original submission to the website.

## Allowlist, Watchlist, Blocklist

An owner can add email, domain, IP/network, or text-pattern rules in **Trust & Reputation → Lists & Rules**. Rules belong to the organization; expired rules are excluded from evaluation.

| List | Effect |
| --- | --- |
| Blocklist | Matching rule forces `block` even if an allow rule also matches. |
| Watchlist | Matching rule adds 15 risk points; other evidence can raise the decision. |
| Allowlist | If no block rule and no populated honeypot match, caps the calculated score at 24. |

Allowlisting does not override a block rule or populated honeypot. Rules operate on submitted metadata, so the trustworthiness of client-provided fields, especially IP and elapsed time, is the integrating application's responsibility. Set the IP from your trusted server/request context rather than accepting a form field.

## Security considerations

Use a separate credential per website for revocation and event attribution. Store it as a server-side secret, rotate by creating a new credential and revoking the old one, and avoid logging request headers. Protect submissions under applicable privacy requirements. Form Shield stores a content fingerprint and bounded decision evidence; do not submit more personal data than needed. Review [Security](SECURITY.md) before exposing the endpoint.
