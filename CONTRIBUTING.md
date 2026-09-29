# Contributing to EzzeSecure Community

EzzeSecure Community v0.1.0 is a preview. Useful feedback includes a reproducible bug, a missing-evidence case, confusing setup instructions, or a narrowly scoped feature proposal.

## Issues

Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) or [feature request](.github/ISSUE_TEMPLATE/feature_request.md) template. Include the EzzeSecure version, Python and Linux versions, relevant configuration **shape**, steps to reproduce, expected behavior, and what happened. Say whether the evidence came from the simulator or a real Linux agent.

Remove tokens, provider credentials, customer data, private domains, IP addresses, logs containing personal data, and screenshots showing sensitive fields. Do not post a security vulnerability publicly. See [Security](docs/SECURITY.md) for the current private-reporting status.

## Code contributions

Open a focused issue or proposal for substantial changes. Keep changes small, explain the user-visible behavior, and update documentation to match the implementation. Run available Python checks and any relevant tests; describe the commands and results in the pull request. Preserve the Community read-only boundary for real servers and avoid adding hidden dependencies or undocumented network calls.

The repository currently has [no explicit software license](docs/LICENSING.md). Do not describe it as open-source until the project owner publishes a license.
