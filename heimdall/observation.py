"""Structured observation rules; no remediation or raw configuration content."""
from pathlib import PurePath


def security_events(snapshot, baseline=None):
    events = []

    def event(kind, summary, severity="WARNING"):
        events.append({"kind": kind, "summary": summary, "severity": severity, "source": "observation_rule"})

    integrity = snapshot.get("file_integrity", {})
    if isinstance(integrity, dict) and integrity.get("available"):
        for change in integrity.get("changes", [])[:50]:
            if not isinstance(change, dict):
                continue
            path = str(change.get("path", "unknown"))
            lower = path.lower()
            kind = "environment_changed" if PurePath(path).name == ".env" else "cron_changed" if "cron" in lower else "systemd_changed" if "systemd" in lower or lower.endswith(".service") else "firewall_changed" if any(p in lower for p in ("iptables", "nftables", "ufw")) else "privilege_changed" if any(p in lower for p in ("sudoers", "/passwd", "/group", "/shadow")) else "file_integrity_changed"
            event(kind, f"Baseline observation {change.get('kind', 'changed')}: {path}. Review authorized changes; file contents were not collected.")
    if baseline:
        for field, key in (("ports", "port"), ("services", "name"), ("users", "name")):
            current, previous = snapshot.get(field), baseline.get(field)
            if not isinstance(current, list) or not isinstance(previous, list):
                continue
            allowed = {str(x.get(key)) for x in previous if isinstance(x, dict)}
            unknown = sorted({str(x.get(key)) for x in current if isinstance(x, dict)} - allowed)
            if unknown:
                event("unexpected_" + field, "Observed outside approved baseline: " + ", ".join(unknown[:20]) + ". Expected purpose requires review.")
        if snapshot.get("firewall") is not None and baseline.get("firewall") is not None and snapshot["firewall"] != baseline["firewall"]:
            event("firewall_changed", "Structured firewall observation differs from the approved baseline; no firewall action taken.")
    # Only explicit collector indicators count, not speculative process names.
    for process in snapshot.get("processes", []):
        if isinstance(process, dict) and process.get("suspicious_indicator"):
            event("suspicious_process", f"Collector reported process indicator: {process.get('name', 'unknown')}; investigate before concluding malicious activity.")
    for indicator in snapshot.get("webshell_indicators", [])[:20]:
        if isinstance(indicator, dict):
            event("webshell_indicator", f"Pattern indicator in {indicator.get('path', 'configured web root')}; a match alone does not establish a web shell.")
    return events
