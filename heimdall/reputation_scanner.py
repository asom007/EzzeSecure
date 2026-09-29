"""Bounded domain and email reputation evidence collection."""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)


def normalize_domain(value):
    if not isinstance(value, str):
        raise ValueError("Enter a valid domain.")
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a valid domain name.")
    return domain


def _public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _dig(record_type, name):
    binary = shutil.which("dig")
    if not binary:
        return None

    try:
        result = subprocess.run(
            [binary, "+short", "+time=2", "+tries=1", record_type, name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return []

    return [
        line.strip().strip('"')
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def _resolve(domain):
    addresses = set()
    try:
        for item in socket.getaddrinfo(
            domain,
            443,
            type=socket.SOCK_STREAM,
        ):
            address = item[4][0]
            if _public_ip(address):
                addresses.add(address)
    except socket.gaierror:
        pass
    return sorted(addresses)


def _tls(domain):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                cert = tls.getpeercert()

        expires_raw = cert.get("notAfter")
        expires = None

        if expires_raw:
            expires = datetime.strptime(
                expires_raw,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

        days = (
            (expires - datetime.now(timezone.utc)).days
            if expires
            else None
        )

        status = "healthy"
        summary = "TLS certificate validated successfully."

        if days is not None and days < 0:
            status = "critical"
            summary = "TLS certificate is expired."
        elif days is not None and days < 14:
            status = "attention"
            summary = f"TLS certificate expires in {days} days."

        return {
            "status": status,
            "summary": summary,
            "evidence": {
                "expires_at": expires.isoformat() if expires else None,
                "days_remaining": days,
                "issuer": cert.get("issuer"),
            },
        }

    except (OSError, ssl.SSLError, ValueError):
        return {
            "status": "attention",
            "summary": "A trusted HTTPS certificate could not be verified.",
            "evidence": {},
        }


class ReputationScanner:
    def scan(self, domain):
        domain = normalize_domain(domain)

        findings = []

        addresses = _resolve(domain)
        findings.append({
            "kind": "dns",
            "status": "healthy" if addresses else "critical",
            "summary": (
                "Domain resolves to public network addresses."
                if addresses
                else "Domain did not resolve to a public network address."
            ),
            "evidence": {"addresses": addresses},
        })

        tls = _tls(domain)
        findings.append({
            "kind": "tls",
            **tls,
        })

        mx = _dig("MX", domain)
        txt = _dig("TXT", domain)
        dmarc = _dig("TXT", "_dmarc." + domain)

        spf = []
        if txt is not None:
            spf = [
                value
                for value in txt
                if "v=spf1" in value.lower()
            ]

        dmarc_records = []
        if dmarc is not None:
            dmarc_records = [
                value
                for value in dmarc
                if "v=dmarc1" in value.lower()
            ]

        # Absence of MX alone does not prove email is unused.
        mail_detected = bool(mx or spf or dmarc_records)

        if mx is None:
            findings.append({
                "kind": "mx",
                "status": "unknown",
                "summary": "MX lookup is unavailable on this host.",
                "evidence": {},
            })
        elif mx:
            findings.append({
                "kind": "mx",
                "status": "healthy",
                "summary": "Mail exchange records were detected.",
                "evidence": {"records": mx},
            })
        else:
            findings.append({
                "kind": "mx",
                "status": "unknown" if mail_detected else "healthy",
                "summary": (
                    "No MX record was found; other mail configuration exists."
                    if mail_detected
                    else "No inbound mail service was detected. Email checks may not apply."
                ),
                "evidence": {"mail_service_detected": mail_detected},
            })

        if not mail_detected:
            findings.append({
                "kind": "mail",
                "status": "not_applicable",
                "summary": "No evidence of domain email service was detected; email reputation checks are not applicable.",
                "evidence": {"applicable": False},
            })
        else:
            findings.append({
                "kind": "spf",
                "status": "healthy" if spf else "attention",
                "summary": (
                    "SPF record detected."
                    if spf
                    else "Mail service is detected but no SPF record was found."
                ),
                "evidence": {"records": spf},
            })

            if dmarc_records:
                record = " ".join(dmarc_records).lower()
                policy = "none"
                match = re.search(r"(?:^|;)\s*p\s*=\s*([^;\s]+)", record)
                if match:
                    policy = match.group(1)

                status = (
                    "healthy"
                    if policy in {"quarantine", "reject"}
                    else "attention"
                )

                findings.append({
                    "kind": "dmarc",
                    "status": status,
                    "summary": f"DMARC policy detected: p={policy}.",
                    "evidence": {
                        "records": dmarc_records,
                        "policy": policy,
                    },
                })
            else:
                findings.append({
                    "kind": "dmarc",
                    "status": "attention",
                    "summary": "Mail service is detected but no DMARC record was found.",
                    "evidence": {"records": []},
                })

        return {
            "domain": domain,
            "mail_service_detected": mail_detected,
            "findings": findings,
        }
