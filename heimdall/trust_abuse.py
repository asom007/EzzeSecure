"""Deterministic trust, abuse and reputation controls for EzzeSecure Community."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from urllib.parse import urlsplit
from .security import digest

KINDS = {"email", "domain", "ip", "pattern"}
LISTS = {"allow", "watch", "block"}
DECISIONS = {"allow", "quarantine", "block"}

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)
WORD_RE = re.compile(r"[A-Za-z0-9]{2,}")

SOLICITATION = (
    "we offer", "we provide", "our services", "our service",
    "we can improve", "we can help you", "would you be interested",
    "would you like me to send", "would you like us to",
    "seo services", "seo service", "marketing services",
    "video services", "web design services", "link building",
    "rank your website", "rank higher", "google rankings",
    "free seo audit", "free audit", "our pricing", "our prices",
    "send you our", "i can help you", "we help businesses",
    "boost your website", "improve your visibility",
)

INDEXING_SPAM = (
    "search index",
    "include your website",
    "include your site",
    "list your website",
    "list your site",
    "submit your website",
    "submit your site",
    "add your website",
    "add your site",
    "displayed in google search",
)

BUYER_SIGNALS = (
    "i need", "we need", "i want", "we want",
    "looking for", "interested in your", "how much",
    "pricing", "can you build", "can you integrate",
    "can ezzesecure", "can you help us",
)


def _clean(value, limit=500):
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())[:limit]


def _domain(value):
    value = _clean(value, 255).lower().rstrip(".")
    if "://" in value:
        value = (urlsplit(value).hostname or "").lower().rstrip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value


def _valid(kind, value):
    if kind == "email":
        return bool(re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}", value))
    if kind == "domain":
        return bool(value and len(value) <= 253 and "." in value and
                    re.fullmatch(r"[a-z0-9.-]+", value))
    if kind == "ip":
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    if kind == "pattern":
        return 1 <= len(value) <= 200
    return False


class TrustAbuse:
    def __init__(self, store):
        self.store = store

    def credentials(self, org):
        return self.store.rows(
            "SELECT id,label,enabled,created_at,last_used_at,revoked_at "
            "FROM form_shield_credentials WHERE org_id=? "
            "ORDER BY created_at DESC",
            (org,),
        )

    def create_credential(self, org, label):
        label = _clean(label, 80)
        if not label:
            raise ValueError("Enter a short integration label.")

        credential_id = uuid.uuid4().hex
        secret = "ezfs_" + secrets.token_urlsafe(32)
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self.store.tx() as db:
            db.execute(
                "INSERT INTO form_shield_credentials("
                "id,org_id,label,token_hash,enabled,created_at"
                ") VALUES(?,?,?,?,1,?)",
                (
                    credential_id,
                    org,
                    label,
                    digest(secret),
                    created,
                ),
            )

        return {
            "id": credential_id,
            "label": label,
            "secret": secret,
            "created_at": created,
        }

    def revoke_credential(self, org, credential_id):
        if not isinstance(credential_id, str) or not credential_id:
            raise ValueError("Credential id is required.")

        revoked = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self.store.tx() as db:
            row = db.execute(
                "SELECT id FROM form_shield_credentials "
                "WHERE id=? AND org_id=? AND enabled=1",
                (credential_id, org),
            ).fetchone()

            if not row:
                raise ValueError("Active credential not found.")

            db.execute(
                "UPDATE form_shield_credentials "
                "SET enabled=0,revoked_at=? "
                "WHERE id=? AND org_id=?",
                (revoked, credential_id, org),
            )

    def authenticate_credential(self, secret):
        if (
            not isinstance(secret, str)
            or not secret.startswith("ezfs_")
            or len(secret) < 40
            or len(secret) > 100
        ):
            return None

        row = self.store.one(
            "SELECT id,org_id,label FROM form_shield_credentials "
            "WHERE token_hash=? AND enabled=1 AND revoked_at IS NULL",
            (digest(secret),),
        )

        if not row:
            return None

        used = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        with self.store.tx() as db:
            db.execute(
                "UPDATE form_shield_credentials SET last_used_at=? "
                "WHERE id=?",
                (used, row["id"]),
            )

        return row

    def rules(self, org):
        return self.store.rows(
            "SELECT id,list_type,kind,value,reason,enabled,created_at,expires_at "
            "FROM trust_rules WHERE org_id=? ORDER BY list_type,kind,value",
            (org,),
        )

    def add_rule(self, org, list_type, kind, value, reason="", expires_at=None):
        if list_type not in LISTS or kind not in KINDS:
            raise ValueError("Choose a supported list and indicator type.")
        value = _clean(value, 255).lower()
        if kind == "domain":
            value = _domain(value)
        if not _valid(kind, value):
            raise ValueError("Enter a valid email, domain, IP/network or pattern.")
        reason = _clean(reason, 300)
        if expires_at is not None and not isinstance(expires_at, (int, float)):
            raise ValueError("Invalid rule expiry.")
        rid = uuid.uuid4().hex
        with self.store.tx() as db:
            db.execute(
                "INSERT INTO trust_rules(id,org_id,list_type,kind,value,reason,enabled,"
                "created_at,expires_at) VALUES(?,?,?,?,?,?,1,?,?)",
                (rid, org, list_type, kind, value, reason,
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 expires_at),
            )
        return rid

    def remove_rule(self, org, rid):
        with self.store.tx() as db:
            row = db.execute(
                "SELECT id FROM trust_rules WHERE id=? AND org_id=?", (rid, org)
            ).fetchone()
            if not row:
                raise ValueError("Rule not found.")
            db.execute("DELETE FROM trust_rules WHERE id=? AND org_id=?", (rid, org))

    def _matching_rules(self, org, email, ip, text, urls):
        now = time.time()
        rules = self.store.rows(
            "SELECT * FROM trust_rules WHERE org_id=? AND enabled=1 "
            "AND (expires_at IS NULL OR expires_at>?)",
            (org, now),
        )
        domains = {_domain(email)}
        domains.update(_domain(url) for url in urls)
        domains.discard("")
        matches = []
        for rule in rules:
            kind, value = rule["kind"], rule["value"]
            hit = False
            if kind == "email":
                hit = email.lower() == value
            elif kind == "domain":
                hit = any(d == value or d.endswith("." + value) for d in domains)
            elif kind == "ip":
                try:
                    hit = bool(ip) and ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
                except ValueError:
                    hit = False
            elif kind == "pattern":
                hit = value.lower() in text.lower()
            if hit:
                matches.append(rule)
        return matches

    def evaluate(self, org, submission):
        if not isinstance(submission, dict):
            raise ValueError("Submission must be an object.")

        name = _clean(submission.get("name"), 120)
        email = _clean(submission.get("email"), 255).lower()
        message = _clean(submission.get("message"), 10000)
        ip = _clean(submission.get("ip"), 80)
        website = _clean(submission.get("website"), 500)
        elapsed = submission.get("elapsed_seconds")
        honeypot = _clean(submission.get("honeypot"), 200)

        combined = " ".join((name, email, website, message))
        lower = combined.lower()
        urls = URL_RE.findall(combined)
        if website:
            urls.append(website)

        matches = self._matching_rules(org, email, ip, combined, urls)
        blocked = [r for r in matches if r["list_type"] == "block"]
        allowed = [r for r in matches if r["list_type"] == "allow"]
        watched = [r for r in matches if r["list_type"] == "watch"]

        evidence = []
        score = 0

        if blocked:
            evidence.append("Matched an operator block rule.")
            score = 100

        if honeypot:
            evidence.append("Hidden form field was populated.")
            score += 80

        if isinstance(elapsed, (int, float)) and elapsed >= 0 and elapsed < 2:
            evidence.append("Form was submitted unusually quickly.")
            score += 45

        words = WORD_RE.findall(message)
        if message and len(message) >= 12:
            alpha = sum(ch.isalpha() for ch in message)
            spaces = max(1, sum(ch.isspace() for ch in message))
            if len(words) <= 2 and alpha > 8:
                evidence.append("Message resembles generated or nonsensical input.")
                score += 45
            elif spaces == 1 and len(message) > 60:
                evidence.append("Message structure is unusual.")
                score += 15

        solicitation_hits = [term for term in SOLICITATION if term in lower]
        indexing_hits = [term for term in INDEXING_SPAM if term in lower]
        buyer_hits = [term for term in BUYER_SIGNALS if term in lower]

        explicit_seller = any(term in lower for term in (
            "we offer",
            "we provide",
            "our services",
            "our service",
            "we help businesses",
            "i can help you",
            "we can improve",
            "would you be interested",
            "would you like me to send",
            "would you like us to",
        ))

        explicit_buyer = any(term in lower for term in (
            "i need",
            "we need",
            "i want",
            "we want",
            "looking for",
            "interested in your",
            "can you provide",
            "can you build",
            "can you integrate",
            "can you help us",
        ))

        seller_directed = explicit_seller or (
            bool(solicitation_hits) and not explicit_buyer
        )

        if seller_directed:
            evidence.append("Message appears to offer services rather than request them.")
            score += min(70, 40 + 10 * len(solicitation_hits))

        if indexing_hits:
            evidence.append("Message resembles unsolicited search-index or website-submission promotion.")
            score += min(70, 45 + 10 * len(indexing_hits))

        suspicious_urls = []
        for url in urls:
            host = _domain(url)
            if host and email and host != _domain(email) and not host.endswith("." + _domain(email)):
                suspicious_urls.append(host)
        if suspicious_urls:
            evidence.append("Submission contains external links unrelated to the sender email domain.")
            score += min(30, 10 * len(set(suspicious_urls)))

        fingerprint_source = "|".join((email, message.lower(), website.lower()))
        fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()
        recent = self.store.one(
            "SELECT COUNT(*) AS n FROM abuse_events WHERE org_id=? AND fingerprint=? "
            "AND created_epoch>?",
            (org, fingerprint, time.time() - 86400),
        )
        duplicate_count = int(recent["n"]) if recent else 0
        if duplicate_count:
            evidence.append("Equivalent content was submitted recently.")
            score += min(50, duplicate_count * 20)

        if watched:
            evidence.append("Matched an operator watch rule.")
            score += 15

        # Allowlisting suppresses content/reputation noise, never explicit block rules,
        # honeypot abuse or high-risk automation signals.
        if allowed and not blocked and not honeypot:
            score = min(score, 24)
            evidence.append("Matched an operator allow rule.")

        score = max(0, min(100, score))
        if blocked or score >= 75:
            decision = "block"
        elif score >= 35:
            decision = "quarantine"
        else:
            decision = "allow"

        intent = "unknown"
        if indexing_hits:
            intent = "spam"
        elif seller_directed:
            intent = "vendor_offer"
        elif explicit_buyer or buyer_hits:
            intent = "buyer"
        elif honeypot or score >= 75:
            intent = "spam"

        result = {
            "decision": decision,
            "risk_score": score,
            "intent": intent,
            "evidence": evidence[:12],
            "matched_rules": [
                {"id": r["id"], "list": r["list_type"], "kind": r["kind"], "value": r["value"]}
                for r in matches[:12]
            ],
        }

        eid = uuid.uuid4().hex
        with self.store.tx() as db:
            db.execute(
                "INSERT INTO abuse_events(id,org_id,created_at,created_epoch,source,"
                "decision,risk_score,intent,fingerprint,evidence,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    eid, org,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    time.time(), _clean(submission.get("source"), 100) or "form",
                    decision, score, intent, fingerprint,
                    json.dumps(result, separators=(",", ":")),
                    "quarantined" if decision == "quarantine" else decision,
                ),
            )
        result["event_id"] = eid
        return result

    def events(self, org, limit=100):
        rows = self.store.rows(
            "SELECT id,created_at,source,decision,risk_score,intent,status,evidence "
            "FROM abuse_events WHERE org_id=? ORDER BY created_epoch DESC LIMIT ?",
            (org, max(1, min(int(limit), 200))),
        )
        for row in rows:
            try:
                detail = json.loads(row.pop("evidence"))
                row["evidence"] = detail.get("evidence", [])
                row["matched_rules"] = detail.get("matched_rules", [])
            except (ValueError, TypeError):
                row["evidence"] = []
                row["matched_rules"] = []
        return rows

    def quarantine_action(self, org, event_id, action):
        if action not in {"release", "block"}:
            raise ValueError("Choose release or block.")
        with self.store.tx() as db:
            row = db.execute(
                "SELECT id,status FROM abuse_events WHERE id=? AND org_id=?",
                (event_id, org),
            ).fetchone()
            if not row:
                raise ValueError("Abuse event not found.")
            db.execute(
                "UPDATE abuse_events SET status=? WHERE id=? AND org_id=?",
                ("released" if action == "release" else "blocked", event_id, org),
            )

    def reputation(self, org):
        findings = self.store.rows(
            "SELECT id,domain,kind,status,summary,observed_at,evidence "
            "FROM reputation_findings WHERE org_id=? ORDER BY observed_epoch DESC LIMIT 100",
            (org,),
        )
        for item in findings:
            try:
                item["evidence"] = json.loads(item["evidence"])
            except (ValueError, TypeError):
                item["evidence"] = {}
        return findings

    def record_reputation(self, org, domain, kind, status, summary, evidence=None):
        domain = _domain(domain)
        if not _valid("domain", domain):
            raise ValueError("Enter a valid domain.")
        kind = _clean(kind, 40).lower()
        status = _clean(status, 30).lower()
        if kind not in {"dns", "mx", "spf", "dkim", "dmarc", "tls", "blocklist", "mail"}:
            raise ValueError("Unsupported reputation evidence type.")
        if status not in {"healthy", "attention", "critical", "unknown", "not_applicable"}:
            raise ValueError("Unsupported reputation status.")
        rid = uuid.uuid4().hex
        with self.store.tx() as db:
            db.execute(
                "INSERT INTO reputation_findings(id,org_id,domain,kind,status,summary,"
                "observed_at,observed_epoch,evidence) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    rid, org, domain, kind, status, _clean(summary, 500),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    time.time(),
                    json.dumps(evidence or {}, separators=(",", ":")),
                ),
            )
        return rid
