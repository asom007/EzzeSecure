"""Authentication primitives. Secrets never belong in audit or browser metadata."""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    key = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32)
    return salt + ":" + key.hex()


def password_matches(password: str, encoded: str) -> bool:
    try:
        return hmac.compare_digest(password_hash(password, encoded.split(":")[0]), encoded)
    except (ValueError, TypeError):
        return False


def signature(secret: str, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    canonical = "\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest()))
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


SENSITIVE_KEYS = re.compile(r"password|passwd|secret|token|authorization|cookie|api.?key|otp|confirmation.?code|^code$|credential|private.?key|payload|exception|customer|phone|email|message.?body|dsn|connection.?string|config.?line|^\.env$", re.I)


def redact(value):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if SENSITIVE_KEYS.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value[:100]]
    if isinstance(value, str):
        value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", value)
        value = re.sub(r'''(?i)(["'](?:password|passwd|secret|token|api[_-]?key)["']\s*:\s*)(["'])(.*?)(\2)''', r'\1\2[REDACTED]\2', value)
        value = re.sub(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", value)
        value = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", value)
        value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*", "[REDACTED PRIVATE KEY]", value, flags=re.S)
        value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED EMAIL]", value, flags=re.I)
        return value[:4000]
    return value


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def issue_headers(secret: str, agent_id: str, method: str, path: str, body: bytes = b"") -> dict:
    timestamp, nonce = str(int(time.time())), secrets.token_hex(16)
    return {"X-Agent-ID": agent_id, "X-Agent-Timestamp": timestamp, "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature(secret, method, path, timestamp, nonce, body)}
