"""Small, explicit local configuration loader. Does not execute .env content."""
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

FIELDS = {
    "EZZESECURE_ORGANIZATION": "organization",
    "EZZESECURE_USERNAME": "username",
    "EZZESECURE_DEMO_OWNER_PHONE": "owner_phone",
    "EZZESECURE_DAILY_BRIEF_HOUR_UTC": "daily_brief_hour_utc",
    "EZZESECURE_PORT": "port",
    "EZZESECURE_MODE": "mode",
    "EZZESECURE_CONTROL_PLANE_URL": "control_plane_url",
    "EZZESECURE_DEMO_ENABLED": "demo_enabled",
    "EZZESECURE_DEBUG": "debug",
}


def local_overrides(root: Path) -> dict:
    values = {}
    env_file = root / ".env"
    if env_file.exists():
        if env_file.stat().st_size > 16384:
            raise ValueError("Local environment file is too large")
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if separator and key.strip() in FIELDS:
                values[key.strip()] = value.strip().strip('"\'')
    values.update({k: os.environ[k] for k in FIELDS if k in os.environ})
    result = {FIELDS[k]: v for k, v in values.items()}
    for key in ("demo_enabled", "debug"):
        if key in result:
            if result[key].lower() not in {"true", "false", "1", "0"}:
                raise ValueError("Invalid boolean setting")
            result[key] = result[key].lower() in {"true", "1"}
    for key, maximum in (("port", 65535), ("daily_brief_hour_utc", 23)):
        if key in result:
            result[key] = int(result[key])
            if not (1 if key == "port" else 0) <= result[key] <= maximum:
                raise ValueError("Invalid local numeric setting")
    for key in ("username", "organization"):
        if key in result and (not result[key] or len(result[key]) > 80 or any(ord(c) < 32 for c in result[key])):
            raise ValueError("Invalid local identity setting")
    if "owner_phone" in result and not re.fullmatch(r"\+[1-9]\d{7,14}", result["owner_phone"]):
        raise ValueError("Use E.164 format for the simulator identity")
    return result


def deployment_settings(config):
    production = config.get("mode") == "production"
    if production:
        if config.get("demo_enabled", False) is not False or config.get("debug", False) is not False:
            raise ValueError("Production requires demo and debug disabled")
        url = urlsplit(config.get("control_plane_url", ""))
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in ("", "/") or url.query or url.fragment
                or not re.fullmatch(r"[A-Za-z0-9.-]+", url.hostname)
                or (url.port is not None and not 1 <= url.port <= 65535)):
            raise ValueError("Production requires a configured HTTPS origin")
        config["control_plane_url"] = "https://" + url.netloc.lower()
        config.update(demo_enabled=False, debug=False, owner_phone="")
    return production
