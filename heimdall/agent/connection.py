"""Private agent connection settings; no collector settings or secret argv."""
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import errno
import json
import os
import re
import stat

DEFAULT_CONNECTION = Path("/var/lib/ezzesecure-agent/connection.json")


def validate_origin(value):
    if (not isinstance(value, str) or not value or len(value) > 2048
            or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
            or any(c in value for c in "\\?#")):
        raise ValueError("Use an HTTPS origin or explicit loopback HTTP origin")
    try:
        url = urlsplit(value)
        host, port = url.hostname, url.port
        if (url.scheme not in {"https", "http"} or not host or url.username is not None
                or url.password is not None or url.path not in ("", "/")
                or url.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535)):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            loopback = address.is_loopback
        except ValueError:
            loopback = False
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError
        if url.scheme == "http" and not loopback:
            raise ValueError
    except ValueError:
        raise ValueError("Use an HTTPS origin or explicit loopback HTTP origin") from None
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if url.scheme == "https" else 80):
        authority += f":{port}"
    return f"{url.scheme}://{authority}"


def access_headers(origin, access):
    if access is None:
        return {}
    if (not origin.startswith("https://") or not isinstance(access, dict)
            or set(access) != {"client_id", "client_secret"}
            or any(not isinstance(v, str) or not 1 <= len(v) <= 4096
                   or any(ord(c) < 33 or ord(c) > 126 for c in v) for v in access.values())):
        raise ValueError("Cloudflare Access requires HTTPS and a valid complete credential pair")
    return {"CF-Access-Client-Id": access["client_id"], "CF-Access-Client-Secret": access["client_secret"]}


def read_private_json(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("Symlink credential files are not allowed") from None
        raise
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Credential configuration must be an owner-only regular file")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Credential configuration exceeds size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Credential configuration must be an object")
    return value


def connection_settings(path, expected_url=None):
    value = read_private_json(path)
    if set(value) - {"control_plane_url", "cloudflare_access"}:
        raise ValueError("Unknown connection setting")
    origin = validate_origin(value.get("control_plane_url"))
    if expected_url is not None and origin != validate_origin(expected_url):
        raise ValueError("Configured origin differs; credentials will not be sent")
    access = value.get("cloudflare_access")
    access_headers(origin, access)
    return origin, access


def write_connection(path, url, access=None):
    origin = validate_origin(url)
    access_headers(origin, access)
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Symlink connection paths are not allowed")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Connection directory must be owned and private")
    value = {"control_plane_url": origin}
    if access is not None:
        value["cloudflare_access"] = access
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
