"""python -m ezzesecure.agent --help"""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import getpass
import http.client
import os
import stat
import sys
import time
import warnings

from .plugins import IntegrityPlugin, LaravelPlugin, LogPlugin, SystemdPlugin
from .runtime import DemoAgent, LinuxAgent
from .security import FileIntegrity
from .transport import LocalAgentClient
from .connection import DEFAULT_CONNECTION, connection_settings, validate_origin, write_connection


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid argv, which may contain a mistakenly
        # pasted credential. Usage is safe; user-supplied values are not.
        super().error("Invalid arguments; use --help and enter secrets only at protected prompts")


def protected_input(prompt):
    if not sys.stdin.isatty():
        raise ValueError("An interactive terminal is required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt).strip()
        except getpass.GetPassWarning:
            raise ValueError("A protected terminal is required") from None


def transport_settings(args):
    if args.connection or not args.url:
        return connection_settings(args.connection or DEFAULT_CONNECTION, args.url)
    return validate_origin(args.url), None


def configured_integrity(config, root, scope="host"):
    values = config.get("integrity_files", []) if scope == "host" else config.get("laravel", {}).get("integrity_files", [])
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("Integrity requires at most 100 explicit files")
    paths = []
    for value in values:
        if (not isinstance(value, str) or not Path(value).is_absolute() or len(value) > 4096
                or any(character in value for character in "\x00\n\r*?[]")):
            raise ValueError("Integrity requires absolute literal file paths")
        paths.append(Path(value))
    filename = "integrity-baseline.json" if scope == "host" else "laravel-baseline.json"
    return FileIntegrity(paths, root / filename, max_file_bytes=1024 * 1024 if scope == "host" else 16 * 1024 * 1024)


def create_integrity_baseline(args):
    if args.demo or not args.config:
        raise ValueError("An explicit monitored-file configuration is required")
    config = json.loads(args.config.read_text())
    root = args.state_dir.absolute()
    # Refuse symlinked state paths; O_EXCL in FileIntegrity also prevents a
    # baseline-file symlink/overwrite. The existing state directory must be private.
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("State directory cannot contain symlinks")
    checker = configured_integrity(config, root, args.scope)
    if not checker.paths:
        raise ValueError("No integrity files configured for selected scope")
    monitored = [*config.get("integrity_files", []), *config.get("laravel", {}).get("integrity_files", [])]
    if any(Path(path).resolve() == checker.baseline_path.resolve() for path in monitored):
        raise ValueError("Baseline must not be a monitored file")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("State directory must be owner-only")
    result = checker.create_baseline()
    available = sum(entry["available"] for entry in result["files"].values())
    return {"status": "created", "scope": args.scope, "baseline": str(checker.baseline_path),
            "files_recorded": len(result["files"]), "files_available": available,
            "files_unavailable": len(result["files"]) - available,
            "note": "Initial trust is operator-reviewed; unavailable files remain unbaselined"}


def build_agent(args):
    root = args.state_dir.resolve()
    if args.demo:
        return DemoAgent(root)
    config = json.loads(args.config.read_text()) if args.config else {}
    if config.get("commands") or config.get("systemd", {}).get("allow_restart") or config.get("laravel", {}).get("allow_actions"):
        raise ValueError("Community agent configuration supports read-only collectors only")
    plugins = []
    laravel_integrity = None
    if config.get("systemd"):
        value = config["systemd"]
        plugins.append(SystemdPlugin(value["units"], Path(value.get("executable", "/usr/bin/systemctl")),
                                     value.get("allow_restart", False)))
    if config.get("laravel"):
        value = config["laravel"]
        root_path = Path(value["root"])
        integrity = FileIntegrity([Path(p) for p in value.get("integrity_files", [])], root / "laravel-baseline.json") if value.get("integrity_files") else None
        laravel_integrity = integrity
        plugins.append(LaravelPlugin(root_path, Path(value["health_file"]) if value.get("health_file") else None,
                                     Path(value.get("php", "/usr/bin/php")), value.get("allow_actions", False), integrity,
                                     scheduler_lock=Path(value["scheduler_lock"]) if value.get("scheduler_lock") else None))
    if config.get("logs"):
        value = config["logs"]
        plugins.append(LogPlugin(Path(value["access"]) if value.get("access") else None,
                                 Path(value["auth"]) if value.get("auth") else None))
    if config.get("sites"):
        from .sites import SitesPlugin
        value = config["sites"]
        plugins.append(SitesPlugin(nginx_paths=value.get("nginx_paths", []), apache_paths=value.get("apache_paths", []), log_paths=value.get("log_paths", [])))
    if config.get("integrity_files"):
        additional = (("laravel", laravel_integrity),) if laravel_integrity else ()
        plugins.append(IntegrityPlugin(configured_integrity(config, root), additional))
    blackbox = None
    if config.get("black_box", {}).get("enabled") is True:
        from .blackbox import BlackBoxCollector
        import hashlib
        value = config["black_box"]
        paths = value.get("integrity_files", [])
        if not isinstance(paths, list) or len(paths) > 100 or any(not isinstance(p, str) or not Path(p).is_absolute() for p in paths):
            raise ValueError("Black Box integrity requires at most 100 explicit absolute paths")
        fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        blackbox = BlackBoxCollector(root, auth_log=value.get("auth_log"), integrity_files=paths,
                                     configuration_hash=fingerprint)
    return LinuxAgent(root, plugins=plugins, disk_path=Path(config.get("disk_path", "/")), blackbox=blackbox)


def main(argv=None):
    parser = PrivateArgumentParser(description="EzzeSecure Community — read-only Linux agent and safe local demo")
    parser.add_argument("--state-dir", type=Path, default=Path(".local/agent"))
    parser.add_argument("--config", type=Path, help="Trusted local JSON registry/probe configuration")
    parser.add_argument("--demo", action="store_true", help="Use clearly marked project-local simulation")
    sub = parser.add_subparsers(dest="command", required=True)
    configure = sub.add_parser("configure", help="Privately configure origin and optional Cloudflare Access credentials")
    configure.add_argument("--url", required=True)
    configure.add_argument("--connection", type=Path, default=DEFAULT_CONNECTION)
    configure.add_argument("--cloudflare-access", action="store_true", help="Prompt without echo for Cloudflare Client ID and Secret")
    collect = sub.add_parser("collect", help="Print one bounded read-only snapshot")
    collect.add_argument("--interval", type=float, default=.2, help="CPU sampling interval, 0.05 to 10 seconds")
    baseline = sub.add_parser("integrity-baseline", help="Explicitly record initial file hashes in private agent state; never overwrite")
    baseline.add_argument("--scope", choices=("host", "laravel"), default="host")
    enroll = sub.add_parser("enroll", help="Consume a one-use enrollment token over HTTPS or local HTTP")
    enroll.add_argument("--url", help="Optional expected origin; must match --connection when both are supplied")
    enroll.add_argument("--connection", type=Path, help="Private connection JSON; installed default when --url is omitted")
    enroll.add_argument("--name", default="Linux server")
    enroll.add_argument("--token-file", type=Path, help="Owner-only file; otherwise prompt without echo")
    enroll.add_argument("--credentials", required=True, type=Path)
    poll = sub.add_parser("poll", help="Send signed telemetry; real monitored servers remain read-only")
    poll.add_argument("--url")
    poll.add_argument("--connection", type=Path)
    poll.add_argument("--credentials", required=True, type=Path)
    poll.add_argument("--interval", type=float, default=30)
    poll.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            origin = validate_origin(args.url)
            access = None
            if args.cloudflare_access:
                if not origin.startswith("https://"):
                    raise ValueError("Cloudflare Access requires HTTPS")
                access = {"client_id": protected_input("Cloudflare Client ID: "),
                          "client_secret": protected_input("Cloudflare Client Secret: ")}
            write_connection(args.connection, origin, access)
            print(json.dumps({"status": "configured"}))
            return 0
        if args.command == "integrity-baseline":
            print(json.dumps(create_integrity_baseline(args), indent=2))
            return 0
        if args.command == "enroll":
            url, access = transport_settings(args)
            if args.token_file:
                info = args.token_file.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                    raise ValueError("Enrollment token must be an owner-only regular file")
                token = args.token_file.read_text().strip()
            else:
                token = protected_input("One-use enrollment token: ")
            if not token or len(token) > 1024:
                raise ValueError("Invalid enrollment token")
            result = LocalAgentClient(url, cloudflare_access=access).enroll(token, args.name, args.credentials)
            print(json.dumps(result, indent=2))
            return 0
        agent = build_agent(args)
        if args.command == "collect":
            if not .05 <= args.interval <= 10:
                parser.error("collect interval must be between 0.05 and 10 seconds")
            if not args.demo:
                agent.collect()
                time.sleep(args.interval)
            print(json.dumps(agent.collect(), indent=2, allow_nan=False))
            return 0
        if not 1 <= args.interval <= 3600:
            parser.error("poll interval must be between 1 and 3600 seconds")
        url, access = transport_settings(args)
        client = LocalAgentClient.from_credentials(url, args.credentials, cloudflare_access=access)
        while True:
            try:
                print(json.dumps(client.poll_once(agent)), flush=True)
            except (OSError, RuntimeError, ValueError, http.client.HTTPException):
                if args.once:
                    raise
                # Transient network or collection failures must not stop monitoring.
                # Never log response bodies, credentials or local file content.
                print(json.dumps({"error": "Telemetry unavailable; retrying"}), flush=True)
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, EOFError, http.client.HTTPException) as exc:
        # Do not print exception content: configuration or HTTP errors could
        # include credentials, health file contents or sensitive local paths.
        print(json.dumps({"error": "Agent operation failed", "type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
