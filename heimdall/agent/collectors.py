"""Read-only Linux evidence. Unsupported/denied evidence is null, never zero."""
from __future__ import annotations

from pathlib import Path
from itertools import islice
import os
import shutil
import time

from .runtime import utc_now


class LinuxCollector:
    def __init__(self, proc_root: Path = Path("/proc"), disk_path: Path = Path("/")):
        self.proc = Path(proc_root)
        self.disk_path = Path(disk_path)
        self._cpu_previous = None
        self._network_previous = {}
        self._disk_previous = {}

    def collect(self) -> dict:
        unavailable = {}
        metrics = {"cpu_percent": None, "ram_percent": None, "disk_percent": None,
                   "load": None, "uptime_seconds": None, "swap_percent": None,
                   "cpu_count": os.cpu_count(), "source": "linux"}
        try:
            values = [int(x) for x in (self.proc / "stat").read_text().splitlines()[0].split()[1:9]]
            total, idle = sum(values), values[3] + values[4]
            previous = self._cpu_previous
            self._cpu_previous = (total, idle)
            if previous and total > previous[0] and 0 <= idle - previous[1] <= total - previous[0]:
                metrics["cpu_percent"] = round(100 * (1 - (idle - previous[1]) / (total - previous[0])), 2)
            else:
                unavailable["cpu_percent"] = "A second sample with elapsed CPU ticks is required"
        except (OSError, ValueError, IndexError):
            unavailable["cpu_percent"] = "Linux /proc/stat unavailable or invalid"
        try:
            memory = {}
            for line in (self.proc / "meminfo").read_text().splitlines():
                key, value = line.split(":", 1)
                memory[key] = int(value.split()[0]) * 1024
            total = memory["MemTotal"]
            metrics["memory_total_bytes"] = total
            available = memory["MemAvailable"]
            metrics["memory_available_bytes"] = available
            metrics["ram_percent"] = round(100 * (total - available) / total, 2)
            swap = memory["SwapTotal"]
            metrics["swap_total_bytes"] = swap
            metrics["swap_percent"] = round(100 * (swap - memory["SwapFree"]) / swap, 2) if swap else 0
        except (OSError, ValueError, KeyError, IndexError, ZeroDivisionError):
            unavailable["memory"] = "Linux memory counters unavailable or incomplete"
        try:
            metrics["uptime_seconds"] = float((self.proc / "uptime").read_text().split()[0])
            metrics["load"] = [float(x) for x in (self.proc / "loadavg").read_text().split()[:3]]
        except (OSError, ValueError, IndexError):
            unavailable["load_uptime"] = "Linux load or uptime counters unavailable"
        try:
            disk = shutil.disk_usage(self.disk_path)
            metrics.update(disk_percent=round(100 * disk.used / disk.total, 2),
                           disk_total_bytes=disk.total, disk_free_bytes=disk.free)
        except (OSError, ZeroDivisionError):
            unavailable["disk_percent"] = "Configured filesystem unavailable"
        metrics["network"] = self.network()
        metrics["disk_io"] = self.disk_io()
        processes, process_status = self.processes()
        ports, port_status = self.ports()
        return {"observed_at": utc_now(), "metrics": metrics, "services": [],
                "processes": processes, "ports": ports, "events": [], "sites": [],
                "application": {"queue_backlog": None, "queue_workers": None, "scheduler_last_run": None,
                                "scheduler_locked": None, "scheduler_running": None, "database_healthy": None},
                "traffic": {"requests_per_minute": None, "baseline_requests_per_minute": None,
                            "authenticated_ratio": None, "top_ip_ratio": None, "sensitive_probes": None,
                            "http_5xx_ratio": None},
                "evidence": {"unavailable": unavailable, "processes": process_status, "ports": port_status,
                             "services": "No service adapters configured", "application": "No application probe configured",
                             "traffic": "No access log configured",
                             "sites": {"available": False, "reason": "No virtual-host configuration paths supplied"}}}

    @staticmethod
    def _bounded_lines(path: Path, limit_bytes=262144):
        with path.open("rb") as stream:
            raw = stream.read(limit_bytes + 1)
        truncated = len(raw) > limit_bytes
        if truncated:
            raw = raw[:limit_bytes].rpartition(b"\n")[0]
        return raw.decode("ascii", "replace").splitlines(), truncated

    @staticmethod
    def _rates(previous, key, now, values):
        old = previous.get(key)
        if old is None or now <= old[0] or any(value < before for value, before in zip(values, old[1])):
            return [None] * len(values)
        return [round((value - before) / (now - old[0]), 2) for value, before in zip(values, old[1])]

    def network(self, now=None):
        now = time.monotonic() if now is None else now
        rows, current, skipped = [], {}, 0
        try:
            lines, truncated = self._bounded_lines(self.proc / "net/dev")
            if len(lines) < 2 or "Receive" not in lines[0] or "Transmit" not in lines[0]:
                raise ValueError("Invalid network counter header")
            candidates = lines[2:]
            truncated = truncated or len(candidates) > 64
            for line in candidates[:64]:
                try:
                    name, raw = line.rsplit(":", 1)
                    fields = [int(value) for value in raw.split()]
                    if len(fields) < 16 or any(value < 0 for value in fields):
                        raise ValueError("Invalid network counters")
                    name = name.strip()
                    rates = self._rates(self._network_previous, name, now, (fields[0], fields[8]))
                    rows.append({"interface": name, "rx_bytes": fields[0], "rx_packets": fields[1],
                                 "rx_errors": fields[2], "rx_dropped": fields[3], "tx_bytes": fields[8],
                                 "tx_packets": fields[9], "tx_errors": fields[10], "tx_dropped": fields[11],
                                 "rx_bytes_per_second": rates[0], "tx_bytes_per_second": rates[1]})
                    current[name] = (now, (fields[0], fields[8]))
                except (ValueError, IndexError):
                    skipped += 1
            self._network_previous = current
            return {"available": bool(rows), "interfaces": rows, "truncated": truncated, "skipped": skipped,
                    "counter_kind": "cumulative_since_interface_reset",
                    "scope": "Visible network namespace; at most 64 interfaces and 256 KiB; includes loopback/virtual devices",
                    "rate_note": "Rates need two valid samples; first sample or counter reset yields null"}
        except (OSError, ValueError):
            self._network_previous = {}
            return {"available": False, "interfaces": [], "reason": "Linux /proc/net/dev unavailable or invalid"}

    def disk_io(self, now=None):
        now = time.monotonic() if now is None else now
        rows, current, skipped = [], {}, 0
        try:
            lines, truncated = self._bounded_lines(self.proc / "diskstats")
            truncated = truncated or len(lines) > 64
            for line in lines[:64]:
                try:
                    fields = line.split()
                    major, minor, name = int(fields[0]), int(fields[1]), fields[2]
                    counters = [int(value) for value in fields[3:]]
                    if len(counters) < 11 or any(value < 0 for value in counters):
                        raise ValueError("Unsupported disk counter format")
                    # Kernel diskstats sectors are always 512 bytes, regardless
                    # of the hardware or filesystem's physical block size.
                    read_bytes, written_bytes = counters[2] * 512, counters[6] * 512
                    values = (read_bytes, written_bytes, counters[0], counters[4])
                    key = (major, minor, name)
                    rates = self._rates(self._disk_previous, key, now, values)
                    rows.append({"device": name, "major": major, "minor": minor,
                                 "read_operations": counters[0], "write_operations": counters[4],
                                 "read_bytes": read_bytes, "written_bytes": written_bytes,
                                 "read_milliseconds": counters[3], "write_milliseconds": counters[7],
                                 "io_in_progress": counters[8], "io_milliseconds": counters[9],
                                 "read_bytes_per_second": rates[0], "written_bytes_per_second": rates[1],
                                 "read_operations_per_second": rates[2], "write_operations_per_second": rates[3]})
                    current[key] = (now, values)
                except (ValueError, IndexError):
                    skipped += 1
            self._disk_previous = current
            return {"available": bool(rows), "devices": rows, "truncated": truncated, "skipped": skipped,
                    "counter_kind": "cumulative_since_device_reset_except_io_in_progress_gauge",
                    "scope": "At most 64 block-device rows and 256 KiB; partitions and virtual layers may overlap; do not sum rows",
                    "rate_note": "Rates need two valid samples; first sample or counter reset yields null"}
        except OSError:
            self._disk_previous = {}
            return {"available": False, "devices": [], "reason": "Linux /proc/diskstats unavailable"}

    def processes(self, limit=25, scan_limit=256):
        limit, scan_limit = min(max(1, limit), 25), min(max(1, scan_limit), 256)
        rows, skipped = [], 0
        try:
            with os.scandir(self.proc) as entries:
                pids = sorted((Path(p.path) for p in islice((p for p in entries if p.name.isdigit()), scan_limit + 1)), key=lambda p: int(p.name))
        except OSError:
            return [], {"available": False, "reason": "Linux process directory unavailable"}
        for path in pids[:scan_limit]:
            try:
                status = {}
                lines, _ = self._bounded_lines(path / "status", 16384)
                for line in lines:
                    key, value = line.split(":", 1)
                    status[key] = value.strip()
                row = {"pid": int(path.name), "name": status.get("Name"), "state": status.get("State"),
                       "memory_bytes": int(status["VmRSS"].split()[0]) * 1024 if "VmRSS" in status else None,
                       "cpu_ticks": None}
                try:
                    stat_lines, _ = self._bounded_lines(path / "stat", 16384)
                    # comm may contain whitespace and ')' characters; split
                    # after its final ')' rather than treating it as a token.
                    fields = stat_lines[0].rsplit(")", 1)[1].split()
                    row["cpu_ticks"] = int(fields[11]) + int(fields[12])
                except (OSError, ValueError, IndexError):
                    pass
                rows.append(row)
            except (OSError, ValueError, KeyError):
                skipped += 1
        rows.sort(key=lambda row: (-(row["memory_bytes"] if row["memory_bytes"] is not None else -1), row["pid"]))
        return rows[:limit], {"available": True, "truncated": len(pids) > scan_limit or len(rows) > limit,
                             "scan_truncated": len(pids) > scan_limit, "scanned": min(len(pids), scan_limit),
                             "returned": min(len(rows), limit), "skipped": skipped,
                             "scope": "Top 25 by resident memory within at most 256 sampled visible processes; not a global top; no command arguments",
                             "cpu_ticks_kind": "Cumulative process user+system ticks; not CPU percentage"}

    def ports(self):
        rows, missing, truncated = [], [], False
        for table in ("tcp", "tcp6", "udp", "udp6"):
            try:
                lines, byte_limited = self._bounded_lines(self.proc / "net" / table)
                lines = lines[1:]
                truncated = truncated or byte_limited or len(lines) > 4096
                for line in lines[:4096]:
                    fields = line.split()
                    if table.startswith("tcp") and fields[3] != "0A":
                        continue
                    if len(rows) >= 100:
                        truncated = True
                        continue
                    rows.append({"port": int(fields[1].split(":")[1], 16), "protocol": table,
                                 "state": "listening" if table.startswith("tcp") else "bound"})
            except (OSError, ValueError, IndexError):
                missing.append(table)
        return rows, {"available": len(missing) < 4, "unavailable_tables": missing,
                      "truncated": truncated, "returned": len(rows),
                      "scope": "Visible network namespace; 100 ports total, at most 4096 rows and 256 KiB read per table"}
