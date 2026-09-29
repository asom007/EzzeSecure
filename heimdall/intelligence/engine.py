"""Evidence-first, offline operations intelligence for the community edition.

An interpretation is an observation-based hypothesis, never proof of root cause.
This module neither executes commands nor grants approval to execute them.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any


ACTIONS = frozenset({"scheduler.run", "queue.restart", "job.run", "job.retry",
                     "cache.clear", "service.restart", "health.check"})
MAX_HISTORY = 288
MAX_CAPACITY_HISTORY = 10_000
CONTEXT_TTL_SECONDS = 600


def _number(value: Any, minimum: float = 0, maximum: float | None = None) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    if not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
        return None
    return value


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            return None
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _fmt(value: float) -> str:
    return f"{value:g}"


def _samples(history: list[dict], limit: int = MAX_HISTORY) -> list[dict]:
    # Sort and deduplicate timestamps so repeated polling cannot manufacture a trend.
    unique: dict[datetime, dict] = {}
    for sample in history[-limit:]:
        if isinstance(sample, dict):
            at = _timestamp(sample.get("observed_at"))
            if at:
                unique[at] = sample
    return [unique[at] for at in sorted(unique)]


def capacity_advice(history: list[dict]) -> dict:
    """Reserve capacity planning for distributed pressure over at least three days."""
    samples = _samples(history, MAX_CAPACITY_HISTORY)
    if samples:
        cutoff = _timestamp(samples[-1]["observed_at"]) - timedelta(days=7)
        samples = [s for s in samples if _timestamp(s["observed_at"]) >= cutoff]
    span = ((_timestamp(samples[-1]["observed_at"]) - _timestamp(samples[0]["observed_at"])).total_seconds()
            if len(samples) > 1 else 0)
    gaps = [(_timestamp(right["observed_at"]) - _timestamp(left["observed_at"])).total_seconds()
            for left, right in zip(samples, samples[1:])]
    facts = [f"{len(samples)} distinct timestamped samples cover {_fmt(span / 60)} minutes."]
    sustained: list[str] = []
    recent_pressure: list[str] = []
    peaks: dict[str, float] = {}
    medians: dict[str, float] = {}
    coverage: dict[str, int] = {}
    daily_coverage: dict[str, int] = {}
    derived: list[str] = []
    enough = len(samples) >= 18 and span >= 3 * 86400 and max(gaps, default=0) <= 6 * 3600
    complete = enough
    for key, label, threshold in (("cpu_percent", "CPU", 85), ("ram_percent", "RAM", 85),
                                  ("disk_percent", "disk", 90)):
        values = [_number(_mapping(s.get("metrics")).get(key), maximum=100) for s in samples]
        valid = [v for v in values if v is not None]
        coverage[key] = len(valid)
        if valid:
            peaks[key] = max(valid)
            ordered = sorted(valid)
            mid = len(ordered) // 2
            median = (ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2)
            medians[key] = median
            high = sum(v >= threshold for v in valid)
            facts.append(f"{label}: peak {_fmt(max(valid))}%, median {_fmt(median)}%, {high}/{len(valid)} readings at or above {threshold}%.")
            days: dict[str, list[tuple[datetime, float]]] = {}
            for item, value in zip(samples, values):
                if value is not None:
                    at = _timestamp(item["observed_at"])
                    days.setdefault(at.date().isoformat(), []).append((at, value))
            covered_days = [readings for readings in days.values()
                            if len(readings) >= 6 and (readings[-1][0] - readings[0][0]).total_seconds() >= 12 * 3600]
            high_days = sum(sum(v >= threshold for _, v in readings) / len(readings) >= .75
                            for readings in covered_days)
            daily_coverage[key] = len(covered_days)
            facts.append(f"{label}: {len(covered_days)} UTC day(s) have at least six readings distributed across at least 12 hours; {high_days} of those days show sustained pressure.")
            metric_complete = len(valid) >= 18 and len(valid) >= len(samples) * .8 and len(covered_days) >= 3
            complete = complete and metric_complete
            if enough and metric_complete and high_days >= 3 and high_days / len(covered_days) >= .75 and high / len(valid) >= .75 and all(v is not None and v >= threshold for v in values[-3:]):
                sustained.append(key)
                derived.append(f"Multi-day {label} pressure: at least three adequately sampled UTC days, at least 72 hours of coverage, at least 75% high readings and persistence in the last three readings at the {threshold}% threshold.")
            recent = [(s, v) for s, v in zip(samples, values)
                      if (_timestamp(samples[-1]["observed_at"]) - _timestamp(s["observed_at"])).total_seconds() <= 3600]
            recent_valid = [v for _, v in recent if v is not None]
            recent_span = ((_timestamp(recent[-1][0]["observed_at"]) - _timestamp(recent[0][0]["observed_at"])).total_seconds()
                           if len(recent) > 1 else 0)
            recent_gaps = [(_timestamp(right[0]["observed_at"]) - _timestamp(left[0]["observed_at"])).total_seconds()
                           for left, right in zip(recent, recent[1:])]
            if len(recent_valid) >= 6 and len(recent_valid) >= len(recent) * .8 and recent_span >= 1800 and max(recent_gaps, default=0) <= 900 and sum(v >= threshold for v in recent_valid) / len(recent_valid) >= .75 and all(v is not None and v >= threshold for _, v in recent[-3:]):
                recent_pressure.append(key)
                derived.append(f"Recent {label} pressure spans at least 30 minutes; this short window alone cannot justify a capacity upgrade.")
        else:
            complete = False
            daily_coverage[key] = 0
    if sustained:
        status = "sustained_pressure"
        recommendation = "Multi-day resource pressure supports capacity planning. Investigate workload and reclaim avoidable usage; consider an upgrade only if pressure persists after tuning."
    elif recent_pressure:
        status = "recent_pressure"
        recommendation = "Investigate the recent resource-pressure trend and collect distributed observations over at least three days. The short window does not justify a capacity upgrade."
    elif not complete:
        status = "insufficient_evidence"
        recommendation = "Collect at least 72 hours of CPU, RAM and disk observations, with at least three UTC days each containing six readings distributed over 12 hours and no gaps over six hours, before recommending a capacity upgrade."
    else:
        status = "no_sustained_pressure"
        recommendation = "Continue monitoring; the observed window does not justify a capacity increase."
    return {"status": status, "classification": status, "facts": facts, "derived_metrics": derived,
            "recommendation": recommendation, "recommendations": [recommendation],
            "sustained_resources": sustained, "recent_pressure_resources": recent_pressure,
            "upgrade_supported": bool(sustained), "peak_percent": peaks, "median_percent": medians,
            "coverage": coverage, "adequately_sampled_days": daily_coverage,
            "sample_count": len(samples), "window_minutes": round(span / 60, 2),
            "confidence": "high" if complete else "low", "incomplete_evidence": not complete,
            "provider": "deterministic"}


def analyze(evidence: dict, history: list[dict] = []) -> dict:
    """Classify observed operational symptoms with explicit uncertainty and provenance."""
    evidence = _mapping(evidence)
    metrics = _mapping(evidence.get("metrics"))
    traffic = _mapping(evidence.get("traffic"))
    application = _mapping(evidence.get("application"))
    facts: list[str] = []
    derived: list[str] = []
    missing: list[str] = []
    usage: dict[str, float] = {}
    for key, label in (("cpu_percent", "CPU"), ("ram_percent", "RAM"), ("disk_percent", "disk")):
        value = _number(metrics.get(key), maximum=100)
        if value is None:
            missing.append(key)
        else:
            usage[key] = value
            facts.append(f"{label} utilization is {_fmt(value)}%.")
    rpm = _number(traffic.get("requests_per_minute"))
    baseline = _number(traffic.get("baseline_requests_per_minute"))
    authenticated = _number(traffic.get("authenticated_ratio"), maximum=1)
    top_ip = _number(traffic.get("top_ip_ratio"), maximum=1)
    probes = _number(traffic.get("sensitive_probes"))
    errors = _number(traffic.get("http_5xx_ratio"), maximum=1)
    queue = _number(application.get("queue_backlog"))
    workers = _number(application.get("queue_workers"))
    queue_driver = str(application.get("queue_driver") or _mapping(application.get("queue")).get("driver") or "").lower()
    if queue_driver == "sync":
        queue = workers = None
        facts.append("Laravel uses the synchronous queue driver; asynchronous backlog and workers do not apply.")
    db = application.get("database_healthy")
    db = db if isinstance(db, bool) else None
    for value, label in ((rpm, "Requests per minute"), (baseline, "Baseline requests per minute"),
                         (probes, "Sensitive endpoint probes"), (queue, "Queue backlog"),
                         (workers, "Queue workers")):
        if value is not None:
            facts.append(f"{label}: {_fmt(value)}.")
    for value, label in ((authenticated, "Authenticated traffic"), (top_ip, "Top source share"), (errors, "HTTP 5xx responses")):
        if value is not None:
            facts.append(f"{label}: {_fmt(value * 100)}%.")
    if db is not None:
        facts.append("Database health check " + ("passed." if db else "failed."))
    else:
        missing.append("database_healthy")
    if rpm is None:
        missing.append("requests_per_minute")
    if baseline is None or baseline == 0:
        missing.append("positive traffic baseline")
    if queue is None and queue_driver != "sync":
        missing.append("queue_backlog")
    if workers is None and queue_driver != "sync":
        missing.append("queue_workers")
    multiplier = rpm / baseline if rpm is not None and baseline is not None and baseline > 0 else None
    if multiplier is not None and not math.isfinite(multiplier):
        multiplier = None
        missing.append("finite traffic comparison")
    if multiplier is not None:
        derived.append(f"Traffic is {multiplier:.2f}× the supplied baseline.")
    elevated = multiplier is not None and multiplier >= 2
    capacity = capacity_advice([*history[-MAX_CAPACITY_HISTORY + 1:], evidence])
    conditions: list[dict] = []

    def condition(classification: str, severity: str, interpretation: str, recommendations: list[str]) -> None:
        conditions.append({"classification": classification, "severity": severity,
                           "interpretation": interpretation, "recommendations": recommendations})

    if db is False:
        condition("database", "critical", "The database health check failed; application failures may be downstream symptoms. The cause is not established.",
                  ["Inspect database connectivity, health and connection limits before restarting dependent services.",
                   "Review database logs and recent deployment changes."])
    if probes is not None and probes >= 20 and (elevated or (top_ip is not None and top_ip >= .6)):
        condition("attack", "high", "Sensitive endpoint probing alongside elevated or concentrated traffic is consistent with a possible attack. Request volume alone does not prove malicious intent.",
                  ["Review request logs, source distribution and sensitive endpoint responses.",
                   "Consider targeted rate limits after validating sources; do not block all traffic automatically."])
    previous = history[-1] if history else {}
    if history and previous.get("received_at") and previous.get("received_at") == evidence.get("received_at"):
        previous = history[-2] if len(history) > 1 else {}
    previous_app = _mapping(_mapping(previous).get("application"))
    previous_queue = _number(previous_app.get("queue_backlog", _mapping(previous_app.get("queue")).get("backlog")))
    if queue is not None and previous_queue is not None and queue > previous_queue:
        derived.append(f"Queue backlog rose from {_fmt(previous_queue)} to {_fmt(queue)} across two observations; arrivals exceeded completions over that interval.")
    service_rows = evidence.get("services") if isinstance(evidence.get("services"), list) else []
    expected_worker_missing = any(isinstance(service, dict) and service.get("expected") is True
                                  and service.get("role") == "queue_worker"
                                  and str(service.get("state") or "").lower() in {"missing", "failed", "inactive", "stopped", "down"}
                                  for service in service_rows)
    if expected_worker_missing:
        facts.append("An explicitly expected queue worker service is unavailable.")
    if queue is not None and queue > 0 and (workers == 0 or expected_worker_missing):
        condition("queue", "high", "Queued work is present while an expected worker is unavailable; worker availability is a likely contributor. The underlying cause is not established.",
                  ["Inspect the registered queue worker service and failed-job logs.",
                   "Request an approved queue worker restart if the service is unhealthy, then verify backlog drainage."])
    elif queue is not None and queue >= 100:
        condition("queue", "warning", "The queue backlog is elevated. A single backlog measurement does not establish whether the queue is draining.",
                  ["Compare enqueue and completion rates over time and inspect worker health."])
    processes = evidence.get("processes")
    background_processes = [p for p in (processes[:100] if isinstance(processes, list) else [])
                            if isinstance(p, dict) and p.get("workload_type") in {"background", "batch", "cron"}
                            and (_number(p.get("cpu_percent")) or 0) >= 30]
    active_jobs = _number(application.get("background_jobs_active"))
    if usage.get("cpu_percent", 0) >= 75 and (background_processes or (active_jobs is not None and active_jobs > 0) or application.get("scheduler_running") is True):
        if background_processes:
            facts.append(f"{len(background_processes)} explicitly labeled background/batch/cron process(es) each report at least 30% CPU.")
        if active_jobs is not None:
            facts.append(f"Active background jobs: {_fmt(active_jobs)}.")
        if application.get("scheduler_running") is True:
            facts.append("The application reports an active scheduler run.")
        condition("background_workload", "warning", "High CPU coincides with explicitly reported background work. This supports a background-workload hypothesis but does not prove causation.",
                  ["Compare the active job or scheduler run with process CPU and completion history before interrupting work."])
    if capacity["sustained_resources"]:
        derived.extend(capacity["derived_metrics"])
        condition("capacity", "high", "Timestamped observations show sustained resource pressure. This supports capacity planning after checking workload efficiency.", capacity["recommendations"])
    elif capacity["recent_pressure_resources"] or any(v >= 90 for v in usage.values()):
        condition("resource_pressure", "warning", "Current resource use is high, but sustained capacity demand has not been established.",
                  ["Inspect active workloads and collect a sustained resource history before resizing."])
    if errors is not None and errors >= .05:
        condition("application_errors", "high", "The observed HTTP 5xx rate is elevated. Error logs and dependency checks are needed to establish the cause.",
                  ["Inspect application error logs and upstream dependency health."])
    services = evidence.get("services")
    if isinstance(services, list):
        failed = [str(s.get("name", "unnamed service"))[:100] for s in services[:100]
                  if isinstance(s, dict) and (s.get("state") in ("failed", "stopped", "inactive", "down", "missing")
                                               or s.get("available") is False)]
        if failed:
            facts.append(f"{len(failed)} service(s) are reported unavailable or have a failed probe.")
            condition("service", "high", "At least one expected service is unavailable or its probe failed. Whether this is maintenance is unknown.",
                      ["Check the affected service status, logs and expected operating state before requesting a restart."])
    if elevated:
        if authenticated is not None and authenticated >= .65 and probes is not None and probes < 5 and errors is not None and errors < .02:
            condition("growth", "warning" if any(v >= 90 for v in usage.values()) else "info", "Traffic increased relative to the supplied baseline, with mostly authenticated requests, few sensitive probes and a low observed error rate. This is consistent with legitimate growth, not proof of demand quality.",
                      ["Track traffic and conversion trends, latency and resource headroom before changing capacity."])
        else:
            condition("traffic_spike", "warning", "Traffic exceeds the supplied baseline; available evidence does not establish legitimate growth or an attack.",
                      ["Compare authentication, source distribution, sensitive probes and error rates with the traffic baseline."])
    if application.get("scheduler_locked") is True:
        facts.append("The scheduler reports a lock.")
        condition("scheduler", "warning", "The scheduler reports a lock; this may be an active run or a stale lock. Lock age and process state are needed to distinguish them.",
                  ["Inspect scheduler lock age, process state and last-run logs before requesting a run."])
    last_run = _timestamp(application.get("scheduler_last_run"))
    observed_at = _timestamp(evidence.get("observed_at"))
    if last_run and observed_at and observed_at >= last_run:
        interval = _number(application.get("scheduler_interval_seconds"))
        derived.append(f"Scheduler last-run age at observation: {_fmt((observed_at - last_run).total_seconds() / 60)} minutes" + (f"; expected interval {_fmt(interval / 60)} minutes." if interval else "; expected interval was not supplied."))
        if interval and (observed_at - last_run).total_seconds() > interval * 2:
            condition("scheduler", "warning", "Scheduler runner activity is stale relative to its supplied interval. Individual task completion is not observed.",
                      ["Inspect runner scheduling and its most recent safe execution metadata."])
    if not conditions:
        if missing:
            condition("unknown", "info", "Available observations do not establish a fault, and evidence is incomplete; overall health cannot be confirmed.",
                      ["Collect missing telemetry and compare with a known baseline."])
        else:
            condition("healthy", "info", "The supplied resource, traffic, database and queue observations show no classified fault. This is limited to the available checks.",
                      ["Continue monitoring and retain timestamped history for trend analysis."])
    severity_rank = {"critical": 4, "high": 3, "warning": 2, "info": 1}
    category_order = {"database": 12, "attack": 11, "queue": 10, "application_errors": 9,
                      "service": 8, "capacity": 7, "scheduler": 6, "growth": 5,
                      "background_workload": 4, "resource_pressure": 3, "traffic_spike": 2}
    conditions.sort(key=lambda item: (severity_rank[item["severity"]], category_order.get(item["classification"], 0)), reverse=True)
    classifications = {"growth": "NORMAL_GROWTH", "attack": "SUSPICIOUS_ACTIVITY",
                       "background_workload": "BACKGROUND_WORKLOAD", "capacity": "CAPACITY_PRESSURE",
                       "resource_pressure": "CAPACITY_PRESSURE", "database": "APPLICATION_BOTTLENECK",
                       "queue": "APPLICATION_BOTTLENECK", "application_errors": "APPLICATION_BOTTLENECK",
                       "service": "APPLICATION_BOTTLENECK", "scheduler": "APPLICATION_BOTTLENECK"}
    severities = {"info": "INFO", "warning": "WARNING", "high": "WARNING", "critical": "CRITICAL"}
    for finding in conditions:
        finding["category"] = finding["classification"]
        finding["classification"] = classifications.get(finding["category"], "UNKNOWN")
        finding["notification_severity"] = {"info": "INFO", "warning": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}[finding["severity"]]
        finding["severity"] = severities[finding["severity"]]
    primary = dict(conditions[0])
    primary["status"] = "healthy" if primary["category"] == "healthy" else "unknown" if primary["category"] == "unknown" else "attention"
    if missing:
        facts.append("Incomplete evidence: missing or invalid " + ", ".join(missing) + ".")
    primary.update({"facts": facts, "derived_metrics": derived, "confidence": "low" if missing else "medium",
                    "provider": "deterministic", "incomplete_evidence": bool(missing),
                    "missing_evidence": missing, "findings": conditions})
    return primary


def daily_brief(samples: list[dict], events: list[dict]) -> dict:
    """Summarize only the supplied, bounded observation window; never invent a day."""
    history = _samples(samples, MAX_CAPACITY_HISTORY)
    recent = history
    previous: list[dict] = []
    if history:
        end = _timestamp(history[-1]["observed_at"])
        cutoff = end - timedelta(days=1)
        recent = [s for s in history if _timestamp(s["observed_at"]) > cutoff][-MAX_HISTORY:]
        previous = [s for s in history if cutoff - timedelta(days=1) < _timestamp(s["observed_at"]) <= cutoff][-MAX_HISTORY:]
    # Snapshot hypotheses are linear; the multi-day capacity window is assessed once.
    analyses = [analyze(sample) for sample in recent]
    counts = Counter(a["classification"] for a in analyses)
    categories = Counter(a["category"] for a in analyses)
    valid_events = [e for e in events[-200:] if isinstance(e, dict)]
    summaries = [str(e["summary"])[:500] for e in valid_events if isinstance(e.get("summary"), str)][:20]
    facts = [f"{len(recent)} distinct timestamped observations and {len(valid_events)} supplied events reviewed."]
    if recent:
        facts.append(f"Observation window: {recent[0]['observed_at']} to {recent[-1]['observed_at']}.")
    facts.extend(f"{key}: {value} observation(s)." for key, value in sorted(counts.items()))
    capacity = capacity_advice(history)
    averages: dict[str, float | None] = {}
    average_coverage: dict[str, int] = {}
    for key in ("cpu_percent", "ram_percent", "disk_percent"):
        values = [_number(_mapping(s.get("metrics")).get(key), maximum=100) for s in recent]
        valid = [v for v in values if v is not None]
        averages[key] = round(sum(valid) / len(valid), 2) if valid else None
        average_coverage[key] = len(valid)
    availability_values = [_mapping(s.get("availability")).get("available", s.get("available")) for s in recent]
    availability_observations = [v for v in availability_values if isinstance(v, bool)]
    availability = {"status": "observed" if availability_observations else "insufficient_evidence",
                    "sample_count": len(availability_observations),
                    "observed_available_percent": round(sum(availability_observations) / len(availability_observations) * 100, 2) if availability_observations else None,
                    "limitation": "Availability is the fraction of explicitly labeled observations; it is not continuous uptime and does not cover missing intervals."}

    def traffic_average(window: list[dict]) -> float | None:
        values = [_number(_mapping(s.get("traffic")).get("requests_per_minute")) for s in window]
        valid = [v for v in values if v is not None]
        span = ((_timestamp(window[-1]["observed_at"]) - _timestamp(window[0]["observed_at"])).total_seconds()
                if len(window) > 1 else 0)
        gaps = [(_timestamp(right["observed_at"]) - _timestamp(left["observed_at"])).total_seconds()
                for left, right in zip(window, window[1:])]
        if len(valid) < 6 or len(valid) < len(window) * .8 or span < 12 * 3600 or max(gaps, default=0) > 6 * 3600:
            return None
        mean = sum(v / len(valid) for v in valid)
        return mean if math.isfinite(mean) else None

    current_traffic, previous_traffic = traffic_average(recent), traffic_average(previous)
    change = ((current_traffic / previous_traffic - 1) * 100
              if current_traffic is not None and previous_traffic is not None and previous_traffic > 0 else None)
    change = change if change is not None and math.isfinite(change) else None
    traffic_comparison = {"status": "observed" if change is not None else "insufficient_evidence",
                          "current_mean_requests_per_minute": current_traffic,
                          "previous_mean_requests_per_minute": previous_traffic,
                          "change_percent": round(change, 2) if change is not None else None,
                          "limitation": "Compares sampled request-rate means for the latest and preceding 24-hour windows, each requiring six readings across 12 hours and gaps of at most six hours; this is not total requests."}
    security_events = [e for e in valid_events if e.get("kind") in {"security", "auth", "failed_login", "ssh", "firewall", "fim", "file_integrity"} or e.get("category") == "security"]
    security = {"event_count": len(security_events),
                "reported_occurrences": sum(_number(e.get("count")) if _number(e.get("count")) is not None else 1 for e in security_events),
                "severity_counts": dict(Counter(str(e.get("severity", "UNKNOWN")).upper() for e in security_events)),
                "limitation": "Counts only supplied security events; event coverage and absence of threats are not established."}
    incomplete = not recent or any(a["incomplete_evidence"] for a in analyses)
    summary = ("No timestamped observations were supplied; daily health cannot be assessed." if not recent
               else f"Reviewed {len(recent)} observations: " + ", ".join(f"{value} {key.replace('_', ' ')}" for key, value in sorted(categories.items())) + ".")
    measured = [f"{label} {_fmt(averages[key])}%" for key, label in (("cpu_percent", "CPU"), ("ram_percent", "RAM"), ("disk_percent", "disk")) if averages[key] is not None]
    if measured:
        summary += " Sampled averages: " + ", ".join(measured) + "."
    summary += (f" Availability: {_fmt(availability['observed_available_percent'])}% of {availability['sample_count']} explicitly labeled observations."
                if availability_observations else " Availability evidence was not supplied.")
    summary += (f" Sampled traffic changed by {traffic_comparison['change_percent']:g}% versus the preceding window."
                if change is not None else " Traffic comparison needs more distributed observations.")
    summary += f" Supplied security events: {security['event_count']}. Capacity assessment: {capacity['status'].replace('_', ' ')}."
    return {"summary": summary, "facts": facts, "classifications": dict(counts), "categories": dict(categories), "events": summaries,
            "capacity": capacity, "recommendations": capacity["recommendations"],
            "average_percent": averages, "average_coverage": average_coverage,
            "availability": availability, "traffic_comparison": traffic_comparison, "security": security,
            "sample_count": len(recent), "event_count": len(valid_events),
            "period_start": recent[0]["observed_at"] if recent else None,
            "period_end": recent[-1]["observed_at"] if recent else None,
            "incomplete_evidence": incomplete, "confidence": "low" if incomplete else "medium",
            "limitations": "Only supplied observations are covered; missing intervals are not assumed healthy. Event summaries are reported observations, not verified causes.",
            "provider": "deterministic"}


def _normalize(text: str) -> str:
    text = re.sub(r"[\u064b-\u065f\u0670\u0640]", "", text.casefold())
    return text.translate(str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ى": "ي"})).strip()


def _result(intent: str, command_class: str = "A", action: str | None = None,
            topic: str = "operations", parameters: dict | None = None, **extra: Any) -> dict:
    return {"intent": intent, "command_class": command_class, "action": action,
            "parameters": parameters or {}, "topic": topic, **extra}


def _diagnostic_topic(text: str) -> str:
    for topic, pattern in (
        ("scheduler", r"\b(?:scheduler|schedule|cron)\b|(?:الجدول|الجدوله|الجدولة|المجدول|الكرون|كرون|السكجولر)"),
        ("queue", r"\b(?:queue|workers?|queues|messages?)\b|(?:الطابور|الكيو|الصف|العمال|الرسائل)"),
        ("security", r"\b(?:security|attack|attacks|threat|threats|intrusion|suspicious|fim|ssh|sudo)\b|(?:امن|امان|هجوم|اختراق|مشبوه|حمايه|حماية|يحاول يفوت)"),
        ("cpu", r"\b(?:cpu|processor|load)\b|(?:المعالج|معالج)"),
        ("memory", r"\b(?:memory|ram|swap)\b|(?:الذاكره|الذاكرة|رام)"),
        ("disk", r"\b(?:disk|storage|space|filesystem)\b|(?:قرص|القرص|التخزين|مساحه|مساحة)"),
        ("database", r"\b(?:database|db|mysql|postgres|redis)\b|(?:قاعده البيانات|قاعدة البيانات|الداتابيس)"),
        ("traffic", r"\b(?:traffic|requests|visitors|growth)\b|(?:الزيارات|زوار|الطلبات|ترافيك)"),
        ("logs", r"\b(?:logs?|errors?|exceptions?)\b|(?:سجلات|السجلات|اخطاء|الاخطاء)"),
        ("services", r"\b(?:services?|processes|ports)\b|(?:خدمات|الخدمات|العمليات|المنافذ)"),
        ("history", r"\b(?:history|historical|yesterday|trend|trends|last hour)\b|(?:السجل|سابق|الامس|تاريخ|مبارح|اخر ساعه|اخر ساعة)"),
        ("capacity", r"\b(?:capacity|resize|upgrade|sizing)\b|(?:السعه|السعة|ترقيه|ترقية|موارد)"),
        ("daily_brief", r"\b(?:daily|brief|summary|report)\b|(?:ملخص|تقرير)"),
        ("overview", r"\b(?:health|status|overview|server|check)\b|(?:افحص|الحاله|الحالة|الوضع|السيرفر|الخادم)"),
    ):
        if re.search(pattern, text):
            return topic
    return "operations"


def _recent_action(context: dict | None) -> tuple[str, dict] | None:
    if not isinstance(context, dict):
        return None
    candidate = context.get("recent_action", context)
    if not isinstance(candidate, dict):
        return None
    established = _timestamp(candidate.get("established_at"))
    # A caller can supply now for deterministic simulations; production passes trusted context.
    now = _timestamp(context.get("now")) or datetime.now(timezone.utc)
    if not established or not 0 <= (now - established).total_seconds() <= CONTEXT_TTL_SECONDS:
        return None
    action = candidate.get("action")
    params = candidate.get("parameters", {})
    if action not in ACTIONS or not isinstance(params, dict) or set(params) - {"target"}:
        return None
    if "target" in params and (not isinstance(params["target"], str) or not re.fullmatch(r"[\w.-]{1,80}", params["target"])):
        return None
    return action, dict(params)


def interpret(text: str, context: dict | None = None) -> dict:
    """Parse a bounded bilingual request. Class B means approval required, never execute."""
    if not isinstance(text, str) or not text.strip():
        return _result("clarify", topic="unknown", reason="No command was supplied.")
    if len(text) > 2000:
        return _result("denied", "C", topic="protected", reason="Request exceeds the command length limit.")
    normalized = _normalize(text)
    protected = (r"\b(?:rm|sudo|su|chmod|chown|mkfs|shutdown|reboot|poweroff|iptables|ufw|firewall|eval|exec|curl|wget|ssh|bash|sh|kill|passwd|useradd)\b",
                 r"\b(?:delete|drop|truncate|wipe|erase|format)\b",
                 r"\b(?:secret|secrets|password|passwords|credential|credentials|private\s+key|api\s*key|token|tokens)\b",
                 r"\b(?:disable|bypass|ignore)\b.*\b(?:auth|authentication|security|approval|approvals|rules|instructions|audit)\b",
                 r"\b(?:clear|purge|flush|alter|edit|modify)\b.*\b(?:logs?|audit|users?|permissions?|configuration|config)\b",
                 r"\b(?:restart|stop)\s+(?:the\s+)?(?:server|system|host)\b",
                 r"(?:احذف|حذف|امسح|فورمات|اطفي|اطفاء|كلمه السر|كلمة السر|كلمات المرور|كلمه المرور|كلمة المرور|المفاتيح|الاسرار|الجدار الناري|تعطيل الحمايه|تعطيل الحماية)",
                 r"(?:تجاهل|تجاوز).*(?:تعليمات|موافق|حماي|حماية|امن)",
                 r"[;`|]|\$\(|&&|[<>]|[\r\n]")
    # Reading SSH/sudo history is safe; these words otherwise remain protected.
    safety_text = normalized
    if _diagnostic_topic(normalized) == "security" and re.search(r"\b(?:summary|activity|attempts|logins|failed|show|status)\b", normalized):
        safety_text = re.sub(r"\b(?:ssh|sudo)\b", "security", normalized)
    if any(re.search(pattern, safety_text) for pattern in protected):
        return _result("denied", "C", topic="protected", reason="Protected operation or executable command syntax is not supported.")
    if re.search(r"\b(?:do not|don't|dont|never)\b|(?:^|\s)(?:لا|لاتشغل|لاتعيد|لاتنفذ)(?:\s|$)", normalized):
        return _result("diagnose", topic="operations", reason="A negated request cannot authorize an action.")
    scheduler = bool(re.search(r"\b(?:scheduler|schedule|cron)\b|(?:الجدول|الجدوله|الجدولة|المجدول|الكرون|كرون|السكجولر)", normalized))
    queue = bool(re.search(r"\b(?:queue|workers?|queues)\b|(?:الطابور|الكيو|الصف|العمال)", normalized))
    topic = _diagnostic_topic(normalized)
    question = bool(re.search(r"\b(?:why|how|when|explain|diagnose|investigate|delayed|delay|late|slow|stuck|status|what happened)\b|(?:ليش|لماذا|كيف|متي|تاخر|تاخير|متاخر|بطي|حاله|حالة|اشرح)", normalized))
    if question:
        return _result("diagnose", topic=topic)
    if re.search(r"\b(?:daily|brief|summary|report)\b|(?:ملخص|تقرير)", normalized):
        return _result("diagnose", topic=topic) if topic == "security" else _result("daily_brief", topic="daily_brief")
    if re.search(r"\b(?:capacity|resize|upgrade|sizing)\b|(?:السعه|السعة|ترقيه|ترقية|موارد)", normalized):
        return _result("capacity", topic="capacity")
    repeat = bool(re.fullmatch(r"(?:please\s+)?(?:do it|run it|repeat(?: it)?|again|execute it|نفذ|نفذها|نفذه|شغلها|شغله|عيدها|كررها)(?:\s+(?:please|now|الان|الحين|هلق|هسه|دلوقتي))?[.!؟?]?", normalized))
    if repeat:
        recent = _recent_action(context)
        if recent:
            return _result("request_action", "B", recent[0], recent[0].split(".")[0], recent[1], requires_approval=True)
        return _result("clarify", topic="unknown", reason="Specify an action; no recent unambiguous action context is available.")
    run = bool(re.search(r"\b(?:run|start|trigger|execute|launch)\b|(?:شغل|تشغيل|نفذ|تنفيذ|ابدا)", normalized))
    restart = bool(re.search(r"\brestart\b|(?:اعد تشغيل|اعاده تشغيل|اعادة تشغيل|ريستارت)", normalized))
    cache = bool(re.search(r"\bcache\b|(?:الكاش|ذاكره التخزين|ذاكرة التخزين)", normalized))
    job = bool(re.search(r"\bjob\b|(?:المهمه|المهمة|وظيفه|وظيفة)", normalized))
    service = bool(re.search(r"\bservice\b|(?:الخدمه|الخدمة)", normalized))
    categories = sum((scheduler, queue, cache, job, service))
    if categories > 1 or re.search(r"\b(?:then|and|or)\b|(?:وبعدين|ثم)|(?:و(?:شغل|نفذ|اعد|نظف|امسح))", normalized):
        return _result("clarify", topic="operations", reason="Submit one explicit operation at a time.")
    action: str | None = None
    if scheduler and run and not restart:
        action = "scheduler.run"
    elif queue and restart:
        action = "queue.restart"
    elif cache and re.search(r"\b(?:clear|flush|purge)\b|(?:نظف|تنظيف|افرغ|تفريغ)", normalized):
        action = "cache.clear"
    elif job and re.search(r"\bretry\b|(?:اعد المحاوله|اعد المحاولة|اعاده المحاوله|اعادة المحاولة)", normalized):
        action = "job.retry"
    elif job and run:
        action = "job.run"
    elif service and restart:
        action = "service.restart"
    elif re.search(r"\b(?:run|perform|execute)\s+(?:a\s+)?health\s*check\b|(?:نفذ|شغل|اجر).*(?:فحص الصحه|فحص الصحة)", normalized):
        action = "health.check"
    parameters: dict[str, str] = {}
    if action:
        target = re.search(r"(?:\btarget\s*[:=]?\s*|الهدف\s*[:=]?\s*)([\w.-]{1,80})(?![\w.-])", normalized)
        if target:
            parameters["target"] = target.group(1)
        elif action.startswith(("service.", "job.")):
            target = re.search(r"(?:\b(?:service|job)\s+|(?:الخدمه|الخدمة|المهمه|المهمة)\s+)([a-z0-9][a-z0-9_.-]{0,79})(?![\w.-])", normalized)
            if target and target.group(1) not in {"now", "please", "again"}:
                parameters["target"] = target.group(1)
            else:
                return _result("clarify", topic=action.split(".")[0], reason="Specify a registered target.")
        return _result("request_action", "B", action, action.split(".")[0], parameters, requires_approval=True)
    return _result("diagnose" if topic != "operations" else "clarify",
                   topic=topic,
                   reason="No unambiguous supported action was requested.")
