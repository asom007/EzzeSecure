"""Closed command registry: natural language and providers cannot create capabilities."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    name: str
    target: str
    description: str
    confirmation: bool = True


ACTIONS = {
    "scheduler.run": Action("scheduler.run", "laravel", "Run the registered scheduler once; check lock and verify completion"),
    "queue.restart": Action("queue.restart", "laravel", "Restart the registered queue workers"),
    "job.run": Action("job.run", "demo-job", "Run a registered job once"),
    "job.retry": Action("job.retry", "demo-job", "Retry a specifically registered failed job"),
    "cache.clear": Action("cache.clear", "laravel", "Clear the registered application's approved cache"),
    "service.restart": Action("service.restart", "web", "Restart a registered non-critical service"),
    "health.check": Action("health.check", "application", "Run the registered read-only health check", False),
}


def validate_action(action, parameters):
    if action not in ACTIONS or not isinstance(parameters, dict) or set(parameters) - {"target"}:
        raise ValueError("Action is not registered by policy")
    target = parameters.get("target", ACTIONS[action].target)
    if target != ACTIONS[action].target:
        raise ValueError("Target is not registered by policy")
    return {"target": target}
