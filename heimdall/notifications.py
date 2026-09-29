"""Local notification boundary; optional structured delivery lives in notification_delivery."""
from typing import Protocol


class NotificationChannel(Protocol):
    def send(self, message: str, *, severity: str, recipient_id: str) -> dict: ...


class LocalNotificationChannel:
    def send(self, message: str, *, severity: str, recipient_id: str) -> dict:
        return {"status": "recorded_locally", "channel": "local", "message": message}


def alert_message(server, severity, issue, assessment):
    symbol = "🚨" if severity == "CRITICAL" else "⚠️"
    return f"{symbol} EzzeSecure — {severity}\nServer: {server}\nIssue: {issue}\nAssessment: {assessment}\nAction taken: none\nReply: SECURITY for details."
