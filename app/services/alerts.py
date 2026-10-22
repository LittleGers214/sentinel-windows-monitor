"""Notifications are dispatched by the UI, never by collectors."""


def alert_text(alert):
    return f"{alert['severity']} · Инцидент #{alert['id']}\n{alert['title']}"
