"""Transactional detection; SQL-backed windows survive restarts."""

import json
from datetime import timedelta

from sqlalchemy import select

from app.database.models import DetectionRule, Incident, IncidentEvent, SecurityEvent


def analyze(session, event):
    rule_id = {
        4625: "failed_logins",
        1102: "log_cleared",
        4720: "account_created",
        4672: "special_privileges",
    }.get(event.event_id)
    if not rule_id:
        return None
    rule = session.get(DetectionRule, rule_id)
    if not rule.enabled:
        return None
    key = json.dumps([rule_id, event.source, event.username, event.ip_address])
    evidence = [event]
    incident = None
    if event.event_id == 4625:
        cutoff = event.timestamp - timedelta(seconds=rule.window_seconds)
        evidence = list(
            session.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.event_id == 4625,
                    SecurityEvent.source == event.source,
                    SecurityEvent.username == event.username,
                    SecurityEvent.ip_address == event.ip_address,
                    SecurityEvent.timestamp >= cutoff,
                    SecurityEvent.timestamp <= event.timestamp,
                )
                .order_by(SecurityEvent.timestamp)
            )
        )
        if len(evidence) < rule.threshold:
            return None
        incident = session.scalar(
            select(Incident)
            .where(
                Incident.series_key == key,
                Incident.last_seen >= cutoff,
                Incident.first_seen <= event.timestamp,
            )
            .order_by(Incident.last_seen.desc())
            .limit(1)
        )
    created = incident is None
    if created:
        incident = Incident(
            rule_id=rule_id,
            title=rule.name,
            series_key=key,
            severity={4625: "Medium", 1102: "High", 4720: "Medium", 4672: "Low"}[event.event_id],
            first_seen=evidence[0].timestamp,
            last_seen=event.timestamp,
            event_count=0,
            status="Open",
        )
        session.add(incident)
        session.flush()
    for item in evidence:
        if not session.get(IncidentEvent, (incident.id, item.id)):
            session.add(IncidentEvent(incident_id=incident.id, event_id=item.id))
            incident.event_count += 1
    incident.last_seen = max(incident.last_seen, event.timestamp)
    return (
        {"id": incident.id, "title": incident.title, "severity": incident.severity}
        if created
        else None
    )
