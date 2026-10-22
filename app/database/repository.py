import json
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from time import time_ns

from sqlalchemy import create_engine, delete, event, func, select
from sqlalchemy.orm import sessionmaker

from app.database.models import (
    Base,
    DetectionRule,
    FileBaseline,
    Incident,
    IncidentEvent,
    InvestigationNote,
    ProcessSnapshot,
    SecurityEvent,
    Setting,
    utcnow,
)
from app.detection.engine import analyze
from app.detection.rules import RULES


def row_dict(row):
    return {col.name: getattr(row, col.name) for col in row.__table__.columns}


class Repository:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine("sqlite:///" + str(path), connect_args={"timeout": 15})

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(self.engine, expire_on_commit=False)
        with self.session.begin() as session:
            for key, name, threshold, window in RULES:
                if not session.get(DetectionRule, key):
                    session.add(
                        DetectionRule(
                            id=key,
                            name=name,
                            enabled=True,
                            threshold=threshold,
                            window_seconds=window,
                        )
                    )

    def setting(self, key, default=None):
        with self.session() as session:
            value = session.get(Setting, key)
            return json.loads(value.value) if value else default

    def save_settings(self, values, rules=None):
        if "integrity_roots" in values:
            roots = [str(Path(p).resolve()) for p in values["integrity_roots"] if p.strip()]
            db_parent = Path(self.engine.url.database).resolve().parent
            for root in roots:
                if db_parent.is_relative_to(Path(root)):
                    raise ValueError("Папка наблюдения не должна содержать рабочую базу Sentinel")
            values = dict(values, integrity_roots=list(dict.fromkeys(roots)))
        if "interval" in values and not 1 <= int(values["interval"]) <= 300:
            raise ValueError("Интервал должен быть от 1 до 300 секунд")
        if "retention_days" in values and not 1 <= int(values["retention_days"]) <= 3650:
            raise ValueError("Срок хранения должен быть от 1 до 3650 дней")
        with self.session.begin() as session:
            for key, value in values.items():
                session.merge(Setting(key=key, value=json.dumps(value)))
            for item in rules or []:
                if not 1 <= item["threshold"] <= 10000 or not 1 <= item["window_seconds"] <= 86400:
                    raise ValueError("Некорректные параметры правила")
                rule = session.get(DetectionRule, item["id"])
                rule.enabled = item["enabled"]
                rule.threshold = item["threshold"]
                rule.window_seconds = item["window_seconds"]

    def rules(self):
        with self.session() as session:
            return [row_dict(r) for r in session.scalars(select(DetectionRule))]

    def ingest(self, data, cursor=None):
        with self.session.begin() as session:
            exists = session.scalar(
                select(SecurityEvent.id).where(
                    SecurityEvent.channel == data.channel,
                    SecurityEvent.source == data.source,
                    SecurityEvent.record_id == data.record_id,
                    SecurityEvent.timestamp == data.timestamp,
                )
            )
            alert = None
            if not exists:
                item = SecurityEvent(**asdict(data))
                session.add(item)
                session.flush()
                alert = analyze(session, item)
            if cursor is not None:
                session.merge(Setting(key="event_cursor", value=json.dumps(cursor)))
            return alert

    def save_processes(self, rows):
        with self.session.begin() as session:
            session.add_all([ProcessSnapshot(**row) for row in rows])

    def events(self, since=None, event_id=None, severity=None, limit=500):
        query = select(SecurityEvent)
        if since:
            query = query.where(SecurityEvent.timestamp >= since)
        if event_id:
            query = query.where(SecurityEvent.event_id == int(event_id))
        if severity:
            query = query.where(
                SecurityEvent.id.in_(
                    select(IncidentEvent.event_id)
                    .join(Incident, Incident.id == IncidentEvent.incident_id)
                    .where(Incident.severity == severity)
                )
            )
        with self.session() as session:
            return [
                row_dict(r)
                for r in session.scalars(
                    query.order_by(SecurityEvent.timestamp.desc()).limit(limit)
                )
            ]

    def incidents(self, limit=500):
        with self.session() as session:
            return [
                row_dict(r)
                for r in session.scalars(
                    select(Incident).order_by(Incident.last_seen.desc()).limit(limit)
                )
            ]

    def evidence(self, incident_id):
        with self.session() as session:
            return [
                row_dict(r)
                for r in session.scalars(
                    select(SecurityEvent)
                    .join(IncidentEvent, SecurityEvent.id == IncidentEvent.event_id)
                    .where(IncidentEvent.incident_id == incident_id)
                    .order_by(SecurityEvent.timestamp)
                )
            ]

    def set_status(self, incident_id, status):
        if status not in ("Open", "Investigating", "Resolved", "FalsePositive"):
            raise ValueError("Неизвестный статус")
        with self.session.begin() as session:
            row = session.get(Incident, incident_id)
            if row is None:
                raise ValueError("Инцидент не найден")
            if row.status != status:
                session.add(
                    InvestigationNote(
                        incident_id=incident_id,
                        timestamp=utcnow(),
                        text=f"Статус: {row.status} → {status}",
                    )
                )
                row.status = status

    def add_note(self, incident_id, text):
        text = text.strip()
        if not text or len(text) > 10000:
            raise ValueError("Комментарий должен содержать от 1 до 10 000 символов")
        with self.session.begin() as session:
            if not session.get(Incident, incident_id):
                raise ValueError("Инцидент не найден")
            session.add(InvestigationNote(incident_id=incident_id, timestamp=utcnow(), text=text))

    def notes(self, incident_id):
        with self.session() as session:
            return [
                row_dict(r)
                for r in session.scalars(
                    select(InvestigationNote)
                    .where(InvestigationNote.incident_id == incident_id)
                    .order_by(InvestigationNote.id)
                )
            ]

    def apply_file_scan(self, root, files):
        alerts = []
        with self.session.begin() as session:
            marker = "baseline:" + root
            initialized = session.get(Setting, marker) is not None
            previous = {
                r.path: r
                for r in session.scalars(select(FileBaseline).where(FileBaseline.root == root))
            }
            for path in sorted(set(previous) | set(files)):
                old = previous[path].digest if path in previous else None
                new = files.get(path)
                if old == new:
                    continue
                if initialized:
                    action = "Создан" if old is None else "Удалён" if new is None else "Изменён"
                    now = utcnow()
                    incident = Incident(
                        rule_id="file_integrity",
                        title=f"{action} файл: {Path(path).name}",
                        series_key=path,
                        severity="Medium",
                        status="Open",
                        first_seen=now,
                        last_seen=now,
                        event_count=1,
                    )
                    session.add(incident)
                    data = SecurityEvent(
                        record_id=time_ns(),
                        event_id=9001,
                        timestamp=now,
                        source=root,
                        username="",
                        ip_address="",
                        channel="FileIntegrity",
                        raw_data=json.dumps(
                            {"action": action, "path": path, "old_sha256": old, "new_sha256": new},
                            ensure_ascii=False,
                        ),
                    )
                    session.add(data)
                    session.flush()
                    session.add(IncidentEvent(incident_id=incident.id, event_id=data.id))
                    alerts.append(
                        {"id": incident.id, "title": incident.title, "severity": "Medium"}
                    )
                if new is None:
                    session.delete(previous[path])
                else:
                    session.merge(FileBaseline(root=root, path=path, digest=new))
            session.merge(Setting(key=marker, value="true"))
        return alerts

    def stats(self):
        with self.session() as session:
            return {
                "events": session.scalar(select(func.count()).select_from(SecurityEvent)),
                "open": session.scalar(
                    select(func.count())
                    .select_from(Incident)
                    .where(Incident.status.in_(["Open", "Investigating"]))
                ),
                "high": session.scalar(
                    select(func.count())
                    .select_from(Incident)
                    .where(
                        Incident.severity == "High", Incident.status.in_(["Open", "Investigating"])
                    )
                ),
                "trend": [
                    session.scalar(
                        select(func.count())
                        .select_from(Incident)
                        .where(
                            Incident.first_seen
                            >= utcnow().replace(minute=0, second=0, microsecond=0)
                            - timedelta(hours=i),
                            Incident.first_seen
                            < utcnow().replace(minute=0, second=0, microsecond=0)
                            - timedelta(hours=i - 1),
                        )
                    )
                    for i in range(11, -1, -1)
                ],
            }

    def cleanup(self, days):
        cutoff = utcnow() - timedelta(days=days)
        with self.session.begin() as session:
            session.execute(delete(Incident).where(Incident.last_seen < cutoff))
            session.execute(
                delete(SecurityEvent).where(
                    SecurityEvent.timestamp < cutoff,
                    ~SecurityEvent.id.in_(select(IncidentEvent.event_id)),
                )
            )
            session.execute(delete(ProcessSnapshot).where(ProcessSnapshot.collected_at < cutoff))
