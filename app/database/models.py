from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow():
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class EventData:
    record_id: int
    event_id: int
    timestamp: datetime
    source: str
    username: str = ""
    ip_address: str = ""
    raw_data: str = ""
    channel: str = "Security"


class Base(DeclarativeBase):
    pass


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("channel", "source", "record_id", "timestamp"),
        Index("ix_event_series", "event_id", "source", "username", "ip_address", "timestamp"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    record_id: Mapped[int]
    event_id: Mapped[int] = mapped_column(index=True)
    timestamp: Mapped[datetime] = mapped_column(index=True)
    source: Mapped[str]
    username: Mapped[str]
    ip_address: Mapped[str]
    raw_data: Mapped[str]
    channel: Mapped[str]


class ProcessSnapshot(Base):
    __tablename__ = "process_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    pid: Mapped[int]
    process_name: Mapped[str]
    executable_path: Mapped[str | None]
    started_at: Mapped[float | None]
    username: Mapped[str | None]
    collected_at: Mapped[datetime] = mapped_column(index=True)
    cpu_percent: Mapped[float | None]
    memory_bytes: Mapped[int | None]
    connections: Mapped[str]


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str]
    title: Mapped[str]
    series_key: Mapped[str] = mapped_column(index=True)
    severity: Mapped[str]
    status: Mapped[str] = mapped_column(default="Open", index=True)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime] = mapped_column(index=True)
    event_count: Mapped[int]


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True
    )


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    threshold: Mapped[int] = mapped_column(default=5)
    window_seconds: Mapped[int] = mapped_column(default=60)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str]


class FileBaseline(Base):
    __tablename__ = "file_baselines"
    root: Mapped[str] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(primary_key=True)
    digest: Mapped[str]


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[datetime]
    text: Mapped[str]
