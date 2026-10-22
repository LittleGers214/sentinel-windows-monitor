import json
from datetime import UTC, datetime, timedelta
from xml.etree.ElementTree import ParseError

import pytest
from sqlalchemy import func, select

from app.collectors.windows_events import parse_event
from app.database.models import EventData, IncidentEvent, ProcessSnapshot
from app.database.repository import Repository
from app.services.reports import export_report


@pytest.fixture
def repo(tmp_path):
    repository = Repository(tmp_path / "test.db")
    yield repository
    repository.engine.dispose()


def event(i, seconds=None, **kwargs):
    return EventData(
        i,
        kwargs.pop("event_id", 4625),
        datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)
        + timedelta(seconds=i if seconds is None else seconds),
        kwargs.pop("source", "PC"),
        kwargs.pop("username", "alice"),
        kwargs.pop("ip_address", ""),
        **kwargs,
    )


def test_threshold_dedup_and_restart(repo):
    for i in range(4):
        assert repo.ingest(event(i)) is None
    assert repo.stats()["open"] == 0
    assert repo.ingest(event(4))["severity"] == "Medium"
    repo.ingest(event(4))
    assert repo.stats()["events"] == 5
    other = Repository(repo.engine.url.database)
    assert other.ingest(event(5)) is None
    assert other.incidents()[0]["event_count"] == 6
    assert len(other.evidence(other.incidents()[0]["id"])) == 6
    other.engine.dispose()


def test_window_and_identity(repo):
    for i in range(4):
        repo.ingest(event(i))
    repo.ingest(event(4, seconds=64))
    repo.ingest(event(5, username="bob"))
    repo.ingest(event(6, ip_address="192.0.2.1"))
    assert repo.stats()["open"] == 0


def test_inclusive_boundary_new_series_and_reused_record(repo):
    for i, seconds in enumerate([0, 10, 20, 30, 60]):
        repo.ingest(event(i, seconds))
    assert repo.stats()["open"] == 1
    for i in range(5):
        repo.ingest(event(i, 200 + i))
    assert repo.stats()["events"] == 10
    assert repo.stats()["open"] == 2


def test_rules_status_and_cursor(repo):
    repo.save_settings(
        {}, [{"id": "failed_logins", "enabled": False, "threshold": 5, "window_seconds": 60}]
    )
    for i in range(5):
        repo.ingest(event(i))
    assert repo.stats()["open"] == 0
    result = repo.ingest(event(6, event_id=1102), {"record_id": 6})
    assert result["severity"] == "High"
    assert repo.setting("event_cursor")["record_id"] == 6
    repo.set_status(result["id"], "Resolved")
    assert repo.stats()["open"] == 0
    with pytest.raises(ValueError):
        repo.set_status(result["id"], "invalid")
    with pytest.raises(ValueError):
        repo.set_status(999, "Open")


def test_transaction_rollback(repo, monkeypatch):
    def fail(*args):
        raise RuntimeError("simulated detector failure")

    monkeypatch.setattr("app.database.repository.analyze", fail)
    with pytest.raises(RuntimeError):
        repo.ingest(event(1), {"record_id": 1})
    assert repo.stats()["events"] == 0
    assert repo.setting("event_cursor") is None


def test_retention_cascades(repo):
    for i in range(5):
        repo.ingest(event(i))
    repo.cleanup(1)
    assert repo.stats()["events"] == 0
    assert repo.stats()["open"] == 0
    with repo.session() as session:
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 0


def test_parse_xml():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.1234567Z"/><EventRecordID>8</EventRecordID><Computer>PC</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">-</Data></EventData></Event>"""
    parsed = parse_event(xml)
    assert parsed.event_id == 4625
    assert parsed.record_id == 8
    assert parsed.username == "alice"
    assert parsed.ip_address == ""
    with pytest.raises(ParseError):
        parse_event("broken")


def test_reports(tmp_path):
    rows = [{"username": "=1+1", "count": 5}]
    export_report(tmp_path / "report.json", rows)
    assert json.loads((tmp_path / "report.json").read_text()) == rows
    export_report(tmp_path / "report.csv", rows)
    assert "'=1+1" in (tmp_path / "report.csv").read_text(encoding="utf-8-sig")


def test_missing_process_data(repo, monkeypatch):
    from app.collectors import processes

    class Fake:
        def is_running(self):
            return True

        def as_dict(self, **kwargs):
            return {
                "pid": 10,
                "name": "system",
                "exe": None,
                "create_time": None,
                "username": None,
                "cpu_percent": None,
                "memory_info": None,
            }

    monkeypatch.setattr(processes.psutil, "process_iter", lambda: [Fake()])
    monkeypatch.setattr(processes, "collect_connections", lambda: ({}, "denied"))
    rows, warning = processes.collect_processes()
    repo.save_processes(rows)
    assert warning == "denied"
    assert rows[0]["memory_bytes"] is None
    with repo.session() as session:
        assert session.scalar(select(ProcessSnapshot)).pid == 10
