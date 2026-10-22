from app.collectors.windows_events import WindowsEvents
from app.database.repository import Repository
from app.services.monitor import Monitor


def xml(record, time="2026-01-01T00:00:00Z"):
    return f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="{time}"/><EventRecordID>{record}</EventRecordID><Computer>PC</Computer></System></Event>'


def test_cursor_reset_and_bad_record():
    reader = object.__new__(WindowsEvents)
    queries = []

    def query(xpath, **kwargs):
        queries.append(xpath)
        return [] if len(queries) == 1 else ["bad", xml(1)]

    reader._query = query
    rows = reader.poll({"record_id": 900, "timestamp": "2025-12-01T00:00:00"})
    assert "EventRecordID>0" in queries[1]
    assert len(rows) == 1
    assert rows[0][1]["record_id"] == 1


def test_resume_at_verified_record():
    reader = object.__new__(WindowsEvents)
    queries = []

    def query(xpath, **kwargs):
        queries.append(xpath)
        return [xml(10)] if len(queries) == 1 else [xml(11)]

    reader._query = query
    rows = reader.poll({"record_id": 10, "timestamp": "2026-01-01T00:00:00"})
    assert "EventRecordID>10" in queries[1]
    assert rows[0][0].record_id == 11


def test_monitor_survives_denied_log(tmp_path, monkeypatch):
    repo = Repository(tmp_path / "monitor.db")

    class Denied:
        def poll(self, cursor):
            raise PermissionError("denied")

    monitor = Monitor(repo)
    monitor.collector = Denied()
    monkeypatch.setattr("app.services.monitor.collect_processes", lambda: ([], None))
    snapshot = monitor.tick()
    assert "denied" in snapshot["warnings"][0]
    assert snapshot["stats"]["events"] == 0
    repo.engine.dispose()
