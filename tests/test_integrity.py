import json

import pytest
from sqlalchemy import inspect

from app.collectors.integrity import scan_folder
from app.database.models import Base
from app.database.repository import Repository


def test_baseline_create_modify_delete_restart(tmp_path):
    folder = tmp_path / "watched"
    folder.mkdir()
    file = folder / "example.txt"
    file.write_text("first")
    repo = Repository(tmp_path / "db" / "test.db")
    root = str(folder)
    assert repo.apply_file_scan(root, scan_folder(root)) == []
    assert repo.stats()["open"] == 0
    file.write_text("second")
    alerts = repo.apply_file_scan(root, scan_folder(root))
    assert len(alerts) == 1
    evidence = json.loads(repo.evidence(alerts[0]["id"])[0]["raw_data"])
    assert evidence["old_sha256"] != evidence["new_sha256"]
    assert repo.apply_file_scan(root, scan_folder(root)) == []
    repo.engine.dispose()
    repo = Repository(tmp_path / "db" / "test.db")
    file.unlink()
    assert len(repo.apply_file_scan(root, scan_folder(root))) == 1
    file.write_text("new")
    assert len(repo.apply_file_scan(root, scan_folder(root))) == 1
    assert repo.stats()["open"] == 3
    repo.engine.dispose()


def test_failed_scan_does_not_delete_baseline(tmp_path, monkeypatch):
    from app.services.monitor import Monitor

    repo = Repository(tmp_path / "db" / "test.db")
    folder = tmp_path / "watched"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    root = str(folder)
    repo.apply_file_scan(root, scan_folder(root))
    repo.save_settings({"integrity_roots": [root]})

    def denied(_):
        raise PermissionError("denied")

    monkeypatch.setattr("app.services.monitor.scan_folder", denied)
    monkeypatch.setattr("app.services.monitor.collect_processes", lambda: ([], None))
    monitor = Monitor(repo, demo=True)
    snapshot = monitor.tick()
    assert "denied" in snapshot["diagnostics"][1][1]
    assert repo.stats()["open"] == 0
    assert repo.apply_file_scan(root, scan_folder(root)) == []
    repo.engine.dispose()


def test_notes_false_positive_and_compatibility(tmp_path):
    repo = Repository(tmp_path / "test.db")
    # Simulate the previous release: only the two new tables are absent.
    Base.metadata.tables["file_baselines"].drop(repo.engine)
    Base.metadata.tables["investigation_notes"].drop(repo.engine)
    repo.save_settings({"interval": 17})
    repo.engine.dispose()
    repo = Repository(tmp_path / "test.db")
    assert repo.setting("interval") == 17
    assert "investigation_notes" in inspect(repo.engine).get_table_names()
    repo.apply_file_scan("test", {})
    alert = repo.apply_file_scan("test", {"test/file": "digest"})[0]
    repo.add_note(alert["id"], "Проверено аналитиком")
    repo.set_status(alert["id"], "FalsePositive")
    assert len(repo.notes(alert["id"])) == 2
    assert repo.stats()["open"] == 0
    repo.set_status(alert["id"], "Investigating")
    assert repo.stats()["open"] == 1
    with pytest.raises(ValueError):
        repo.add_note(alert["id"], "   ")
    with pytest.raises(ValueError):
        repo.save_settings({"integrity_roots": [str(tmp_path)]})
    repo.engine.dispose()


def test_missing_folder(tmp_path):
    with pytest.raises(OSError):
        scan_folder(tmp_path / "missing")
