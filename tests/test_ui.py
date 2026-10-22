import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from app.database.repository import Repository
from app.services.monitor import seed_demo
from app.ui.window import MainWindow


def test_navigation_and_incident_status(tmp_path):
    app = QApplication.instance() or QApplication([])
    repo = Repository(tmp_path / "ui.db")
    seed_demo(repo)
    window = MainWindow(repo, demo=True, start_worker=False)
    window.show()
    for i in range(5):
        window.navigate(i)
        app.processEvents()
        assert window.stack.currentIndex() == i
    window.navigate(3)
    window.incidents.grid.selectRow(0)
    window.incidents.status.setCurrentText("Resolved")
    window.incidents.save()
    assert repo.incidents()[0]["status"] == "Resolved"
    window.incidents.comment.setText("Проверка нового комментария")
    window.incidents.add_comment()
    assert "Проверка нового комментария" in window.incidents.text.toPlainText()
    window.incidents.status.setCurrentText("FalsePositive")
    window.incidents.save()
    assert repo.incidents()[0]["status"] == "FalsePositive"
    window.close()
    repo.engine.dispose()


def test_worker_does_not_block_ui(tmp_path, monkeypatch):
    import time

    from PyQt6.QtCore import QTimer

    from app.ui.window import Worker

    app = QApplication.instance() or QApplication([])
    repo = Repository(tmp_path / "worker.db")
    worker = Worker(repo, True)

    def slow_tick():
        time.sleep(0.25)
        return {}

    monkeypatch.setattr(worker.monitor, "tick", slow_tick)
    beats = []
    timer = QTimer()
    timer.timeout.connect(lambda: beats.append(1))
    timer.start(10)
    worker.start()
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    worker.requestInterruption()
    assert worker.wait(2000)
    timer.stop()
    assert len(beats) >= 5
    repo.engine.dispose()
