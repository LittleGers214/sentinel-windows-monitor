"""Render our own Qt widgets offscreen and benchmark the 10k-event dashboard."""

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import QApplication

from app.database.models import SecurityEvent, utcnow
from app.database.repository import Repository
from app.services.monitor import Monitor, seed_demo
from app.ui.window import MainWindow


def main():
    app = QApplication([])
    fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    for font in ("segoeui.ttf", "segoeuib.ttf", "seguisym.ttf"):
        QFontDatabase.addApplicationFont(str(fonts / font))
    output = Path("artifacts")
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        repo = Repository(Path(folder) / "preview.db")
        seed_demo(repo)
        snapshot = Monitor(repo, demo=True).tick()
        window = MainWindow(repo, demo=True, start_worker=False)
        window.refresh(snapshot)
        window.show()
        app.processEvents()
        for index, name in enumerate(["dashboard", "events", "processes", "incidents", "settings"]):
            window.navigate(index)
            app.processEvents()
            window.grab().save(str(output / f"{name}.png"))
        window.close()
        now = utcnow()
        with repo.session.begin() as session:
            session.add_all(
                [
                    SecurityEvent(
                        record_id=1000 + i,
                        event_id=4624,
                        timestamp=now,
                        source="BENCH",
                        username="test",
                        ip_address="",
                        channel="Security",
                        raw_data="",
                    )
                    for i in range(10000)
                ]
            )
        start = time.perf_counter()
        window = MainWindow(repo, start_worker=False)
        window.show()
        app.processEvents()
        elapsed = time.perf_counter() - start
        print(f"Dashboard construction + first paint, 10056 events: {elapsed:.3f}s")
        window.close()
        repo.engine.dispose()


if __name__ == "__main__":
    main()
