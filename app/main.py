import argparse
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.database.repository import Repository
from app.services.monitor import Monitor, seed_demo


def main():
    parser = argparse.ArgumentParser(description="Sentinel — Windows Security Monitor")
    parser.add_argument(
        "--demo", action="store_true", help="Separate database with synthetic events"
    )
    parser.add_argument("--console", action="store_true", help="Run without Qt")
    parser.add_argument("--once", action="store_true", help="One console collection cycle")
    parser.add_argument("--db", type=Path, help="Explicit SQLite file")
    args = parser.parse_args()
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Sentinel"
    if args.demo and args.db:
        parser.error("--demo uses a separate database; --db cannot be combined with --demo")
    path = args.db or base / ("demo.db" if args.demo else "sentinel.db")
    path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        handlers=[
            RotatingFileHandler(
                path.parent / "sentinel.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
            )
        ],
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    repo = Repository(path)
    if args.demo:
        seed_demo(repo)
    if args.console or args.once:
        monitor = Monitor(repo, args.demo)
        try:
            while True:
                snapshot = monitor.tick()
                print(
                    {
                        "stats": snapshot["stats"],
                        "warnings": snapshot["warnings"],
                        "alerts": snapshot["alerts"],
                    },
                    flush=True,
                )
                if args.once:
                    break
                time.sleep(repo.setting("interval", 5))
        except KeyboardInterrupt:
            pass
        finally:
            repo.engine.dispose()
    else:
        from PyQt6.QtWidgets import QApplication

        from app.ui.window import MainWindow

        app = QApplication([])
        window = MainWindow(repo, args.demo)
        window.show()
        app.exec()
        repo.engine.dispose()


if __name__ == "__main__":
    main()
