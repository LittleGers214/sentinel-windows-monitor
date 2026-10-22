import logging
import os
import time
from datetime import timedelta

import psutil

from app.collectors.integrity import scan_folder
from app.collectors.processes import collect_processes
from app.collectors.windows_events import WindowsEvents
from app.database.models import EventData, utcnow
from app.detection.rules import EVENT_NAMES

log = logging.getLogger(__name__)


class Monitor:
    def __init__(self, repository, demo=False):
        self.repo = repository
        self.demo = demo
        self.collector = None
        self.last_cleanup = 0
        self.last_integrity = 0
        self.integrity_status = "Выключен"

    def tick(self):
        warnings, alerts = [], []
        diagnostics = []
        security_status = "DEMO: журнал не читается"
        if not self.demo:
            try:
                if self.collector is None:
                    self.collector = WindowsEvents()
                for data, cursor in self.collector.poll(self.repo.setting("event_cursor")):
                    if data.event_id in EVENT_NAMES:
                        alert = self.repo.ingest(data, cursor)
                        if alert:
                            alerts.append(alert)
                    else:
                        self.repo.save_settings({"event_cursor": cursor})
                security_status = "Доступен"
                latest = self.collector.latest_record()
                checkpoint = self.repo.setting("event_cursor")
                if latest and checkpoint:
                    gap = max(0, latest.record_id - checkpoint["record_id"])
                    security_status += f" · отставание по RecordID: {gap}"
            except Exception as exc:
                log.exception("Security log collection failed")
                warnings.append(f"Security недоступен: {exc}")
                security_status = (
                    f"Ошибка: {exc}. Проверьте службу Windows Event Log и права чтения Security."
                )
        cursor = self.repo.setting("event_cursor")
        diagnostics.append(
            ("Windows Security", security_status, cursor.get("timestamp", "—") if cursor else "—")
        )
        roots = self.repo.setting("integrity_roots", [])
        if roots and time.monotonic() - self.last_integrity >= 60:
            problems = []
            count = 0
            for root in roots:
                try:
                    files = scan_folder(root)
                    alerts.extend(self.repo.apply_file_scan(root, files))
                    count += len(files)
                except OSError as exc:
                    log.warning("File integrity scan failed: %s", exc)
                    problems.append(f"{root}: {exc}")
            self.integrity_status = (
                " | ".join(problems)
                if problems
                else f"Проверено файлов: {count} · {utcnow():%H:%M:%S} UTC"
            )
            self.last_integrity = time.monotonic()
        if not roots:
            self.integrity_status = "Выключен: выберите папку в Settings"
        diagnostics.append(("Целостность файлов", self.integrity_status, "Каждые 60 секунд"))
        rows, warning = collect_processes()
        if warning:
            warnings.append(warning)
        self.repo.save_processes(rows)
        diagnostics.append(
            ("Процессы / сеть", warning or f"Доступно процессов: {len(rows)}", str(utcnow()))
        )
        diagnostics.append(("SQLite", "Запись успешна", str(self.repo.engine.url.database)))
        if time.monotonic() - self.last_cleanup > 3600:
            self.repo.cleanup(self.repo.setting("retention_days", 30))
            self.last_cleanup = time.monotonic()
        return {
            "processes": rows,
            "warnings": warnings,
            "alerts": alerts,
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(os.path.abspath(os.sep)).percent,
            "stats": self.repo.stats(),
            "incidents": self.repo.incidents(),
            "diagnostics": diagnostics,
        }


def seed_demo(repository):
    if repository.stats()["events"]:
        return
    now = utcnow()
    for i in range(48):
        repository.ingest(
            EventData(
                i + 1,
                4624,
                now - timedelta(minutes=48 - i),
                "DEMO-PC",
                "LAB\\analyst",
                "192.0.2.10",
                "Demo event",
            )
        )
    for i in range(7):
        repository.ingest(
            EventData(
                100 + i,
                4625,
                now - timedelta(seconds=50 - i * 7),
                "DEMO-PC",
                "LAB\\operator",
                "192.0.2.24",
                "Demo failed login",
            )
        )
    repository.ingest(EventData(200, 1102, now, "DEMO-PC", "LAB\\admin", raw_data="Demo log clear"))
