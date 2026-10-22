import json
from datetime import UTC, datetime

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from app.ui.widgets import fill, label, table


class Processes(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(
            label(
                "CPU процесса может превышать 100% на нескольких ядрах. «—» означает отсутствие доступа.",
                "muted",
            )
        )
        self.grid = table(
            ["PID", "Процесс", "CPU %", "RAM МБ", "Владелец", "Запуск UTC", "Путь", "Соединения"]
        )
        layout.addWidget(self.grid)

    def refresh(self, snapshot):
        rows = []
        for r in snapshot["processes"]:
            connections = json.loads(r["connections"])
            rows.append(
                (
                    r["pid"],
                    r["process_name"],
                    r["cpu_percent"],
                    round(r["memory_bytes"] / 1048576, 1)
                    if r["memory_bytes"] is not None
                    else None,
                    r["username"],
                    datetime.fromtimestamp(r["started_at"], UTC).strftime("%d.%m %H:%M:%S")
                    if r["started_at"]
                    else None,
                    r["executable_path"],
                    "; ".join(f"{c['local']} → {c['remote']} ({c['status']})" for c in connections)
                    if connections is not None
                    else None,
                )
            )
        fill(self.grid, rows)
