from datetime import timedelta

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.database.models import utcnow
from app.detection.rules import EVENT_NAMES
from app.services.reports import export_report
from app.ui.widgets import fill, label, table


class Events(QWidget):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo
        self.rows = []
        layout = QVBoxLayout(self)
        filters = QHBoxLayout()
        self.period, self.kind, self.severity = QComboBox(), QComboBox(), QComboBox()
        self.period.addItems(
            ["Всё время", "Последний час", "Последние 24 часа", "Последние 7 дней"]
        )
        self.kind.addItem("Все события", None)
        for event_id, name in EVENT_NAMES.items():
            self.kind.addItem(f"{event_id} · {name}", event_id)
        self.severity.addItems(["Любой риск", "High", "Medium", "Low"])
        for widget in [self.period, self.kind, self.severity]:
            filters.addWidget(widget)
            widget.currentIndexChanged.connect(self.refresh)
        export = QPushButton("Экспорт CSV / JSON")
        export.clicked.connect(self.export)
        filters.addWidget(export)
        layout.addLayout(filters)
        layout.addWidget(
            label(
                "Последние 500 совпадений · время UTC · двойной щелчок: исходное событие", "muted"
            )
        )
        self.grid = table(["Запись", "ID", "Время UTC", "Компьютер", "Учётная запись", "IP"])
        self.grid.cellDoubleClicked.connect(self.details)
        layout.addWidget(self.grid)

    def refresh(self):
        hours = [None, 1, 24, 168][self.period.currentIndex()]
        self.rows = self.repo.events(
            since=utcnow() - timedelta(hours=hours) if hours else None,
            event_id=self.kind.currentData(),
            severity=self.severity.currentText() if self.severity.currentIndex() else None,
        )
        fill(
            self.grid,
            [
                (
                    r["record_id"],
                    r["event_id"],
                    r["timestamp"],
                    r["source"],
                    r["username"],
                    r["ip_address"],
                )
                for r in self.rows
            ],
        )

    def details(self, row, _):
        from PyQt6.QtWidgets import QDialog, QTextEdit

        dialog = QDialog(self)
        dialog.setWindowTitle("Исходное событие")
        dialog.resize(800, 500)
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(self.rows[row]["raw_data"])
        layout.addWidget(text)
        dialog.exec()

    def export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт показанных событий", "events.json", "JSON (*.json);;CSV (*.csv)"
        )
        if path:
            try:
                export_report(path, self.rows)
            except OSError as exc:
                QMessageBox.warning(self, "Ошибка экспорта", str(exc))
