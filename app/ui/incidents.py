from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.services.reports import export_report
from app.ui.widgets import fill, label, table


class Incidents(QWidget):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo
        self.rows = []
        layout = QVBoxLayout(self)
        layout.addWidget(
            label("Выберите инцидент для просмотра доказательств и изменения статуса", "muted")
        )
        self.grid = table(
            ["№", "Правило", "Риск", "Начало UTC", "Последнее UTC", "События", "Статус"]
        )
        self.grid.itemSelectionChanged.connect(self.details)
        layout.addWidget(self.grid, 3)
        bar = QHBoxLayout()
        self.status = QComboBox()
        self.status.addItems(["Open", "Investigating", "Resolved", "FalsePositive"])
        bar.addWidget(self.status)
        button = QPushButton("Сохранить статус")
        button.clicked.connect(self.save)
        bar.addWidget(button)
        bar.addStretch()
        layout.addLayout(bar)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text, 2)
        self.comment = QLineEdit()
        self.comment.setPlaceholderText("Комментарий аналитика (сохраняется отдельно от статуса)")
        layout.addWidget(self.comment)
        actions = QHBoxLayout()
        add = QPushButton("Добавить комментарий")
        add.clicked.connect(self.add_comment)
        actions.addWidget(add)
        export = QPushButton("Экспорт карточки JSON")
        export.clicked.connect(self.export)
        actions.addWidget(export)
        layout.addLayout(actions)

    def refresh(self):
        selected = self.selected()
        self.grid.blockSignals(True)
        self.rows = self.repo.incidents()
        fill(
            self.grid,
            [
                (
                    r["id"],
                    r["title"],
                    r["severity"],
                    r["first_seen"],
                    r["last_seen"],
                    r["event_count"],
                    r["status"],
                )
                for r in self.rows
            ],
        )
        if selected:
            for index, row in enumerate(self.rows):
                if row["id"] == selected["id"]:
                    self.grid.selectRow(index)
                    break
        self.grid.blockSignals(False)
        self.details()

    def selected(self):
        index = self.grid.currentRow()
        return self.rows[index] if 0 <= index < len(self.rows) else None

    def details(self):
        row = self.selected()
        if row:
            self.status.setCurrentText(row["status"])
            evidence = self.repo.evidence(row["id"])
            self.text.setPlainText(
                f"Инцидент #{row['id']} · {row['title']}\nРиск: {row['severity']} · Статус: {row['status']}\n\nДОКАЗАТЕЛЬСТВА\n"
                + "\n\n".join(
                    f"{e['timestamp']} | {e['event_id']} | {e['source']} | {e['username']} | IP: {e['ip_address'] or 'недоступен'}\n{e['raw_data']}"
                    for e in evidence
                )
                + "\n\nИСТОРИЯ РАССЛЕДОВАНИЯ\n"
                + "\n".join(f"{n['timestamp']} · {n['text']}" for n in self.repo.notes(row["id"]))
            )

    def add_comment(self):
        row = self.selected()
        if row:
            try:
                self.repo.add_note(row["id"], self.comment.text())
                self.comment.clear()
                self.details()
            except ValueError as exc:
                QMessageBox.warning(self, "Комментарий", str(exc))

    def export(self):
        row = self.selected()
        if row:
            path, _ = QFileDialog.getSaveFileName(
                self, "Карточка инцидента", f"incident-{row['id']}.json", "JSON (*.json)"
            )
            if path:
                try:
                    export_report(
                        path,
                        [
                            dict(
                                row,
                                evidence=self.repo.evidence(row["id"]),
                                notes=self.repo.notes(row["id"]),
                            )
                        ],
                    )
                except OSError as exc:
                    QMessageBox.warning(self, "Экспорт", str(exc))

    def save(self):
        row = self.selected()
        if row:
            self.repo.set_status(row["id"], self.status.currentText())
            self.refresh()
