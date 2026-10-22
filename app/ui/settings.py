from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.ui.widgets import label


class Settings(QWidget):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.interval, self.retention = QSpinBox(), QSpinBox()
        self.interval.setRange(1, 300)
        self.interval.setValue(repo.setting("interval", 5))
        self.interval.setSuffix(" сек")
        self.retention.setRange(1, 3650)
        self.retention.setValue(repo.setting("retention_days", 30))
        self.retention.setSuffix(" дней")
        self.notifications = QCheckBox("Локальные уведомления в системном трее")
        self.notifications.setChecked(repo.setting("notifications", True))
        form.addRow("Интервал опроса", self.interval)
        form.addRow("Хранение истории", self.retention)
        form.addRow(self.notifications)
        layout.addLayout(form)
        layout.addWidget(label("Контроль целостности · SHA-256 · опрос раз в минуту", "section"))
        self.roots = QPlainTextEdit()
        self.roots.setPlaceholderText(
            "Папки наблюдения — по одной на строку. Пустой список отключает контроль."
        )
        self.roots.setPlainText("\n".join(repo.setting("integrity_roots", [])))
        self.roots.setMaximumHeight(70)
        layout.addWidget(self.roots)
        choose = QPushButton("Добавить папку…")
        choose.clicked.connect(self.choose_folder)
        layout.addWidget(choose)
        layout.addWidget(
            label(
                "Первое сканирование создаёт эталон без тревог. Последующие изменения создают инциденты.",
                "muted",
            )
        )
        layout.addWidget(label("Правила обнаружения", "section"))
        self.rules = []
        for rule in repo.rules():
            bar = QHBoxLayout()
            enabled = QCheckBox(rule["name"])
            enabled.setChecked(rule["enabled"])
            bar.addWidget(enabled, 1)
            threshold, window = QSpinBox(), QSpinBox()
            threshold.setRange(1, 10000)
            threshold.setValue(rule["threshold"])
            window.setRange(1, 86400)
            window.setValue(rule["window_seconds"])
            window.setSuffix(" сек")
            if rule["id"] == "failed_logins":
                bar.addWidget(QLabel("Порог"))
                bar.addWidget(threshold)
                bar.addWidget(QLabel("Окно"))
                bar.addWidget(window)
            self.rules.append((rule["id"], enabled, threshold, window))
            layout.addLayout(bar)
        layout.addWidget(
            label(
                "4672 — контекстное событие, само по себе не означает компрометацию.\nУдаление старой истории выполняется раз в час. Данные остаются на этом компьютере.",
                "muted",
            )
        )
        save = QPushButton("Сохранить настройки", objectName="primary")
        save.clicked.connect(self.save)
        layout.addWidget(save)
        self.feedback = label("", "status")
        layout.addWidget(self.feedback)
        layout.addStretch()

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Папка для контроля целостности")
        if path:
            self.roots.appendPlainText(path)

    def save(self):
        try:
            self.persist()
        except ValueError as exc:
            QMessageBox.warning(self, "Настройки", str(exc))

    def persist(self):
        self.repo.save_settings(
            {
                "interval": self.interval.value(),
                "retention_days": self.retention.value(),
                "notifications": self.notifications.isChecked(),
                "integrity_roots": self.roots.toPlainText().splitlines(),
            },
            [
                {
                    "id": key,
                    "enabled": enabled.isChecked(),
                    "threshold": threshold.value(),
                    "window_seconds": window.value(),
                }
                for key, enabled, threshold, window in self.rules
            ],
        )
        self.feedback.setText("Сохранено. Изменения применятся к следующему циклу сбора.")
