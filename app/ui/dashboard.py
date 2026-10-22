from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QProgressBar, QVBoxLayout, QWidget

from app.ui.widgets import fill, label, table


class Trend(QWidget):
    def __init__(self):
        super().__init__()
        self.values = [0] * 12
        self.setMinimumHeight(100)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = self.width() / 12
        maximum = max(max(self.values), 1)
        for i, value in enumerate(self.values):
            height = max(3, int(value / maximum * (self.height() - 28)))
            painter.setBrush(QColor("#548bfa" if value else "#2a3850"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(
                int(i * width + 5), self.height() - height - 22, int(width - 10), height, 3, 3
            )
            painter.setPen(QColor("#8fa2bf"))
            painter.drawText(
                QRectF(i * width, self.height() - 22, width, 22),
                Qt.AlignmentFlag.AlignCenter,
                f"−{11 - i}ч" if i != 11 else "Сейчас",
            )
        painter.end()


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        cards = QHBoxLayout()
        self.metrics = {}
        for key, title, subtitle in [
            ("events", "СОБЫТИЯ", "В локальной базе"),
            ("open", "ИНЦИДЕНТЫ", "Требуют рассмотрения"),
            ("processes", "ПРОЦЕССЫ", "Последний снимок"),
            ("high", "ВЫСОКИЙ РИСК", "Открытые инциденты"),
        ]:
            card = QFrame(objectName="card")
            box = QVBoxLayout(card)
            box.setContentsMargins(20, 18, 20, 18)
            box.addWidget(label(title, "muted"))
            self.metrics[key] = label("—", "metric")
            box.addWidget(self.metrics[key])
            box.addWidget(label(subtitle, "muted"))
            cards.addWidget(card)
        layout.addLayout(cards)
        resources = QHBoxLayout()
        self.resources = {}
        for key, title in [("cpu", "CPU"), ("memory", "Память"), ("disk", "Диск")]:
            frame = QFrame(objectName="card")
            box = QVBoxLayout(frame)
            title_label = label(title, "section")
            bar = QProgressBar()
            bar.setTextVisible(False)
            box.addWidget(title_label)
            box.addWidget(bar)
            self.resources[key] = (title, title_label, bar)
            resources.addWidget(frame)
        layout.addLayout(resources)
        layout.addWidget(label("Динамика инцидентов · последние 12 часов", "section"))
        self.trend = Trend()
        layout.addWidget(self.trend)
        layout.addWidget(label("Последние инциденты", "section"))
        self.recent = table(["Время UTC", "Правило", "Риск", "События", "Статус"])
        layout.addWidget(self.recent, 1)
        layout.addWidget(
            label("Диагностика источников · последнее обработанное событие / проверка", "section")
        )
        self.diagnostics = table(["Источник", "Состояние", "Время UTC / подробности"])
        self.diagnostics.setMaximumHeight(175)
        layout.addWidget(self.diagnostics)

    def refresh(self, snapshot):
        fill(self.diagnostics, snapshot.get("diagnostics", []))
        counts = dict(snapshot["stats"], processes=len(snapshot["processes"]))
        for key, widget in self.metrics.items():
            widget.setText(f"{counts[key]:,}".replace(",", " "))
        for key, (title, widget, bar) in self.resources.items():
            widget.setText(f"{title}     {snapshot[key]:.1f}%")
            bar.setValue(round(snapshot[key]))
        self.trend.values = counts["trend"]
        self.trend.update()
        fill(
            self.recent,
            [
                (
                    r["last_seen"].strftime("%d.%m %H:%M:%S"),
                    r["title"],
                    r["severity"],
                    r["event_count"],
                    r["status"],
                )
                for r in snapshot["incidents"][:8]
            ],
        )
