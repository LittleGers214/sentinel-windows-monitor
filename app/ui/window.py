import logging

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from app.services.alerts import alert_text
from app.services.monitor import Monitor
from app.ui.dashboard import Dashboard
from app.ui.events import Events
from app.ui.incidents import Incidents
from app.ui.processes import Processes
from app.ui.settings import Settings
from app.ui.widgets import STYLE, label


class Worker(QThread):
    snapshot = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, repo, demo):
        super().__init__()
        self.repo = repo
        self.monitor = Monitor(repo, demo)

    def run(self):
        while not self.isInterruptionRequested():
            try:
                self.snapshot.emit(self.monitor.tick())
            except Exception as exc:
                logging.getLogger(__name__).exception("Collection cycle failed")
                self.failed.emit(str(exc))
            for _ in range(self.repo.setting("interval", 5) * 10):
                if self.isInterruptionRequested():
                    return
                self.msleep(100)


class MainWindow(QMainWindow):
    def __init__(self, repo, demo=False, start_worker=True):
        super().__init__()
        self.repo = repo
        self.demo = demo
        self.closing = False
        self.setWindowTitle("Sentinel — Windows Security Monitor" + (" [DEMO]" if demo else ""))
        self.resize(1360, 860)
        self.setMinimumSize(1080, 700)
        self.setStyleSheet(STYLE)
        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        sidebar = QFrame(objectName="sidebar")
        sidebar.setFixedWidth(225)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(18, 28, 18, 20)
        nav.setSpacing(10)
        nav.addWidget(label("◈  SENTINEL", "brand"))
        nav.addWidget(label("WINDOWS SECURITY MONITOR", "muted"))
        nav.addSpacing(35)
        nav.addWidget(label("РАБОЧЕЕ ПРОСТРАНСТВО", "muted"))
        self.buttons = []
        for index, title in enumerate(
            ["◫   Dashboard", "≡   Events", "▤   Processes", "◇   Incidents", "⚙   Settings"]
        ):
            button = QPushButton(title, objectName="nav")
            button.setCheckable(True)
            button.clicked.connect(lambda checked, i=index: self.navigate(i))
            self.buttons.append(button)
            nav.addWidget(button)
        nav.addStretch()
        nav.addWidget(label("●  Локальное хранение", "status"))
        nav.addWidget(label("Sentinel 0.1 · Windows 10 / 11", "muted"))
        shell.addWidget(sidebar)
        content = QVBoxLayout()
        content.setContentsMargins(30, 25, 30, 20)
        content.setSpacing(15)
        self.title = label("Обзор безопасности", "title")
        content.addWidget(self.title)
        content.addWidget(label("События, процессы и инциденты вашего компьютера", "muted"))
        self.health = label(
            "DEMO · события синтетические, процессы реальные"
            if demo
            else "Подключение к локальным источникам…",
            "status",
        )
        self.health.setWordWrap(True)
        content.addWidget(self.health)
        self.stack = QStackedWidget()
        self.dashboard = Dashboard()
        initial_stats = repo.stats()
        for key in ("events", "open", "high"):
            self.dashboard.metrics[key].setText(str(initial_stats[key]))
        self.dashboard.trend.values = initial_stats["trend"]
        self.events = Events(repo)
        self.processes = Processes()
        self.incidents = Incidents(repo)
        self.settings = Settings(repo)
        for page in [self.dashboard, self.events, self.processes, self.incidents, self.settings]:
            self.stack.addWidget(page)
        content.addWidget(self.stack, 1)
        content.addWidget(
            label(
                "Данные безопасности могут содержать имена пользователей и IP-адреса · время в UTC",
                "muted",
            )
        )
        shell.addLayout(content, 1)
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor("#4e8cff"))
        self.setWindowIcon(QIcon(pixmap))
        self.tray = QSystemTrayIcon(self.windowIcon(), self)
        self.tray.setToolTip("Sentinel")
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()
        self.worker = Worker(repo, demo)
        self.worker.snapshot.connect(self.refresh)
        self.worker.failed.connect(lambda message: self.health.setText("Ошибка сбора: " + message))
        self.worker.finished.connect(self.finish_close)
        self.navigate(0)
        if start_worker:
            self.worker.start()

    def navigate(self, index):
        self.stack.setCurrentIndex(index)
        self.title.setText(
            [
                "Обзор безопасности",
                "Журнал событий",
                "Активные процессы",
                "Расследование инцидентов",
                "Настройки мониторинга",
            ][index]
        )
        for i, button in enumerate(self.buttons):
            button.setChecked(i == index)
        if index == 1:
            self.events.refresh()
        elif index == 3:
            self.incidents.refresh()

    def refresh(self, snapshot):
        self.dashboard.refresh(snapshot)
        self.processes.refresh(snapshot)
        if self.stack.currentIndex() == 1:
            self.events.refresh()
        # Incident evidence remains stable while the user investigates; refresh on navigation.
        prefix = "DEMO · синтетические события / реальные процессы. " if self.demo else ""
        self.health.setText(
            prefix
            + (" | ".join(snapshot["warnings"]) or "●  Сбор активен · последнее обновление успешно")
        )
        self.health.setStyleSheet("color:#efbd68;" if snapshot["warnings"] else "color:#58dca8;")
        if self.repo.setting("notifications", True) and not self.demo:
            for alert in snapshot["alerts"][:5]:
                self.tray.showMessage("Sentinel", alert_text(alert))

    def closeEvent(self, event):
        if self.worker.isRunning():
            self.closing = True
            self.worker.requestInterruption()
            self.health.setText("Завершение текущего цикла сбора…")
            event.ignore()
        else:
            self.tray.hide()
            event.accept()

    def finish_close(self):
        if self.closing:
            self.close()
