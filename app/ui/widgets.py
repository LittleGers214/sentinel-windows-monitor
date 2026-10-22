from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QLabel, QTableWidget, QTableWidgetItem


def label(text, kind=""):
    widget = QLabel(text)
    widget.setObjectName(kind)
    return widget


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    widget.verticalHeader().hide()
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    widget.setAlternatingRowColors(True)
    widget.setShowGrid(False)
    return widget


def fill(widget, rows):
    widget.setRowCount(len(rows))
    for row_index, row in enumerate(rows):
        for col, value in enumerate(row):
            item = QTableWidgetItem("—" if value is None else str(value))
            item.setToolTip(item.text())
            item.setData(Qt.ItemDataRole.UserRole, value)
            widget.setItem(row_index, col, item)


STYLE = """
QWidget { background:#101724; color:#dce5f3; font-family:'Segoe UI'; font-size:13px; }
QMainWindow { background:#101724; }
QFrame#sidebar { background:#0b1220; border-right:1px solid #263247; }
QLabel { background:transparent; }
QLabel#brand { font-size:25px; font-weight:700; color:#80aaff; }
QLabel#title { font-size:27px; font-weight:700; }
QLabel#muted { color:#8796af; font-size:12px; }
QLabel#metric { font-size:36px; font-weight:700; color:#f0f5ff; }
QLabel#section { font-size:16px; font-weight:600; }
QLabel#status { color:#58dca8; }
QFrame#card { background:#192333; border:1px solid #2a374b; border-radius:12px; }
QPushButton { background:#202d42; border:1px solid #30425b; border-radius:7px; padding:9px 15px; }
QPushButton:hover { background:#2c4160; }
QPushButton:checked, QPushButton#primary { background:#2869e8; color:white; border:1px solid #397cf7; }
QPushButton#nav { text-align:left; padding:13px 18px; }
QTableWidget { background:#172131; alternate-background-color:#1b2739; border:1px solid #2a374b; border-radius:8px; selection-background-color:#284e80; }
QTableWidget::item { padding:8px; }
QHeaderView::section { background:#202c40; color:#9cacc3; padding:10px; border:0; }
QTableCornerButton::section { background:#202c40; border:0; }
QComboBox, QSpinBox, QTextEdit { background:#172131; border:1px solid #34445e; border-radius:6px; padding:7px; }
QProgressBar { background:#2d3a50; border:0; border-radius:4px; max-height:8px; }
QProgressBar::chunk { background:#4d92ff; border-radius:4px; }
QScrollArea { border:0; }
QCheckBox { spacing:9px; }
QToolTip { background:#26364f; color:white; border:1px solid #476187; }
"""
