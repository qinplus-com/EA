# -*- coding: utf-8 -*-
"""PyQt5 主界面：首页 / 技术检测 / 问卷评估 / 检测报告 / 历史对比"""
import logging
import os
import subprocess
import sys
import time
import webbrowser
from datetime import datetime

from PyQt5.QtCore import (Qt, QThread, pyqtSignal, QTimer, QPointF, QSize,
                          QUrl)
from PyQt5.QtGui import (QFont, QColor, QIcon, QPainter, QPen, QPixmap,
                         QDesktopServices, QFontMetrics, QTextOption)
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QStackedWidget, QListWidget, QListWidgetItem, QComboBox, QLineEdit,
    QProgressBar, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox,
    QRadioButton, QButtonGroup, QScrollArea, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QGroupBox, QSplitter,
    QCheckBox, QDialog, QFormLayout, QSizePolicy, QSpinBox, QPlainTextEdit,
    QTextBrowser,
    QSystemTrayIcon, QMenu, QApplication, QGridLayout,
)

from core.models import (STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_MANUAL,
                         STATUS_ERROR, STATUS_TEXT, LAYERS, layer_of, LAYER_DEVICE)
from core import engine, storage, report, baseline, config_loader
from core import appconfig, secret
from questionnaire.data import get_quiz_items, QUIZ_CATEGORIES, ANSWER_OPTIONS
import questionnaire.data as qd
from ui.help_content import HELP_HTML


def app_icon():
    """应用图标（兼容 PyInstaller onefile 解包目录）"""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    for name in ("icon.ico", "icon.png"):
        p = os.path.join(base, "assets", name)
        if os.path.exists(p):
            return QIcon(p)
    return QIcon()


def asset_path(rel):
    """assets/{rel} 的绝对路径（兼容 PyInstaller onefile 解包目录），不存在返回空串"""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(base, "assets", rel)
    return p if os.path.exists(p) else ""


def asset_icon(name):
    """导航/功能图标：assets/icons/{name}.png（缺失时返回空图标）"""
    p = asset_path(os.path.join("icons", "%s.png" % name))
    return QIcon(p) if p else QIcon()


def back_about_btn(page):
    """各功能页统一的「返回」按钮：回到启动时的关于界面"""
    b = QPushButton("返回")
    b.setObjectName("ghost")
    b.setCursor(Qt.PointingHandCursor)
    b.setToolTip("返回关于界面")
    b.clicked.connect(lambda: page.window()._goto_about_page())
    return b

STATUS_STYLE = {
    STATUS_PASS: ("#22c55e", "✓"), STATUS_FAIL: ("#ef4444", "✗"),
    STATUS_WARN: ("#f89800", "△"), STATUS_MANUAL: ("#8b5cf6", "?"),
    STATUS_ERROR: ("#6f8f7c", "!"),
}

QSS = """
QMainWindow, QWidget { background:#0b100d; color:#ffffff; }
QLabel { background:transparent; }
#nav { background:#070b09; }
#nav QListWidget { background:transparent; border:none; outline:none; }
#nav QListWidget::item { padding:12px 18px; margin:2px 8px; color:#9aa39c; outline:0; border:none; border-radius:8px; }
#nav QListWidget::item:selected { background:#223026; color:#ffffff; outline:0; border:none; border-radius:8px; }
#nav QListWidget::item:hover:!selected { color:#ffffff; background:#131b16; outline:0; border:none; border-radius:8px; }
QPushButton { background:transparent; color:#e7ede9; border:1px solid #314038; border-radius:8px; padding:9px 20px; }
QPushButton:hover { background:#1a211d; border-color:#2f9c3a; }
QPushButton:pressed { background:#141a16; }
QPushButton:disabled { background:transparent; color:#6d7871; border-color:#232c26; }
QPushButton#ghost { background:transparent; border:1px solid #314038; color:#c9d3cc; }
QPushButton#ghost:hover { background:#1a211d; color:#ffffff; border-color:#2f9c3a; }
QPushButton#ghost:disabled { background:transparent; color:#5c6660; border-color:#232c26; }
QComboBox, QLineEdit, QSpinBox { background:#131b16; border:1px solid #26312a; border-radius:6px; padding:5px 10px; color:#ffffff; }
QComboBox { padding-right:24px; }
QComboBox::drop-down { subcontrol-position:center right; width:20px; border:none; background:transparent; }
__COMBO_ARROW_DARK__
QComboBox:focus, QLineEdit:focus, QSpinBox:focus { border:1px solid #2f9c3a; }
QComboBox QAbstractItemView { background:#131b16; color:#ffffff; selection-background-color:#2f9c3a; selection-color:#ffffff; border:none; }
QProgressBar { background:#131b16; border:none; border-radius:7px; height:14px; text-align:center; color:#ffffff; }
QProgressBar::chunk { background:#2f9c3a; border-radius:7px; }
QTreeWidget, QTableWidget, QListWidget { background:#0f1512; border:none; border-radius:8px; gridline-color:#161e19; }
QHeaderView::section { background:#131b16; color:#c9d3cc; padding:8px; border:none; }
QGroupBox { border:none; margin-top:14px; padding-top:14px; font-weight:bold; color:#c9d3cc; }
QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 6px; background:#0b100d; }
QGroupBox#plainBox { margin-top:0; padding-top:4px; font-weight:normal; }
QRadioButton { padding:4px 8px; spacing:6px; }
QCheckBox { spacing:6px; }
QScrollBar:vertical { background:transparent; width:10px; border-radius:5px; }
QScrollBar::handle:vertical { background:#232c26; border-radius:5px; min-height:24px; }
QScrollBar::handle:vertical:hover { background:#314038; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QLabel#hero { font-size:26px; font-weight:800; color:#ffffff; border:none; }
QLabel#sub { color:#9aa39c; border:none; }
QLabel#muted { color:#9aa39c; border:none; }
QLabel#pageTitle { font-size:18px; font-weight:800; color:#ffffff; border:none; }
QLabel#pageSub { color:#9aa39c; border:none; }
QLabel#noticeBar { background:#121712; color:#b9a67a; padding:7px 18px; }
QFrame#flow { background:#111814; border:none; border-radius:8px; }
QLabel#flowText { color:#9aa39c; }
QLabel#statCard { background:#111814; border:none; border-radius:8px; color:#ffffff; padding:8px 12px; }
QPushButton#aboutLink { background:transparent; border:none; color:#9aa39c; text-align:left;
    padding:9px 18px 3px 18px; min-height:20px; }
QPushButton#aboutLink:hover { color:#ffffff; }
QScrollArea { border:none; }
QPlainTextEdit { background:#0f1512; border:none; border-radius:8px; color:#ffffff; padding:8px; }
QFrame#scopeCard { background:transparent; border:1px solid #26312a; border-radius:10px; }
QFrame#scopeCard:hover { border-color:#2f9c3a; }
QFrame#scopeCard[selected="true"] { background:transparent; border:2px solid #2f9c3a; }
QFrame#scopeCard QLabel#cardIcon { font-size:24px; background:transparent; border:none; }
QFrame#scopeCard QLabel#cardTitle { font-weight:700; color:#ffffff; background:transparent; border:none; }
QFrame#scopeCard QLabel#cardTip { color:#9aa39c; background:transparent; border:none; }
QFrame#scopeCard[selected="true"] QLabel#cardTitle { color:#7bc043; }
QFrame#scopeCard[selected="true"] QLabel#cardTip { color:#c9d3cc; }
QLabel#badge { background:#141c17; color:#c9d3cc; border:none; border-radius:12px; padding:6px 14px; }
QFrame#panel { background:#111814; border:none; border-radius:8px; }
QLabel#verLine { color:#7bc043; font-weight:600; border:none; }
QFrame#featCard { background:#0f1512; border:none; border-radius:10px; }
QFrame#featCard QLabel#featTitle { font-weight:700; color:#ffffff; background:transparent; border:none; }
QFrame#featCard QLabel#featDesc { color:#9aa39c; background:transparent; border:none; }
QFrame#quizItem { background:transparent; border:1px solid #26312a; border-radius:8px; }
QTextBrowser { background:#0f1512; color:#ffffff; border:none; padding:16px; }
QToolTip { background:#141c17; color:#ffffff; border:none; }
QCheckBox::indicator, QRadioButton::indicator { width:14px; height:14px; background:#131b16; border:none; }
QCheckBox::indicator { border-radius:4px; }
QRadioButton::indicator { border-radius:7px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background:#2f9c3a; }
"""

# 亮色主题：排版尺寸与暗色保持一致，仅覆盖颜色相关属性
LIGHT_QSS = """
QMainWindow, QWidget { background:#ffffff; color:#111111; }
QLabel { background:transparent; }
#nav { background:#f5f7f5; }
#nav QListWidget { background:transparent; border:none; outline:none; }
#nav QListWidget::item { padding:12px 18px; margin:2px 8px; color:#5f6b62; outline:0; border:none; border-radius:8px; }
#nav QListWidget::item:selected { background:#e6ebe7; color:#111111; outline:0; border:none; border-radius:8px; }
#nav QListWidget::item:hover:!selected { color:#111111; background:#e9efe9; outline:0; border:none; border-radius:8px; }
QPushButton { background:transparent; color:#111111; border:1px solid #c4cfc7; border-radius:8px; padding:9px 20px; }
QPushButton:hover { background:#f0f4f1; border-color:#2f9c3a; }
QPushButton:pressed { background:#e6ece8; }
QPushButton:disabled { background:transparent; color:#9aa39c; border-color:#e3e8e4; }
QPushButton#ghost { background:transparent; border:1px solid #c4cfc7; color:#333333; }
QPushButton#ghost:hover { background:#f0f4f1; color:#111111; border-color:#2f9c3a; }
QPushButton#ghost:disabled { background:transparent; color:#a4aea7; border-color:#e3e8e4; }
QComboBox, QLineEdit, QSpinBox { background:#ffffff; border:1px solid #dbe3dd; border-radius:6px; padding:5px 10px; color:#111111; }
QComboBox { padding-right:24px; }
QComboBox::drop-down { subcontrol-position:center right; width:20px; border:none; background:transparent; }
__COMBO_ARROW_LIGHT__
QComboBox:focus, QLineEdit:focus, QSpinBox:focus { border:1px solid #2f9c3a; }
QComboBox QAbstractItemView { background:#ffffff; color:#111111; selection-background-color:#2f9c3a; selection-color:#ffffff; border:none; }
QProgressBar { background:#ecf0ed; border:none; border-radius:7px; height:14px; text-align:center; color:#111111; }
QProgressBar::chunk { background:#2f9c3a; border-radius:7px; }
QTreeWidget, QTableWidget, QListWidget { background:#ffffff; border:none; border-radius:8px; gridline-color:#eef0ee; }
QHeaderView::section { background:#f5f7f5; color:#333333; padding:8px; border:none; }
QGroupBox { border:none; margin-top:14px; padding-top:14px; font-weight:bold; color:#333333; }
QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 6px; background:#ffffff; }
QGroupBox#plainBox { margin-top:0; padding-top:4px; font-weight:normal; }
QRadioButton { padding:4px 8px; spacing:6px; }
QCheckBox { spacing:6px; }
QScrollBar:vertical { background:transparent; width:10px; border-radius:5px; }
QScrollBar::handle:vertical { background:#d5ddd7; border-radius:5px; min-height:24px; }
QScrollBar::handle:vertical:hover { background:#bcc9bf; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QLabel#hero { font-size:26px; font-weight:800; color:#111111; border:none; }
QLabel#sub { color:#5f6b62; border:none; }
QLabel#muted { color:#5f6b62; border:none; }
QLabel#pageTitle { font-size:18px; font-weight:800; color:#111111; border:none; }
QLabel#pageSub { color:#5f6b62; border:none; }
QLabel#noticeBar { background:#fbf5e6; color:#7a6428; padding:7px 18px; }
QFrame#flow { background:#f5f7f5; border:none; border-radius:8px; }
QLabel#flowText { color:#5f6b62; }
QLabel#statCard { background:#ffffff; border:none; border-radius:8px; color:#111111; padding:8px 12px; }
QPushButton#aboutLink { background:transparent; border:none; color:#5f6b62; text-align:left;
    padding:9px 18px 3px 18px; min-height:20px; }
QPushButton#aboutLink:hover { color:#111111; }
QScrollArea { border:none; }
QPlainTextEdit { background:#ffffff; border:none; border-radius:8px; color:#111111; padding:8px; }
QFrame#scopeCard { background:transparent; border:1px solid #dbe3dd; border-radius:10px; }
QFrame#scopeCard:hover { border-color:#2f9c3a; }
QFrame#scopeCard[selected="true"] { background:transparent; border:2px solid #2f9c3a; }
QFrame#scopeCard QLabel#cardIcon { font-size:24px; background:transparent; border:none; }
QFrame#scopeCard QLabel#cardTitle { font-weight:700; color:#111111; background:transparent; border:none; }
QFrame#scopeCard QLabel#cardTip { color:#5f6b62; background:transparent; border:none; }
QFrame#scopeCard[selected="true"] QLabel#cardTitle { color:#2f9c3a; }
QFrame#scopeCard[selected="true"] QLabel#cardTip { color:#333333; }
QLabel#badge { background:#f2f5f2; color:#333333; border:none; border-radius:12px; padding:6px 14px; }
QFrame#panel { background:#f5f7f5; border:none; border-radius:8px; }
QLabel#verLine { color:#2f9c3a; font-weight:600; border:none; }
QFrame#featCard { background:#f5f7f5; border:none; border-radius:10px; }
QFrame#featCard QLabel#featTitle { font-weight:700; color:#111111; background:transparent; border:none; }
QFrame#featCard QLabel#featDesc { color:#5f6b62; background:transparent; border:none; }
QFrame#quizItem { background:transparent; border:1px solid #dbe3dd; border-radius:8px; }
QTextBrowser { background:#ffffff; color:#111111; border:none; padding:16px; }
QToolTip { background:#f2f5f2; color:#111111; border:none; }
QCheckBox::indicator, QRadioButton::indicator { width:14px; height:14px; background:#eef1ee; border:none; }
QCheckBox::indicator { border-radius:4px; }
QRadioButton::indicator { border-radius:7px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background:#2f9c3a; }
"""


def _build_qss(theme):
    """生成主题样式表：把下拉箭头等运行时资源路径注入 QSS 占位符"""
    qss = LIGHT_QSS if theme == "light" else QSS
    p = asset_path(os.path.join(
        "icons", "arrow_down_l.png" if theme == "light" else "arrow_down_d.png"))
    if p:
        rule = ("QComboBox::down-arrow { image: url(%s); width:11px; height:7px; }"
                % p.replace("\\", "/"))
    else:  # 资源缺失时退化为仅缩小默认箭头
        rule = "QComboBox::down-arrow { width:9px; height:9px; }"
    return qss.replace("__COMBO_ARROW_DARK__", rule) \
              .replace("__COMBO_ARROW_LIGHT__", rule)


class _DbLogHandler(logging.Handler):
    """把 WARNING 及以上日志写入历史库（异常内部吞掉，不影响主流程）"""

    def __init__(self):
        super().__init__(logging.WARNING)
        self._last_msg = ""
        self._last_ts = 0.0

    def emit(self, record):
        try:
            msg = self.format(record)
            if appconfig.get("mask_secrets", True):
                msg = secret.sanitize(msg)
            # 简单去重：5 秒内同一条消息只写一次，避免重复错误刷爆库
            now = time.time()
            if msg == self._last_msg and now - self._last_ts < 5:
                return
            self._last_msg, self._last_ts = msg, now
            storage.add_log(record.levelname, msg[:1000])
        except Exception:
            pass


class ConnectWorker(QThread):
    """后台测试远程服务器连通性"""
    ok = pyqtSignal(str)
    fail = pyqtSignal(str)

    def __init__(self, conf):
        super().__init__()
        self.conf = dict(conf)

    def run(self):
        from core.remote import build_executor
        ex = build_executor(self.conf)
        try:
            ex.connect()
            self.ok.emit(ex.os_name())
        except Exception as e:
            self.fail.emit(str(e))
        finally:
            ex.close()


class CheckWorker(QThread):
    progress = pyqtSignal(int, int, str)
    item_done = pyqtSignal(object)
    finished_all = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, level, target, target_conf=None, layers=None, db_conf=None,
                 net_conf=None, mw_conf=None, app_conf=None):
        super().__init__()
        self.level = level
        self.target = target
        self.target_conf = target_conf or {"mode": "local"}
        self.layers = layers
        self.db_conf = db_conf or {}
        self.net_conf = net_conf or {}
        self.mw_conf = mw_conf or {}
        self.app_conf = app_conf or {}
        self._stop = False

    def run(self):
        from core.remote import build_executor
        ex = build_executor(self.target_conf)
        try:
            ex.connect()
            s = engine.run_all(
                self.level, self.target, executor=ex,
                on_item=lambda r: self.item_done.emit(r),
                on_progress=lambda c, t, n: self.progress.emit(c, t, n),
                should_stop=lambda: self._stop, layers=self.layers,
                db_conf=self.db_conf, net_conf=self.net_conf,
                mw_conf=self.mw_conf, app_conf=self.app_conf)
            self.finished_all.emit(s)
        except Exception as e:
            self.failed.emit(str(e))
        finally:
            ex.close()

    def stop(self):
        self._stop = True


class BatchRunWorker(QThread):
    """按顺序逐个运行 BatchTarget 列表中的目标"""
    item_started = pyqtSignal(int, int, str)  # index, total, name
    item_finished = pyqtSignal(int, object)    # index, RunSummary | None
    item_failed = pyqtSignal(int, str)         # index, error
    all_finished = pyqtSignal(list)            # list of (BatchTarget, RunSummary | None, error | None)

    def __init__(self, targets):
        super().__init__()
        self.targets = list(targets)
        self._stop = False

    def _run_netdev(self, t, note=""):
        """按网络设备直连核查（SSH/SNMP），仅执行网络与边界安全层"""
        from core.remote import LocalExecutor
        from core.models import LAYER_NET
        summary = engine.run_all(
            t.level, t.name, executor=LocalExecutor(),
            layers=[LAYER_NET], net_conf=t.as_net_conf())
        summary.note = note or "网络设备直连核查"
        return summary

    def _db_precheck(self, host, port):
        """数据库直连前先探测端口，给出明确失败原因（避免误测本机）"""
        import socket
        try:
            port = int(str(port or "").strip() or 0)
        except ValueError:
            port = 0
        if not host or not port:
            return
        try:
            with socket.create_connection((host, port), timeout=6):
                return
        except Exception as e:
            raise Exception("无法连接数据库 %s:%s（%s）。请检查 IP、端口、防火墙，"
                            "以及数据库是否允许远程连接。"
                            % (host, port, secret.sanitize(str(e))))

    def run(self):
        from core.remote import build_executor, LocalExecutor
        from core.models import LAYER_DB, LAYER_NET
        results = []
        total = len(self.targets)
        layer_db = LAYER_DB
        layer_net = LAYER_NET
        all_layers = config_loader.ALL_LAYERS
        for i, t in enumerate(self.targets):
            if self._stop:
                break
            self.item_started.emit(i, total, t.name)
            try:
                summary = None
                db_only = t.layers == [layer_db]
                if t.mode == "netdev":
                    summary = self._run_netdev(t)
                elif db_only and not (t.db_host or t.db_user or t.db_type):
                    # 新模板：仅检测「数据库安全」→ 直连数据库核查（IP+端口+数据库账号），
                    # 不走 SSH，更不会回退到本机全量检测
                    db_conf = t.as_db_conf_auto(db_only=True)
                    self._db_precheck(db_conf.get("host"), db_conf.get("port"))
                    summary = engine.run_all(
                        t.level, t.name, executor=build_executor({"mode": "local"}),
                        layers=t.layers, db_conf=db_conf)
                    summary.note = summary.note or "数据库直连核查"
                else:
                    ex = build_executor(t.as_target_conf())
                    try:
                        ex.connect()
                    except Exception as e:
                        msg = str(e)
                        # SSH 通道建立成功但拿不到 Linux shell：目标其实是防火墙/交换机 CLI
                        # 仅在检测范围包含网络层时才按网络设备核查，其余情况如实报错
                        if t.mode == "ssh" and ("远程命令无法执行" in msg or "SSH 通道已建立" in msg) \
                                and (layer_net in t.layers
                                     or len(t.layers) == len(all_layers)):
                            summary = self._run_netdev(
                                t, note="SSH 目标为网络设备，已按网络与边界安全层面核查")
                            ex = None
                        else:
                            raise
                    if ex is not None:
                        # 显式数据库列优先；新模板（无数据库专列）时从 IP 复用数据库主机
                        db_conf = t.as_db_conf()
                        if layer_db in t.layers and not db_conf:
                            db_conf = t.as_db_conf_auto(db_only=False)
                        try:
                            summary = engine.run_all(
                                t.level, t.name, executor=ex,
                                layers=t.layers, db_conf=db_conf,
                                net_conf=t.as_net_conf(), mw_conf=t.as_mw_conf(),
                                app_conf=t.as_app_conf())
                        finally:
                            ex.close()
                t.run_score = summary.score
                t.run_items = len(summary.results)
                t.run_result_id = summary.run_id
                self.item_finished.emit(i, summary)
                results.append((t, summary, None))
            except Exception as e:
                msg = str(e)
                t.run_error = msg
                self.item_failed.emit(i, msg)
                results.append((t, None, msg))
        self.all_finished.emit(results)

    def stop(self):
        self._stop = True


# ---------------- 可点击层面卡片 ----------------

class ScopeCard(QFrame):
    """单张可点击卡片：显示图标 + 层面名称 + 说明，有选中/未选中/hover 三种状态"""
    clicked = pyqtSignal(bool)  # 选中后发出

    def __init__(self, title, icon, tip, is_all=False, parent=None):
        super().__init__(parent)
        self.title = title
        self.icon = icon
        self.tip = tip
        self.is_all = is_all
        self._selected = False
        self.setObjectName("scopeCard")
        self.setFixedHeight(100)
        self.setMinimumWidth(110)
        self.setCursor(Qt.PointingHandCursor)
        self._build()
        self._apply_style()

    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(6, 8, 6, 8)
        v.setSpacing(2)
        self.icon_label = QLabel()
        self.icon_label.setObjectName("cardIcon")
        self.icon_label.setAlignment(Qt.AlignCenter)
        self._icon_size = 26
        icon_path = asset_path(os.path.join("icons", "%s.png" % self.icon))
        self._icon_path = icon_path
        if icon_path:
            self.icon_label.setPixmap(
                QPixmap(icon_path).scaled(self._icon_size, self._icon_size,
                                          Qt.KeepAspectRatio,
                                          Qt.SmoothTransformation))
        else:
            self.icon_label.setText(self.icon)
        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("cardTitle")
        self.title_label.setAlignment(Qt.AlignCenter)
        # 标题不换行（避免与图标/说明重叠），超长时省略
        self.title_label.setWordWrap(False)
        self.title_label.setTextInteractionFlags(Qt.NoTextInteraction)
        self.tip_label = QLabel(self.tip)
        self.tip_label.setObjectName("cardTip")
        self.tip_label.setAlignment(Qt.AlignCenter)
        self.tip_label.setWordWrap(False)
        v.addWidget(self.icon_label)
        v.addWidget(self.title_label)
        v.addWidget(self.tip_label)

    def apply_scale(self, width_hint):
        """按可用宽度自适应：卡片高度、图标随之缩放（文字统一使用系统字号）"""
        w = int(width_hint)
        if w >= 140:
            h, icon, margin = 88, 24, 8
        elif w >= 115:
            h, icon, margin = 80, 20, 6
        elif w >= 95:
            h, icon, margin = 74, 18, 5
        else:
            h, icon, margin = 66, 14, 4
        self.setFixedHeight(h)
        self.setMinimumWidth(max(64, w))
        if self._icon_path and icon != self._icon_size:
            self._icon_size = icon
            self.icon_label.setPixmap(
                QPixmap(self._icon_path).scaled(icon, icon, Qt.KeepAspectRatio,
                                                Qt.SmoothTransformation))
        self.layout().setContentsMargins(margin, 6, margin, 6)

    def set_selected(self, sel):
        self._selected = bool(sel)
        self._apply_style()

    def set_tip(self, tip):
        """动态更新卡片底部的 tip 文本（用于切换等保级别时刷新检测项数量）"""
        self.tip = tip
        self.tip_label.setText(tip)

    def is_selected(self):
        return self._selected

    def _apply_style(self):
        """选中状态交给 QSS 的属性选择器，自动适配暗色 / 亮色主题"""
        self.setProperty("selected", "true" if self._selected else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            # 单选语义：点击后始终选中（外部负责取消其它）
            self._selected = True
            self._apply_style()
            self.clicked.emit(True)
            event.accept()
        else:
            super().mousePressEvent(event)


# ---------------- 得分趋势图 ----------------

class TrendChart(QWidget):
    """得分趋势折线图：纯 QPainter 绘制，不引入额外图表依赖"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = []
        self.setMinimumHeight(130)
        self.setMaximumHeight(150)

    def set_data(self, rows):
        """rows: [(started, score, target), ...]，按时间正序"""
        self._data = list(rows or [])
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        text_color = self.palette().windowText().color()
        muted = QColor(text_color)
        muted.setAlpha(150)
        grid = QColor(text_color)
        grid.setAlpha(45)

        left, right, top, bottom = 46, 18, 18, 26
        pw = max(1, self.width() - left - right)
        ph = max(1, self.height() - top - bottom)
        painter.setFont(QFont(self.font().family(), 8))

        # 网格线 + Y 轴刻度（0~100）
        for i in range(5):
            value = i * 25
            y = top + ph - (value / 100.0) * ph
            painter.setPen(QPen(grid, 1))
            painter.drawLine(QPointF(left, y), QPointF(left + pw, y))
            painter.setPen(QPen(muted))
            painter.drawText(0, int(y) - 8, left - 10, 16,
                             Qt.AlignRight | Qt.AlignVCenter, str(value))

        if not self._data:
            painter.setPen(QPen(muted))
            painter.drawText(left, top, pw, ph, Qt.AlignCenter, "暂无数据")
            return

        n = len(self._data)
        points = []
        for i, (_started, score, _target) in enumerate(self._data):
            x = left + pw / 2 if n == 1 else left + i * pw / (n - 1)
            try:
                value = max(0.0, min(100.0, float(score)))
            except (TypeError, ValueError):
                value = 0.0
            y = top + ph - (value / 100.0) * ph
            points.append((x, y, value))

        line_color = QColor("#2f9c3a")
        painter.setPen(QPen(line_color, 2))
        for (x1, y1, _v1), (x2, y2, _v2) in zip(points, points[1:]):
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        painter.setBrush(line_color)
        painter.setPen(Qt.NoPen)
        for x, y, _v in points:
            painter.drawEllipse(QPointF(x, y), 3.5, 3.5)

        # 最新一次得分标注
        x, y, value = points[-1]
        label_x = min(int(x) + 8, left + pw - 52)
        painter.setPen(QPen(text_color))
        painter.drawText(label_x, int(y) - 9, 52, 16,
                         Qt.AlignLeft | Qt.AlignVCenter, "%.1f" % value)


# ---------------- 关于（应用首屏） ----------------

APP_NAME = "勤加等保测评助手"
APP_SHORT = "测评助手"
APP_EN = "Evaluation Assistant"
APP_VERSION = "V1.0"
APP_DEMO = "https://ea.qinplus.com"


class AboutPage(QWidget):
    """应用启动后的默认界面：产品介绍与在线演示入口"""

    def __init__(self, state):
        super().__init__()
        self.state = state
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        v = QVBoxLayout(inner)
        v.setContentsMargins(40, 32, 40, 24)
        v.setSpacing(12)

        logo_row = QHBoxLayout()
        logo = QLabel()
        ic = app_icon()
        if ic and not ic.isNull():
            logo.setPixmap(ic.pixmap(56, 56))
        logo_row.addWidget(logo)
        logo_row.addSpacing(14)
        names = QVBoxLayout()
        names.setSpacing(2)
        t1 = QLabel(APP_NAME)
        t1.setObjectName("hero")
        t2 = QLabel("简称：%s（%s）" % (APP_SHORT, APP_EN))
        t2.setObjectName("muted")
        names.addWidget(t1)
        names.addWidget(t2)
        logo_row.addLayout(names, 1)
        v.addLayout(logo_row)

        ver = QLabel("版本 %s　　适用等级：等保二级 / 三级（GB/T 22239-2019）" % APP_VERSION)
        ver.setObjectName("verLine")
        v.addWidget(ver)

        # 产品简介：卡片容器承载，与整体深色/亮色主题一致
        intro_box = QFrame()
        intro_box.setObjectName("panel")
        il = QVBoxLayout(intro_box)
        il.setContentsMargins(18, 14, 18, 14)
        intro = QLabel(
            "本产品面向企业等保自查场景，按《信息安全技术 网络安全等级保护基本要求》"
            "（GB/T 22239-2019）逐条落地检测项，覆盖安全物理环境、安全通信网络、安全区域边界、"
            "安全计算环境、安全管理中心，以及安全管理制度、管理机构、管理人员、建设管理和运维管理。"
            "技术类检查项自动取证，物理与管理类检查项以问卷评估方式人工核查，最终生成可交付的自查报告。")
        intro.setWordWrap(True)
        il.addWidget(intro)
        v.addWidget(intro_box)

        # 产品特性：3 列 × 2 行卡片网格（图标 + 标题 + 描述）
        feat_head = QLabel("产品特性")
        feat_head.setStyleSheet("font-weight:700;font-size:14px;border:none;")
        v.addWidget(feat_head)
        feat_grid_w = QWidget()
        fg = QGridLayout(feat_grid_w)
        fg.setContentsMargins(0, 0, 0, 0)
        fg.setHorizontalSpacing(10)
        fg.setVerticalSpacing(10)
        features = [
            ("tech", "技术检测", "操作系统 / 网络边界 / 数据库 / 中间件与Web / 应用与数据，支持本机与 SSH、WinRM 远程检测"),
            ("layer_mw", "版本漏洞", "内置 CVE 库，可比对中间件与宿主组件版本并给出风险提示"),
            ("quiz", "问卷评估", "物理环境与管理制度等人工核查项，按条款组织问答并留存证据"),
            ("report", "报告输出", "单目标与批量汇总报告，导出 HTML / Word / PDF，含不合格项汇总"),
            ("history", "安全基线", "内置安全基线库，支持离线更新与版本追溯"),
            ("layer_os", "跨平台", "Windows 桌面版、Linux 桌面版、命令行版本，支持国产操作系统"),
        ]
        for i, (icon, title, desc) in enumerate(features):
            card = QFrame()
            card.setObjectName("featCard")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 12, 14, 12)
            cl.setSpacing(6)
            top = QHBoxLayout()
            top.setSpacing(8)
            ic = asset_icon(icon)
            if not ic.isNull():
                ic_lab = QLabel()
                ic_lab.setStyleSheet("background:transparent;border:none;")
                ic_lab.setPixmap(ic.pixmap(20, 20))
                top.addWidget(ic_lab, 0, Qt.AlignVCenter)
            hd = QLabel(title)
            hd.setObjectName("featTitle")
            top.addWidget(hd, 1, Qt.AlignVCenter)
            cl.addLayout(top)
            dd = QLabel(desc)
            dd.setObjectName("featDesc")
            dd.setWordWrap(True)
            cl.addWidget(dd, 1)
            fg.addWidget(card, i // 3, i % 3)
        for c in range(3):
            fg.setColumnStretch(c, 1)
        v.addWidget(feat_grid_w)

        demo = QFrame()
        demo.setObjectName("panel")
        dv = QHBoxLayout(demo)
        dv.setContentsMargins(18, 14, 18, 14)
        dl = QLabel("在线演示（Web 版）：")
        dl.setStyleSheet("font-weight:700;")
        dv.addWidget(dl)
        link = QLabel("<a href='%s'>%s</a>" % (APP_DEMO, APP_DEMO))
        link.setOpenExternalLinks(True)
        link.setStyleSheet("font-weight:700;")
        dv.addWidget(link)
        dv.addStretch(1)
        v.addWidget(demo)

        note = QLabel("免责声明：本工具用于内部等保自查与整改跟踪，检测结果仅供参考，不作为等保测评结论或评审依据。")
        note.setObjectName("muted")
        note.setWordWrap(True)
        v.addWidget(note)

        # 底部行：公司信息 + 「开始测评」入口（进入检测范围界面）
        foot_row = QHBoxLayout()
        foot = QLabel("内蒙古勤加软件有限公司　　<a href='https://qinplus.com'>qinplus.com</a>")
        foot.setObjectName("muted")
        foot.setOpenExternalLinks(True)
        foot_row.addWidget(foot, 1)
        start_btn = QPushButton("开始测评")
        start_btn.setMinimumHeight(36)
        start_btn.setCursor(Qt.PointingHandCursor)
        start_btn.setToolTip("进入检测范围，开始等保自查")
        start_btn.clicked.connect(lambda: self.window()._goto_home())
        foot_row.addWidget(start_btn)
        v.addLayout(foot_row)
        v.addStretch(1)

        scroll.setWidget(inner)
        outer.addWidget(scroll)


# ---------------- 首页 ----------------

class HomePage(QWidget):
    start = pyqtSignal()
    manual_quiz = pyqtSignal(object)   # 人工核查层 → 直达问卷评估（参数为分类列表）
    batch_finished = pyqtSignal(object)

    MODES = [("local", "本机"), ("ssh", "远程服务器 · Linux (SSH)"),
             ("winrm", "远程服务器 · Windows (WinRM)")]

    # 人工核查层：点击卡片或一键自查直接进入对应内容的问卷评估
    MANUAL_LAYERS = {
        "安全物理与通信安全": [qd.Q_WL],
        "安全管理": [qd.Q_MGR, qd.Q_ORG, qd.Q_STAFF, qd.Q_BUILD, qd.Q_OPS],
    }

    def __init__(self, app_state):
        super().__init__()
        self.state = app_state
        self._connect_worker = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        v = QVBoxLayout(inner)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(10)
        scroll.setWidget(inner)
        outer.addWidget(scroll)

        head = QHBoxLayout()
        hb = QVBoxLayout()
        hb.setSpacing(2)
        title = QLabel("检测范围")
        title.setObjectName("pageTitle")
        sub = QLabel("选择检测层面与等保级别，配置被测对象与登录方式后开始自查")
        sub.setObjectName("pageSub")
        hb.addWidget(title)
        hb.addWidget(sub)
        head.addLayout(hb, 1)
        head.addWidget(back_about_btn(self), 0, Qt.AlignTop)
        head.addSpacing(26)  # 与关于页「开始测评」按钮右边界对齐
        v.addLayout(head)

        # ---------- 选择检测范围 + 等保级别 + 批量导入入口 ----------
        scope = QGroupBox("")
        scope.setObjectName("plainBox")
        sv = QVBoxLayout(scope)
        sv.setContentsMargins(14, 14, 14, 12)
        sv.setSpacing(8)

        # 第一行：被测对象名称 + 等保级别 + 批量导入
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("被测对象名称："))
        self.target_edit = QLineEdit(self.state.get("target", "本机"))
        self.target_edit.setPlaceholderText("如：XX业务系统 / 官网服务器")
        top_row.addWidget(self.target_edit, 1)
        top_row.addSpacing(16)
        top_row.addWidget(QLabel("等保级别："))
        self.level_combo = QComboBox()
        self.level_combo.setMinimumWidth(92)
        self.level_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.level_combo.addItems(["三级", "二级"])
        self.level_combo.setCurrentText(self.state.get("level", "三级"))
        top_row.addWidget(self.level_combo)
        top_row.addSpacing(16)
        self.btn_batch_entry = QPushButton("批量导入目标")
        self.btn_batch_entry.setObjectName("ghost")
        self.btn_batch_entry.clicked.connect(self._open_batch_dialog)
        top_row.addWidget(self.btn_batch_entry)
        top_row.addStretch(1)
        sv.addLayout(top_row)

        # 7 张图形卡片：遍历 LAYERS 自动生成（支持后续扩展）
        self.layer_cards = {}
        self._current_layer = LAYER_DEVICE
        card_grid = QHBoxLayout()
        card_grid.setSpacing(8)
        card_grid.setContentsMargins(0, 0, 0, 0)
        # 卡片图标与短标题（长名称放 tooltip，避免窄窗口下文字被裁切）
        card_meta = {
            "安全物理与通信安全": ("scope", "物理与通信"),
            "设备与计算安全（操作系统）": ("layer_os", "计算环境"),
            "网络与边界安全": ("layer_net", "网络与边界"),
            "数据库安全": ("layer_db", "数据库"),
            "中间件与Web安全": ("layer_mw", "中间件/Web"),
            "应用与数据安全": ("layer_app", "应用与数据"),
            "安全管理": ("tech", "安全管理"),
        }
        for layer_key, _cats in LAYERS:
            icon, short = card_meta.get(layer_key, ("scope", layer_key.split("（")[0]))
            card = ScopeCard(short, icon, "", False)
            card.setToolTip(layer_key)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            card.setMinimumWidth(64)
            card.clicked.connect(lambda checked, k=layer_key: self._select_layer(k, via_card=True))
            self.layer_cards[layer_key] = card
            card_grid.addWidget(card, 1)
        sv.addLayout(card_grid)

        # 等保级别切换 → 卡片检测项数自动刷新
        self.level_combo.currentTextChanged.connect(self._refresh_scope_cards)
        self._refresh_scope_cards(self.level_combo.currentText())

        # 共享登录面板（mode_group + remote_box + 状态 + 测试连接）
        # 每个 layer page 都会 addWidget 这个共享面板
        self._login_panel = self._build_login_panel()

        # 层专属配置区域（QStackedWidget 自动切换）
        self.layer_stack = QStackedWidget()
        self._layer_stack_index = {}
        # 按层名分派专属配置页（与 LAYERS 顺序一致，索引记录在 _layer_stack_index）
        def _info(text):
            p = QWidget(); l = QVBoxLayout(p)
            l.setContentsMargins(0, 0, 0, 0); l.setSpacing(8)
            t = QLabel(text); t.setObjectName("muted"); t.setWordWrap(True)
            l.addWidget(t); l.addStretch(1)
            return p

        page_map = {
            "安全物理与通信安全": lambda: _info(
                "本层（安全物理环境 / 安全通信网络）由人工核查项组成：机房选址、门禁、防雷、防火、"
                "温湿度、供配电、通信线缆与传输加密等，系统按等保条款列出核查要点与取证建议，需现场取证后逐项确认。"),
            "设备与计算安全（操作系统）": self._os_page,
            "网络与边界安全": self._net_page,
            "数据库安全": self._db_page,
            "中间件与Web安全": self._mw_page,
            "应用与数据安全": self._app_page,
            "安全管理": lambda: _info(
                "本层（安全管理制度 / 安全管理机构 / 安全管理人员 / 安全建设管理 / 安全运维管理）"
                "为管理制度类人工核查项，系统按等保条款列出核查要点、期望结果与取证建议。"),
        }
        for layer_key, _cats in LAYERS:
            builder = page_map.get(layer_key)
            self._add_layer_page(layer_key, builder() if builder else _info(""))
        sv.addWidget(self.layer_stack)

        # 层说明
        self.layer_desc = QLabel("")
        self.layer_desc.setObjectName("muted")
        self.layer_desc.setWordWrap(True)
        sv.addWidget(self.layer_desc)

        v.addWidget(scope)

        # ---------- 开始按钮 ----------
        self.start_btn = QPushButton("▶ 开始一键自查")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.clicked.connect(self._on_start)
        v.addWidget(self.start_btn)
        v.addStretch(1)

        # 批处理状态
        self._batch_targets = []
        self._batch_worker = None
        self._batch_dialog = None
        self._batch_group = ""  # 本次批量运行的批次标记（B+时间戳）

        # 初始化
        self._select_layer(LAYER_DEVICE, via_card=False)

        self.mode_group.buttonClicked.connect(self._on_mode_changed)
        self._on_mode_changed()
        # 被测对象名称随层/登录方式/地址自动更新
        self.host_edit.textChanged.connect(self._refresh_target_name)
        self.db_host.textChanged.connect(self._refresh_target_name)
        self.net_fw_ip.textChanged.connect(self._refresh_target_name)
        self.net_snmp_ip.textChanged.connect(self._refresh_target_name)
        self._refresh_target_name()

    # ========== 层专属配置页面构建 ==========


    def _build_login_panel(self):
        """构建共享登录面板（所有 layer page 都会 reparent 它到顶部）"""
        panel = QWidget()
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(6)
        row_mode = QHBoxLayout()
        row_mode.addWidget(QLabel("登录方式："))
        self.mode_group = QButtonGroup(self)
        for i, (key, label) in enumerate(self.MODES):
            rb = QRadioButton(label)
            rb.setProperty("mode", key)
            self.mode_group.addButton(rb, i)
            row_mode.addWidget(rb)
        self.mode_group.button(0).setChecked(True)
        row_mode.addStretch(1)
        pl.addLayout(row_mode)
        self.remote_box = QWidget()
        rv = QVBoxLayout(self.remote_box)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(3)
        r_host = QHBoxLayout()
        r_host.setSpacing(6)
        r_host.addWidget(QLabel("服务器地址："))
        self.host_edit = QLineEdit(); r_host.addWidget(self.host_edit, 3)
        r_host.addWidget(QLabel("端口："))
        self.port_edit = QLineEdit("22"); self.port_edit.setFixedWidth(64); r_host.addWidget(self.port_edit)
        r_host.addWidget(QLabel("用户名："))
        self.user_edit = QLineEdit("root"); self.user_edit.setMinimumWidth(90); r_host.addWidget(self.user_edit, 2)
        rv.addLayout(r_host)
        r_auth = QHBoxLayout()
        r_auth.setSpacing(6)
        r_auth.addWidget(QLabel("口令："))
        self.pwd_edit = QLineEdit(); self.pwd_edit.setEchoMode(QLineEdit.Password); r_auth.addWidget(self.pwd_edit, 2)
        self.key_label = QLabel("私钥文件："); r_auth.addWidget(self.key_label)
        self.key_edit = QLineEdit(); self.key_edit.setPlaceholderText("可留空，使用口令登录"); r_auth.addWidget(self.key_edit, 3)
        self.key_btn = QPushButton("浏览…"); self.key_btn.clicked.connect(self._pick_key); r_auth.addWidget(self.key_btn)
        rv.addLayout(r_auth)
        pl.addWidget(self.remote_box)
        foot = QHBoxLayout()
        self.status_label = QLabel("当前系统：%s" % engine.os_info())
        self.status_label.setObjectName("muted"); self.status_label.setWordWrap(True)
        self.test_btn = QPushButton("测试连接"); self.test_btn.clicked.connect(self._test_connection); self.test_btn.setVisible(False)
        foot.addWidget(self.status_label, 1); foot.addWidget(self.test_btn)
        pl.addLayout(foot)
        return panel

    def _add_layer_page(self, layer_key, page_widget):
        self._layer_stack_index[layer_key] = self.layer_stack.addWidget(page_widget)

    def _os_page(self):
        p = QWidget(); l = QVBoxLayout(p); l.setContentsMargins(0,0,0,0); l.setSpacing(8)
        tip = QLabel("操作系统 / 中间件 / 应用层：平台（Windows / Linux 含国产）将根据上方登录方式自动推断\n"
                      "  · 本机 → 当前系统    · SSH → Linux（统信/麒麟/Anolis/CentOS/Ubuntu）    · WinRM → Windows")
        tip.setObjectName("muted"); tip.setWordWrap(True); l.addWidget(tip); l.addStretch(1)
        return p

    def _net_page(self):
        p = QWidget(); l = QVBoxLayout(p); l.setContentsMargins(0,0,0,0); l.setSpacing(6)
        title = QLabel("网络与边界安全层默认读取目标机网卡、路由、端口监听；如需核查防火墙/路由器/交换机的 ACL、SNMP、HA 等边界配置，填写下方接入信息（可选）：")
        title.setObjectName("muted"); title.setWordWrap(True); l.addWidget(title)
        opt = QFrame(); opt.setObjectName("panel")
        grid = QGridLayout(opt); grid.setContentsMargins(12,8,12,8)
        grid.setHorizontalSpacing(8); grid.setVerticalSpacing(6)
        self.net_fw_ip = QLineEdit(); self.net_fw_ip.setPlaceholderText("设备 IP，留空不检查")
        self.net_fw_port = QLineEdit(); self.net_fw_port.setPlaceholderText("SSH 端口，默认 22")
        self.net_vendor = QComboBox()
        self.net_vendor.addItems(["自动识别", "Cisco IOS", "华为 VRP", "H3C Comware", "Juniper JunOS", "锐捷 RGOS"])
        self.net_model = QLineEdit(); self.net_model.setPlaceholderText("设备型号（可选）")
        self.net_fw_user = QLineEdit(); self.net_fw_user.setPlaceholderText("设备账号，如 admin")
        self.net_fw_pwd = QLineEdit(); self.net_fw_pwd.setEchoMode(QLineEdit.Password); self.net_fw_pwd.setPlaceholderText("仅本次会话有效")
        self.net_fw_enable = QLineEdit(); self.net_fw_enable.setEchoMode(QLineEdit.Password)
        self.net_fw_enable.setPlaceholderText("enable 口令（可选）")
        self.net_snmp_ip = QLineEdit(); self.net_snmp_ip.setPlaceholderText("SNMP 设备 IP，留空不探测")
        self.net_snmp = QLineEdit(); self.net_snmp.setPlaceholderText("SNMP v2c 团体字，如 public")

        def _lab(text):
            lb = QLabel(text); lb.setObjectName("muted"); lb.setFixedWidth(84)
            return lb

        pairs = [("设备 IP：", self.net_fw_ip, "SSH 端口：", self.net_fw_port),
                 ("设备厂商：", self.net_vendor, "设备型号：", self.net_model),
                 ("登录账号：", self.net_fw_user, "登录口令：", self.net_fw_pwd),
                 ("Enable 口令：", self.net_fw_enable, "SNMP 设备IP：", self.net_snmp_ip),
                 ("SNMP 团体字：", self.net_snmp, None, None)]
        for r, (t1, w1, t2, w2) in enumerate(pairs):
            grid.addWidget(_lab(t1), r, 0)
            grid.addWidget(w1, r, 1)
            if t2:
                grid.addWidget(_lab(t2), r, 2)
                grid.addWidget(w2, r, 3)
        grid.setColumnStretch(1, 1); grid.setColumnStretch(3, 1)
        l.addWidget(opt)
        tip = QLabel("说明：通过 SSH 登录设备执行 show/display（Cisco/华为/H3C/Juniper/锐捷）自动识别厂商与型号；"
                     "仅填 SNMP 时按 sysDescr 识别。连接失败自动降级为主机侧证据 + 人工核查，不伪造结果。")
        tip.setObjectName("muted"); tip.setWordWrap(True); l.addWidget(tip)
        l.addStretch(1); return p

    def _net_conf(self):
        vendor_map = {"自动识别": "auto", "Cisco IOS": "cisco", "华为 VRP": "huawei",
                      "H3C Comware": "h3c", "Juniper JunOS": "juniper", "锐捷 RGOS": "ruijie"}
        return {
            "host": self.net_fw_ip.text().strip(),
            "port": self.net_fw_port.text().strip() or "22",
            "vendor": vendor_map.get(self.net_vendor.currentText(), "auto"),
            "model": self.net_model.text().strip(),
            "user": self.net_fw_user.text().strip(),
            "password": self.net_fw_pwd.text(),
            "enable": self.net_fw_enable.text(),
            "snmp_host": self.net_snmp_ip.text().strip(),
            # 留空时回落到「系统设置」中的默认团体名
            "snmp_community": (self.net_snmp.text().strip()
                               or str(appconfig.get("snmp_community", "") or "")),
        }


    def _db_page(self):
        p = QWidget(); l = QVBoxLayout(p); l.setContentsMargins(0,0,0,0); l.setSpacing(6)
        grid = QGridLayout(); grid.setContentsMargins(0,0,0,0)
        grid.setHorizontalSpacing(8); grid.setVerticalSpacing(6)
        self.db_type = QComboBox(); self.db_type.addItems(["自动识别", "SQL Server", "SAP ASE (Sybase)", "SAP IQ", "SAP SQL Anywhere", "MySQL", "PostgreSQL", "Oracle", "MongoDB"])
        self.db_host = QLineEdit(); self.db_host.setPlaceholderText("留空＝本机；填 IP＝远程主机")
        self.db_port = QLineEdit(); self.db_port.setPlaceholderText("留空自动探测")
        self.db_user = QLineEdit(); self.db_user.setPlaceholderText("如 sa / root / postgres")
        self.db_pwd = QLineEdit(); self.db_pwd.setEchoMode(QLineEdit.Password); self.db_pwd.setPlaceholderText("仅本次会话有效")
        self.db_version = QLineEdit()
        self.db_version.setPlaceholderText("自动获取失败时手填，如 8.0.36 / 16.0")

        def _lab(text):
            lb = QLabel(text); lb.setObjectName("muted"); lb.setFixedWidth(84)
            return lb

        pairs = [("数据库主机：", self.db_host, "数据库类型：", self.db_type),
                 ("数据库端口：", self.db_port, "数据库账号：", self.db_user),
                 ("数据库口令：", self.db_pwd, "数据库版本：", self.db_version)]
        for r, (t1, w1, t2, w2) in enumerate(pairs):
            grid.addWidget(_lab(t1), r, 0)
            grid.addWidget(w1, r, 1)
            grid.addWidget(_lab(t2), r, 2)
            grid.addWidget(w2, r, 3)
        grid.setColumnStretch(1, 1); grid.setColumnStretch(3, 1)
        l.addLayout(grid)
        tip = QLabel("填写远程主机时会真实登录数据库（内置 MySQL / PostgreSQL / SQL Server 驱动）：先测端口连通，再校验账号口令，"
                     "任一失败即终止并提示原因。SAP ASE / IQ / RS 使用 TDS 5.0，开源驱动无法登录，请填写「数据库版本」以便评估基线；"
                     "留空则检测本机数据库进程/服务/配置文件。")
        tip.setObjectName("muted"); tip.setWordWrap(True); l.addWidget(tip)
        l.addStretch(1); return p

    def _mw_page(self):
        p = QWidget(); mf = QVBoxLayout(p); mf.setContentsMargins(0,0,0,0); mf.setSpacing(8)
        mw_row = QHBoxLayout(); mw_row.addWidget(QLabel("中间件名称（可选）："))
        self.mw_type = QComboBox(); self.mw_type.setEditable(True); self.mw_type.setFixedWidth(280)
        self.mw_type.setInsertPolicy(QComboBox.NoInsert)
        self.mw_type.addItems(["自动识别", "Nginx", "Apache httpd", "IIS", "Tomcat", "Jetty", "WebLogic", "WebSphere", "JBoss/WildFly", "Redis", "ActiveMQ"])
        self.mw_type.lineEdit().setPlaceholderText("留空自动登录识别，也可直接输入名称")
        mw_row.addWidget(self.mw_type); mw_row.addStretch(1); mf.addLayout(mw_row)
        mw_path_row = QHBoxLayout(); mw_path_row.addWidget(QLabel("安装路径（可选）："))
        self.mw_path = QLineEdit(); self.mw_path.setPlaceholderText("如 /etc/nginx、/opt/tomcat；留空自动推断")
        mw_path_row.addWidget(self.mw_path, 1); mf.addLayout(mw_path_row)
        tip = QLabel("中间件层默认通过上方服务器登录信息（SSH / WinRM）访问目标机，"
                     "读取其进程与配置文件（nginx.conf / httpd.conf / server.xml / web.xml 等）进行评估；"
                     "名称留空时自动登录识别。")
        tip.setObjectName("muted"); tip.setWordWrap(True); mf.addWidget(tip); mf.addStretch(1); return p

    def _mw_conf(self):
        name = self.mw_type.currentText().strip()
        return {"name": "" if name == "自动识别" else name,
                "path": self.mw_path.text().strip()}

    def _app_page(self):
        p = QWidget(); l = QVBoxLayout(p); l.setContentsMargins(0,0,0,0); l.setSpacing(6)
        grid = QGridLayout(); grid.setContentsMargins(0,0,0,0)
        grid.setHorizontalSpacing(8); grid.setVerticalSpacing(6)
        self.app_scheme = QComboBox(); self.app_scheme.addItems(["自动识别", "HTTPS", "HTTP"])
        self.app_port = QLineEdit(); self.app_port.setPlaceholderText("如 443 / 8443 / 8080；留空自动探测")
        self.app_path = QLineEdit(); self.app_path.setPlaceholderText("应用访问路径，留空默认 /，如 /app/login")

        def _lab(text):
            lb = QLabel(text); lb.setObjectName("muted"); lb.setFixedWidth(72)
            return lb

        grid.addWidget(_lab("访问协议："), 0, 0)
        grid.addWidget(self.app_scheme, 0, 1)
        grid.addWidget(_lab("应用端口："), 0, 2)
        grid.addWidget(self.app_port, 0, 3)
        grid.addWidget(_lab("应用路径："), 1, 0)
        grid.addWidget(self.app_path, 1, 1, 1, 3)
        grid.setColumnStretch(1, 1); grid.setColumnStretch(3, 1)
        l.addLayout(grid)
        tip = QLabel("应用与数据安全层默认通过上方服务器登录信息访问目标应用服务器，"
                     "按「协议 + 端口 + 路径」请求应用首页，核查 HTTPS、安全响应头与 TLS 版本；"
                     "未填写端口/路径时自动探测常见端口与根路径。")
        tip.setObjectName("muted"); tip.setWordWrap(True); l.addWidget(tip)
        l.addStretch(1); return p

    def _app_conf(self):
        scheme_map = {"自动识别": "auto", "HTTPS": "https", "HTTP": "http"}
        return {"scheme": scheme_map.get(self.app_scheme.currentText(), "auto"),
                "port": self.app_port.text().strip(),
                "path": self.app_path.text().strip()}

    # ========== 批量导入对话框 ==========

    def _open_batch_dialog(self):
        """点「📂 批量导入目标」弹出对话框"""
        dlg = QDialog(self)
        dlg.setWindowTitle("批量导入目标并按顺序检测")
        dlg.resize(900, 620)
        # 去掉标题栏自带的“?”（Windows 上点击无帮助内容），改用对话框内的帮助按钮
        dlg.setWindowFlags(dlg.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._batch_dialog = dlg

        outer = QVBoxLayout(dlg)
        outer.setContentsMargins(18, 18, 18, 14)
        outer.setSpacing(10)

        tip = QLabel("支持 Excel / CSV / JSON 格式，按文件内顺序逐个执行检测。"
                      "可先点击「⬇ 下载导入模板」获取带填写说明的 Excel 模板；"
                      "每个目标可独立指定登录方式、层范围、等保级别、数据库与中间件/应用参数。")
        tip.setObjectName("muted")
        tip.setWordWrap(True)
        outer.addWidget(tip)

        # 工具栏
        tb = QHBoxLayout()
        btn_import = QPushButton("选择配置文件")
        btn_import.clicked.connect(self._import_batch_file)
        btn_gen = QPushButton("⬇ 下载导入模板")
        btn_gen.setObjectName("ghost")
        btn_gen.clicked.connect(self._generate_batch_example)
        tb.addWidget(btn_import)
        tb.addWidget(btn_gen)
        tb.addStretch(1)
        btn_help = QPushButton("帮助")
        btn_help.setObjectName("ghost")
        btn_help.setToolTip("查看批量导入与检测说明")
        btn_help.clicked.connect(lambda: self._show_batch_help(dlg))
        tb.addWidget(btn_help)
        outer.addLayout(tb)

        # 进度条 + 状态
        batch_progress = QProgressBar()
        batch_progress.setVisible(False)
        outer.addWidget(batch_progress)
        batch_status = QLabel("尚未导入目标，请先选择配置文件。")
        batch_status.setObjectName("muted")
        batch_status.setWordWrap(True)
        outer.addWidget(batch_status)

        # 目标列表表格
        batch_table = QTableWidget(0, 9)
        batch_table.setHorizontalHeaderLabels(
            ["序号", "目标名称", "方式", "地址", "等保级别", "检测层面", "状态", "得分", "说明"])
        batch_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        batch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        batch_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        batch_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        batch_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        batch_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        batch_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        batch_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        batch_table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)
        batch_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        outer.addWidget(batch_table, 1)

        # 底部：开始 + 停止 + 关闭
        bottom = QHBoxLayout()
        btn_stop = QPushButton("■ 停止")
        btn_stop.setObjectName("ghost")
        btn_stop.setEnabled(False)
        btn_run = QPushButton("▶ 按顺序开始自查")
        btn_run.setEnabled(False)
        btn_close = QPushButton("关闭")
        btn_close.setObjectName("ghost")
        btn_close.clicked.connect(dlg.reject)
        bottom.addStretch(1)
        bottom.addWidget(btn_stop)
        bottom.addWidget(btn_run)
        bottom.addWidget(btn_close)
        outer.addLayout(bottom)

        # 关联到 HomePage 字段（让已有的 _import_batch_file/_run_batch 能复用）
        self._dlg_batch_progress = batch_progress
        self._dlg_batch_status = batch_status
        self._dlg_batch_table = batch_table
        self._dlg_btn_run = btn_run
        self._dlg_btn_stop = btn_stop

        def on_import(*_):
            if self._batch_targets:
                batch_status.setText(
                    "已导入 %d 个目标：%s" %
                    (len(self._batch_targets),
                     "、".join(t.name for t in self._batch_targets[:5]) +
                     ("…" if len(self._batch_targets) > 5 else "")))
                btn_run.setEnabled(True)

        btn_import.clicked.connect(on_import)
        btn_run.clicked.connect(self._run_batch)
        btn_stop.clicked.connect(self._stop_batch)

        # 关闭批量窗口即停止后台检测，避免检测完成后突然弹出完成提示
        dlg.finished.connect(lambda *_: self._stop_batch())
        dlg.exec_()



    def _mode(self):
        btn = self.mode_group.checkedButton()
        return btn.property("mode") if btn else "local"

    def _selected_layers(self):
        """返回当前选中的层面列表（供 engine.run_all(layers=...) 使用）"""
        return [self._current_layer]

    def _layer_desc_text(self, label):
        desc_map = {
            "安全物理与通信安全": "安全物理环境 + 安全通信网络：机房选址/门禁/防雷/防火/温湿度/供配电/线缆，以及网络架构与传输加密，均为人工核查项。",
            "设备与计算安全": "操作系统层面（身份鉴别、访问控制、安全审计、入侵防范、恶意代码防范、数据备份）。",
            "网络与边界安全": "网络与边界安全层：默认核查本机网络配置；填写设备 IP 后，将通过 SSH / SNMP 核查该防火墙、路由器或交换机。",
            "数据库安全": "数据库安全层：按数据库主机/端口/账号连接核查（进程、版本、账户、审计、备份）。",
            "中间件与Web安全": "中间件/Web 安全层：默认通过服务器登录信息读取目标机进程与配置（Nginx/Apache/IIS/Tomcat 等），名称留空自动识别。",
            "应用与数据安全": "应用与数据安全层：默认访问应用服务器，按协议/端口/路径核查 HTTPS、响应头、TLS 与数据保护配置。",
            "安全管理": "安全管理制度/机构/人员/建设/运维：全部为管理制度类人工核查项，按等保条款逐项取证。",
        }
        return desc_map.get(label, "")

    @staticmethod
    def _local_ip():
        """本机 IP（用于被测对象命名）"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def _is_os_layer(self):
        return self._current_layer.split("（")[0] == "设备与计算安全"

    def _uses_login_panel(self):
        """操作系统、中间件、应用层共用服务器登录面板（远程优先）"""
        layer = self._current_layer.split("（")[0]
        return layer in ("设备与计算安全", "中间件与Web安全", "应用与数据安全")

    def _refresh_target_name(self, *_):
        """被测对象名称默认格式：层名-IP（IP 中的 . 替换为 _）"""
        layer = self._current_layer.split("（")[0]
        if self._is_os_layer():
            ip = (self.host_edit.text().strip() or self._local_ip()) \
                if self._mode() != "local" else self._local_ip()
        elif layer == "数据库安全":
            ip = self.db_host.text().strip() or self._local_ip()
        elif layer == "网络与边界安全":
            net = self._net_conf()
            ip = net.get("host") or net.get("snmp_host") or self._local_ip()
        elif layer in ("中间件与Web安全", "应用与数据安全"):
            ip = (self.host_edit.text().strip() or self._local_ip()) \
                if self._mode() != "local" else self._local_ip()
        else:
            ip = self._local_ip()
        safe_ip = ip.strip().replace(".", "_").replace(":", "_").replace(" ", "_")
        self.target_edit.setText("%s-%s" % (layer, safe_ip))

    def _refresh_scope_cards(self, level):
        """根据当前等保级别重新计算每层的检测项数量，更新所有卡片的 tip 文本。"""
        from checks import get_technical_checks, current_platform
        from core.models import CATEGORY_LAYER, LAYERS
        try:
            items = get_technical_checks(level or "三级", current_platform())
        except Exception:
            return
        counts = {k: 0 for k, _ in LAYERS}
        for it in items:
            layer = CATEGORY_LAYER.get(it.category)
            if layer and layer in counts:
                counts[layer] += 1
        for layer_key, card in self.layer_cards.items():
            n = counts.get(layer_key, 0)
            card.set_tip("%d 项" % n)
            card.setToolTip("%s（%d 项检测）" % (layer_key, n))
        self._apply_responsive_layout()

    def _apply_responsive_layout(self):
        """按当前窗口尺寸自适应：卡片尺寸/字号缩放；空间不足时折叠流程提示与层说明，保证一屏完成"""
        h = self.height()
        flow = getattr(self, "_flow_frame", None)
        if flow is not None:
            flow.setVisible(h >= 720)
        desc = getattr(self, "layer_desc", None)
        if desc is not None:
            desc.setVisible(h >= 640)
        cards = getattr(self, "layer_cards", None)
        if not cards:
            return
        n = len(cards)
        # 页面左右边距 + 卡片间距
        avail = max(320, self.width() - 124 - 8 * (n - 1))
        w = int(avail / n)
        for card in cards.values():
            card.apply_scale(w)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_responsive_layout()
        self._sync_stack_height()

    def _select_layer(self, layer_key, via_card=True):
        """切换当前层：更新卡片高亮、stack、说明；仅操作系统/中间件/应用层显示登录面板"""
        self._current_layer = layer_key
        idx = self._layer_stack_index.get(layer_key, 0)
        for k, card in self.layer_cards.items():
            card.set_selected(k == layer_key)
        # 登录面板挂在操作系统/中间件/应用层；网络与数据库使用各自的连接信息
        prev = getattr(self, "_login_host", None)
        if self._uses_login_panel():
            page = self.layer_stack.widget(idx)
            if prev is not page:
                if prev is not None and prev.layout() is not None:
                    prev.layout().removeWidget(self._login_panel)
                self._login_panel.setParent(page)
                page.layout().insertWidget(0, self._login_panel)
                self._login_host = page
            self._login_panel.setVisible(True)
            # 中间件/应用首次进入时默认远程服务器（SSH），避免仍然只读本机
            short = layer_key.split("（")[0]
            if short in ("中间件与Web安全", "应用与数据安全"):
                seen = getattr(self, "_remote_default_done", None)
                if seen is None:
                    seen = set()
                    self._remote_default_done = seen
                if short not in seen:
                    seen.add(short)
                    if self._mode() == "local" and not self.host_edit.text().strip():
                        self.mode_group.button(1).setChecked(True)
                        self._on_mode_changed()
        else:
            if prev is not None and prev.layout() is not None:
                prev.layout().removeWidget(self._login_panel)
            self._login_host = None
            self._login_panel.setVisible(False)
        self.layer_stack.setCurrentIndex(idx)
        self.layer_desc.setText(self._layer_desc_text(layer_key.split("（")[0]))
        self._sync_stack_height()
        self._refresh_target_name()
        # 人工核查层：按钮文案改为进入问卷评估
        btn = getattr(self, "start_btn", None)
        if btn is not None:
            btn.setText("▶ 进入问卷评估（人工核查）"
                        if layer_key in self.MANUAL_LAYERS else "▶ 开始一键自查")
        # 物理与通信 / 安全管理为人工核查项：选中后直接进入对应问卷评估
        if via_card and layer_key in self.MANUAL_LAYERS:
            self.manual_quiz.emit(self.MANUAL_LAYERS[layer_key])

    def _sync_stack_height(self):
        """让堆叠区高度只占当前页所需高度（避免隐藏页的 sizeHint 撑高整页出现滚动条）"""
        stack = getattr(self, "layer_stack", None)
        if stack is None:
            return
        page = stack.currentWidget()
        if page is None:
            return
        h = page.sizeHint().height()
        stack.setFixedHeight(max(60, h))

    # -------- 批量导入 / 运行 --------

    def _show_batch_help(self, parent=None):
        """批量检测帮助说明"""
        QMessageBox.information(
            parent or self, "批量检测帮助",
            "<h3>批量检测使用说明</h3>"
            "<p><b>1. 准备配置文件</b><br>"
            "点击「下载导入模板」获取 Excel 模板（也可用 CSV / JSON）。"
            "模板第一行为表头、每行一个目标，第二张工作表为填写说明。</p>"
            "<p><b>2. 连接方式自动识别（无需填写）</b><br>"
            "未填 IP = 本机检测；填了具体设备厂商或 SNMP 地址 = 网络设备；"
            "检测范围仅选「网络与边界安全」也按网络设备核查；"
            "端口为 5985/5986 = Windows(WinRM)；其余填了 IP = SSH 远程检测。</p>"
            "<p><b>3. 数据库检测</b><br>"
            "检测范围选「数据库安全」时：IP地址 = 数据库主机、端口 = 数据库端口"
            "（如 MySQL 3306）、用户名/口令 = 数据库账号，系统直连数据库核查，"
            "不会误测本机。</p>"
            "<p><b>4. 导入并执行</b><br>"
            "点击「选择配置文件」导入，列表中确认目标后点「▶ 开始批量检测」，"
            "系统按文件顺序逐个检测并保存记录。</p>"
            "<p><b>5. 报告输出</b><br>"
            "每个目标完成即生成<b>独立报告</b>（HTML + Word，存于「报告目录\\批量」）；"
            "全部完成后在「检测报告」页可导出<b>批量汇总报告</b>，"
            "其中包含各系统<b>不合格项汇总</b>。</p>"
            "<p><b>6. 失败排查</b><br>"
            "表格「说明」列会显示失败原因；若 SSH 目标实为网络设备，"
            "系统会自动按「网络与边界安全」层面核查。</p>")

    def _generate_batch_example(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存批量导入模板",
            os.path.join(os.path.expanduser("~"), "批量导入模板.xlsx"),
            "Excel 模板 (*.xlsx);;CSV 模板 (*.csv);;JSON 模板 (*.json)")
        if not path:
            return
        low = path.lower()
        fmt = "xlsx" if low.endswith(".xlsx") else ("json" if low.endswith(".json") else "csv")
        try:
            config_loader.write_example(path, fmt)
            QMessageBox.information(
                self, "模板已生成",
                "已生成批量导入模板：\n%s\n\n模板含「导入模板」与「填写说明」两个工作表，"
                "按示例填写后，点击「选择配置文件」导入即可。" % path)
        except Exception as e:
            QMessageBox.warning(self, "生成失败", str(e))

    def _import_batch_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择配置文件",
            "",
            "配置文件 (*.json *.txt *.csv *.xlsx *.xls);;所有文件 (*)")
        if not path:
            return
        try:
            targets = config_loader.load(path)
        except Exception as e:
            QMessageBox.critical(self, "解析失败", "读取配置文件时出错：\n%s" % e)
            return
        if not targets:
            QMessageBox.warning(self, "配置为空", "文件中没有发现任何目标。")
            return
        self._batch_targets = targets
        self._refresh_batch_table()
        self._dlg_batch_status.setText(
            "已导入 %d 个目标：%s\n点击「▶ 按顺序开始自查」开始执行。" %
            (len(targets), "、".join(t.name for t in targets[:5]) +
             ("…" if len(targets) > 5 else "")))
        self._dlg_btn_run.setEnabled(True)

    def _refresh_batch_table(self):
        t = self._dlg_batch_table
        t.setRowCount(len(self._batch_targets))
        for i, target in enumerate(self._batch_targets):
            t.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            t.setItem(i, 1, QTableWidgetItem(target.name))
            t.setItem(i, 2, QTableWidgetItem(
                {"local": "本机", "ssh": "SSH", "winrm": "WinRM",
                 "netdev": "网络设备"}.get(target.mode, target.mode)))
            t.setItem(i, 3, QTableWidgetItem(
                target.host if target.mode != "local" else "(本机)"))
            t.setItem(i, 4, QTableWidgetItem(target.level))
            t.setItem(i, 5, QTableWidgetItem(target.display_layers()))
            status_item = QTableWidgetItem("待运行")
            status_item.setForeground(QColor("#6f8f7c"))
            t.setItem(i, 6, status_item)
            t.setItem(i, 7, QTableWidgetItem("-"))
            t.setItem(i, 8, QTableWidgetItem(""))

    def _run_batch(self):
        if not self._batch_targets:
            return
        # 若上一次批量仍在运行，先停止并断开其信号，避免旧任务完成时
        # 弹出「批量检测完成」干扰本次运行（未完成检查即弹窗的问题）
        old = self._batch_worker
        if old is not None:
            try:
                old.item_started.disconnect()
                old.item_finished.disconnect()
                old.item_failed.disconnect()
                old.all_finished.disconnect()
            except TypeError:
                pass
            if old.isRunning():
                old.stop()
                old.wait(1500)
        self.state["level"] = self.level_combo.currentText()
        self._refresh_batch_table()
        self._dlg_btn_run.setEnabled(False)
        self._dlg_btn_stop.setEnabled(True)
        self._dlg_batch_progress.setVisible(True)
        self._dlg_batch_progress.setRange(0, len(self._batch_targets))
        self._dlg_batch_progress.setValue(0)
        self._dlg_batch_status.setText("准备开始批量检测（%d 个目标）…" % len(self._batch_targets))

        self._batch_worker = BatchRunWorker(self._batch_targets)
        # 为本次批量运行生成批次标记，便于在历史记录中识别同一批次
        self._batch_group = "B" + datetime.now().strftime("%Y%m%d%H%M%S")
        self._batch_worker.item_started.connect(self._on_batch_item_started)
        self._batch_worker.item_finished.connect(self._on_batch_item_finished)
        self._batch_worker.item_failed.connect(self._on_batch_item_failed)
        self._batch_worker.all_finished.connect(self._on_batch_all_finished)
        self._batch_worker.start()

    def _stop_batch(self):
        if self._batch_worker and self._batch_worker.isRunning():
            self._batch_worker.stop()
            try:
                self._dlg_batch_status.setText("已请求停止，等待当前目标完成…")
            except RuntimeError:
                pass

    def _is_current_batch(self):
        """仅处理当前批量任务的信号；旧任务/已关闭对话框的任务直接忽略"""
        return self.sender() is None or self.sender() is self._batch_worker

    def _on_batch_item_started(self, index, total, name):
        if not self._is_current_batch():
            return
        self._dlg_batch_status.setText("[%d/%d] 正在检测：%s" % (index + 1, total, name))
        item = self._dlg_batch_table.item(index, 6)
        if item:
            item.setText("运行中…")
            item.setForeground(QColor("#ffb733"))

    def _on_batch_item_finished(self, index, summary):
        if not self._is_current_batch():
            return
        item_status = self._dlg_batch_table.item(index, 6)
        item_score = self._dlg_batch_table.item(index, 7)
        item_note = self._dlg_batch_table.item(index, 8)
        if summary is None:
            if item_status:
                item_status.setText("异常")
                item_status.setForeground(QColor("#ef4444"))
            if item_score:
                item_score.setText("-")
        else:
            if item_status:
                item_status.setText("完成")
                item_status.setForeground(QColor("#22c55e"))
            score_text = "%.1f" % summary.score if summary.score is not None else "-"
            if item_score:
                item_score.setText(score_text)
            if item_note:
                item_note.setText(getattr(summary, "note", "") or "")
                item_note.setForeground(QColor("#8b948e"))
            # 每个目标完成时单独生成报告文件（HTML + Word）
            t = self._batch_targets[index] if index < len(self._batch_targets) else None
            self._save_batch_target_report(t, summary, index)
        if summary is not None:
            try:
                storage.save_run(summary, batch_group=self._batch_group)
            except Exception:
                pass
        self._dlg_batch_progress.setValue(self._dlg_batch_progress.value() + 1)

    def _save_batch_target_report(self, target, summary, index):
        """每个批量目标完成时单独导出报告"""
        try:
            # 批量报告统一输出到「报告目录/批量」子目录
            out_dir = os.path.join(appconfig.get("report_dir"), "批量")
            os.makedirs(out_dir, exist_ok=True)
            # 用目标名称+日期生成文件名
            name = (target.name or summary.target or "等保自查").strip()
            for ch in '\\/:*?"<>|':
                name = name.replace(ch, "_")
            stamp = datetime.now().strftime("%Y%m%d_%H%M")
            base = "%s-%s" % (name or "等保自查", stamp)
            # HTML 报告
            html_path = os.path.join(out_dir, "%s.html" % base)
            report.export_html(summary, html_path)
            # Word 报告
            docx_path = os.path.join(out_dir, "%s.docx" % base)
            try:
                report.export_docx(summary, docx_path)
                self._dlg_batch_status.setText(
                    "已生成报告：%s" % os.path.basename(docx_path))
            except ImportError:
                pass
            if self._dlg_batch_table.item(index, 8):
                self._dlg_batch_table.item(index, 8).setText(
                    "已生成报告：%s.html" % base)
                self._dlg_batch_table.item(index, 8).setForeground(QColor("#22c55e"))
        except Exception as e:
            if self._dlg_batch_table.item(index, 8):
                self._dlg_batch_table.item(index, 8).setText(
                    "报告生成失败：%s" % e)
                self._dlg_batch_table.item(index, 8).setForeground(QColor("#f89800"))

    def _on_batch_item_failed(self, index, error):
        if not self._is_current_batch():
            return
        item_status = self._dlg_batch_table.item(index, 6)
        item_score = self._dlg_batch_table.item(index, 7)
        item_note = self._dlg_batch_table.item(index, 8)
        if item_status:
            item_status.setText("失败")
            item_status.setForeground(QColor("#ef4444"))
            item_status.setToolTip(error)
        if item_score:
            item_score.setText("-")
        if item_note:
            item_note.setText(error)
            item_note.setToolTip(error)
            item_note.setForeground(QColor("#ef4444"))
        self._dlg_batch_progress.setValue(self._dlg_batch_progress.value() + 1)

    def _on_batch_all_finished(self, results):
        if not self._is_current_batch():
            return
        total = len(results)
        ok = sum(1 for _t, s, e in results if s is not None)
        fail = total - ok
        scores = [t.run_score for t, s, e in results if t.run_score is not None]
        avg_score = sum(scores) / len(scores) if scores else 0
        stopped = bool(getattr(self._batch_worker, "_stop", False))
        if stopped:
            self._dlg_batch_status.setText(
                "批量检测已停止：完成 %d 个目标（成功 %d，失败 %d），"
                "已完成的结果已保存到历史记录。" % (total, ok, fail))
        else:
            self._dlg_batch_status.setText(
                "批量检测完成：共 %d 个目标，成功 %d，失败 %d，平均分 %.1f。"
                "结果已分别保存到历史记录。" %
                (total, ok, fail, avg_score))
        self._dlg_btn_run.setEnabled(True)
        self._dlg_btn_run.setText("▶ 再次按顺序批量检测")
        self._dlg_btn_stop.setEnabled(False)

        # 批量结束，清空批次标记（下一次批量为新批次）
        self._batch_group = ""

        # 用户已停止或已关闭批量窗口：不再弹「批量检测完成」
        if stopped:
            return

        # 交给主窗口处理：写入报告对象、引导进入问卷评估
        self.batch_finished.emit(results)

    def _db_conf(self):
        kind = self.db_type.currentText()
        kind = {"SQL Server": "sqlserver", "SAP ASE (Sybase)": "sap_ase",
                "SAP IQ": "sap_iq", "SAP SQL Anywhere": "sap_sqlanywhere",
                "自动识别": "auto"}.get(kind, kind.lower())
        host = self.db_host.text().strip()
        return {"type": kind, "host": host or "127.0.0.1",
                "port": self.db_port.text().strip(),
                "user": self.db_user.text().strip(),
                "password": self.db_pwd.text(),
                "version": self.db_version.text().strip()}

    def _on_mode_changed(self, *_):
        mode = self._mode()
        remote = mode != "local"
        self.remote_box.setVisible(remote)
        self.test_btn.setVisible(remote)
        self.key_label.setVisible(mode == "ssh")
        self.key_edit.setVisible(mode == "ssh")
        self.key_btn.setVisible(mode == "ssh")
        if mode == "ssh":
            self.port_edit.setText("22")
            if self.user_edit.text() in ("", "Administrator", "root"):
                self.user_edit.setText("root")
            self.status_label.setText(
                "SSH 远程检测：需目标机开启 sshd，建议使用 root 或具备 sudo 权限的账户。"
                "平台将按连接方式自动推断：SSH → Linux（含国产统信/麒麟/Anolis）。")
        elif mode == "winrm":
            self.port_edit.setText("5985")
            if self.user_edit.text() in ("", "root", "Administrator"):
                self.user_edit.setText("Administrator")
            self.status_label.setText(
                "WinRM 远程检测：需目标机执行 Enable-PSRemoting -Force 并开通 5985/5986 端口。"
                "平台将自动推断为 Windows。")
        else:
            self.status_label.setText("本机检测：%s  · 平台将按本机实际系统自动识别。" % engine.os_info())
        self._refresh_target_name()

    def _pick_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择SSH私钥", "", "私钥文件 (*)")
        if path:
            self.key_edit.setText(path)

    def _conf(self):
        mode = self._mode()
        return {
            "mode": mode,
            "host": self.host_edit.text().strip(),
            "port": self.port_edit.text().strip() or ("22" if mode == "ssh" else "5985"),
            "user": self.user_edit.text().strip(),
            "password": self.pwd_edit.text(),
            "keyfile": self.key_edit.text().strip(),
            "transport": "ntlm",
        }

    def _validate(self):
        conf = self._conf()
        if conf["mode"] != "local":
            if not conf["host"]:
                QMessageBox.warning(self, "提示", "请填写服务器地址（IP 或主机名）。")
                return None
            if not conf["user"]:
                QMessageBox.warning(self, "提示", "请填写登录用户名。")
                return None
            if not conf["password"] and not (conf["mode"] == "ssh" and conf["keyfile"]):
                QMessageBox.warning(self, "提示", "请填写登录口令" +
                                    "，或选择SSH私钥文件。" if conf["mode"] == "ssh" else "。")
                return None
        return conf

    def _test_connection(self):
        conf = self._validate()
        if not conf:
            return
        self.test_btn.setEnabled(False)
        self.status_label.setText("正在测试连接 %s …" % conf["host"])
        self._connect_worker = ConnectWorker(conf)
        self._connect_worker.ok.connect(self._on_connect_ok)
        self._connect_worker.fail.connect(self._on_connect_fail)
        self._connect_worker.start()

    def _on_connect_ok(self, os_name):
        self.test_btn.setEnabled(True)
        self.status_label.setText("✓ 连接成功：%s" % os_name)
        self.state["os_name"] = os_name

    def _on_connect_fail(self, err):
        self.test_btn.setEnabled(True)
        self.status_label.setText("✗ 连接失败：%s" % err)

    def _on_start(self):
        # 人工核查层不做技术检测，一键自查直接进入问卷评估
        if self._current_layer in self.MANUAL_LAYERS:
            self.manual_quiz.emit(self.MANUAL_LAYERS[self._current_layer])
            return
        selected = self._selected_layers()
        if not selected:
            QMessageBox.warning(self, "提示", "请先选择检测范围（单选）。")
            return
        # 操作系统/中间件/应用层使用登录面板；数据库用数据库主机、网络用设备 IP
        if self._uses_login_panel():
            conf = self._validate()
            if not conf:
                return
        else:
            conf = {"mode": "local", "host": self._local_ip(), "port": "", "user": "",
                    "password": "", "keyfile": "", "transport": "ntlm"}
        db_conf = self._db_conf()

        # —— 数据库层：连不上就终止，不生成一堆无意义结论 ——
        if not self._db_precheck(db_conf):
            return

        # —— 关键防御：操作系统层选了本机，但数据库主机填了远程 IP ——
        # 数据库层本身就以 db_host 作为连接目标，无需该提示
        if self._is_os_layer() and conf.get("mode") == "local":
            db_host = (db_conf.get("host") or "").strip()
            if db_host and db_host not in ("127.0.0.1", "localhost", "") and not db_host.startswith("127."):
                ret = QMessageBox.warning(
                    self, "配置冲突",
                    "当前选择【本机检测】模式，但数据库主机填写了远程 IP：%s\n\n"
                    "操作系统、网络、中间件检测将全部在本机执行。\n"
                    "数据库层将尝试从本机连接该远程 IP（可能因网络不通而超时）。\n\n"
                    "若你的目标是检测远程服务器 %s，建议切换到 SSH/WinRM 模式。\n\n"
                    "是否仍按本机模式继续？" % (db_host, db_host),
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if ret != QMessageBox.Yes:
                    return

        # —— 远程模式：提前跑一次 connect() 确认，避免中途静默失败 ——
        if conf.get("mode") != "local":
            try:
                from core.remote import build_executor
                ex = build_executor(conf)
                ex.connect()  # 这里会抛异常，如果连不上
                ex.close()
            except Exception as e:
                ret = QMessageBox.critical(
                    self, "远程连接失败",
                    "无法连接到 %s:%s —— %s\n\n"
                    "目标机器不可达时检测无法进行，"
                    "请勿期望工具会自动回退到本机执行（那样会得到虚假结果）。\n\n"
                    "请检查：IP 是否正确、端口是否开放、账号口令/私钥是否正确。"
                    % (conf.get("host"), conf.get("port", 22), e),
                    QMessageBox.Ok)
                return

        # —— 强制用户确认：被测机器是谁 ——
        target_ip, target_desc = self._target_ctx(conf, db_conf)
        QMessageBox.information(
            self, "确认检测目标",
            "本次检测层面：%s\n检测对象：%s\n报告文件名：%s-日期时间.html" % (
                self._current_layer.split("（")[0], target_desc, self._safe_name(target_ip)),
            QMessageBox.Ok)

        self.state["target"] = self.target_edit.text().strip() or self._safe_name(target_ip)
        self.state["target_ip"] = target_ip
        self.state["target_desc"] = target_desc
        self.state["level"] = self.level_combo.currentText()
        self.state["target_conf"] = conf
        self.state["layers"] = selected
        self.state["db_conf"] = db_conf
        self.state["net_conf"] = self._net_conf()
        self.state["mw_conf"] = self._mw_conf()
        self.state["app_conf"] = self._app_conf()
        self.start.emit()

    def _db_precheck(self, db_conf):
        """数据库层开始前先确认真的能连上；连不上直接终止并提示"""
        if self._current_layer.split("（")[0] != "数据库安全":
            return True
        from checks import db_checks as dbc, current_platform
        dbc.set_db_conf(db_conf)
        host = dbc._remote_host()
        if host:
            self.setCursor(Qt.WaitCursor)
            try:
                got = [p for p in dbc._remote_candidates() if dbc._tcp_ok(host, p, 1.5)]
            finally:
                self.unsetCursor()
            if not got:
                QMessageBox.critical(
                    self, "数据库无法连接",
                    "无法连接数据库 %s（已尝试端口：%s）。\n\n检测已终止，请检查：\n"
                    "· 数据库主机地址与端口是否正确\n"
                    "· 网络/防火墙是否放行本机访问\n"
                    "· 数据库是否监听网络地址（bind 0.0.0.0）\n"
                    "· 若需核查服务器进程/配置文件，请改用「设备与计算安全」层并 SSH 登录" % (
                        host, "、".join(str(p) for p in dbc._remote_candidates())))
                return False
            # 填了账号/口令：再做一次真实登录校验（内置 MySQL/PG/SQL Server 驱动）
            kind = str(db_conf.get("type") or "auto").lower()
            user = str(db_conf.get("user") or "").strip()
            if user and kind in ("mysql", "mariadb", "auto", "postgresql", "sqlserver"):
                port = dbc._remote_port() or got[0]
                ok, err = dbc._db_login_test(kind, host, port, user,
                                             str(db_conf.get("password") or ""))
                if not ok:
                    QMessageBox.critical(
                        self, "数据库登录失败",
                        "已连通 %s:%s，但数据库登录失败。\n\n原因：%s\n\n"
                        "检测已终止，请检查账号/口令、账号是否允许远程登录、"
                        "以及授权范围（MySQL: mysql.user 的 host；PG: pg_hba.conf；"
                        "SQL Server: 登录名与远程连接设置）。" % (host, port, err))
                    return False
            return True
        # 本机：必须存在运行中的数据库，否则同样终止
        inv = dbc._win_db_inventory() if current_platform() == "windows" \
            else dbc._linux_db_inventory()
        if not dbc._inv_running(inv):
            QMessageBox.critical(
                self, "未检测到数据库",
                "本机未检测到运行中的数据库服务或进程。\n\n检测已终止。"
                "若数据库部署在其他服务器，请在「数据库主机」填写该服务器 IP 及端口。")
            return False
        return True

    def _target_ctx(self, conf, db_conf):
        """返回 (检测目标IP, 检测对象说明)，按层面区分"""
        layer = self._current_layer.split("（")[0]
        if self._is_os_layer():
            if conf.get("mode") == "local":
                ip = self._local_ip()
                return ip, "本机（%s）" % ip
            return conf["host"], "远程 %s %s（%s:%s）" % (
                {"ssh": "SSH", "winrm": "WinRM"}[conf["mode"]],
                conf["host"], conf["host"], conf.get("port", 22))
        if layer == "数据库安全":
            ip = (db_conf.get("host") or "").strip() or self._local_ip()
            if ip in ("127.0.0.1", "localhost"):
                return ip, "本机数据库（%s）" % self._local_ip()
            return ip, "数据库 %s（由本机发起连接核查）" % ip
        if layer == "网络与边界安全":
            net = self._net_conf()
            device_ip = net.get("host") or net.get("snmp_host")
            if device_ip:
                ways = []
                if net.get("host"):
                    ways.append("SSH")
                if net.get("snmp_host"):
                    ways.append("SNMP")
                model = net.get("model") or ""
                name = ("网络设备 %s%s" % (device_ip, " · %s" % model if model else "")
                        + "（%s 核查）" % ("/".join(ways) or "远程"))
                return device_ip, name
            return self._local_ip(), "本机（%s，未填写设备 IP）" % self._local_ip()
        if layer in ("中间件与Web安全", "应用与数据安全"):
            host = (conf.get("host") or "").strip()
            remote = conf.get("mode") != "local" and host
            mode_label = {"ssh": "SSH", "winrm": "WinRM"}.get(conf.get("mode"), "远程")
            if layer == "中间件与Web安全":
                name = self._mw_conf().get("name") or "自动识别"
                if remote:
                    return host, "中间件 %s · %s（%s 远程核查）" % (name, host, mode_label)
                return self._local_ip(), "本机中间件（%s，%s）" % (name, self._local_ip())
            app = self._app_conf()
            scheme = app.get("scheme")
            port = app.get("port")
            if scheme == "auto":
                scheme = "https" if port in ("443", "8443") else "http"
            if not port:
                port = "443" if scheme == "https" else "80"
            path = app.get("path") or "/"
            if not path.startswith("/"):
                path = "/" + path
            if remote:
                return host, "应用 %s://%s:%s%s（%s 远程核查）" % (
                    scheme, host, port, path, mode_label)
            return self._local_ip(), "本机应用 %s://%s:%s%s" % (
                scheme, self._local_ip(), port, path)
        ip = self._local_ip()
        return ip, "本机（%s）" % ip

    def _safe_name(self, ip=None):
        """报告文件/被测对象名称：层名-IP（点换下划线）"""
        layer = self._current_layer.split("（")[0]
        ip = ip or self._local_ip()
        name = "%s-%s" % (layer, ip.strip().replace(".", "_").replace(":", "_"))
        for ch in '\\/:*?"<>|':
            name = name.replace(ch, "_")
        return name or "等保自查"



# ---------------- 基线更新对话框 ----------------

class BaselineDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("安全基线 / CVE 数据")
        self.setWindowIcon(app_icon())
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.resize(700, 640)
        v = QVBoxLayout(self)
        v.setSpacing(10)

        # —— 版本基线（products 版本安全下限） ——
        g1 = QGroupBox("版本基线（security_baseline.json）")
        v1 = QVBoxLayout(g1)
        v1.setSpacing(6)
        self.b_info = QLabel("")
        self.b_info.setWordWrap(True)
        v1.addWidget(self.b_info)
        tip1 = QLabel("判定规则：被测组件版本低于 products 下限 → 低于基线，报告中标注整改。")
        tip1.setObjectName("muted")
        tip1.setWordWrap(True)
        v1.addWidget(tip1)
        self.url_edit = QLineEdit()
        self.url_edit.setText(baseline.default_url("baseline"))
        v1.addWidget(self.url_edit)
        row1 = QHBoxLayout()
        b_import = QPushButton("导入本地 JSON")
        b_import.setObjectName("ghost")
        b_import.clicked.connect(lambda: self._import("baseline"))
        b_url = QPushButton("从 URL 更新")
        b_url.setObjectName("ghost")
        b_url.clicked.connect(lambda: self._fetch("baseline"))
        b_reset = QPushButton("恢复内置基线")
        b_reset.setObjectName("ghost")
        b_reset.clicked.connect(lambda: self._reset("baseline"))
        for b in (b_import, b_url, b_reset):
            row1.addWidget(b)
        row1.addStretch(1)
        v1.addLayout(row1)
        v.addWidget(g1)

        # —— CVE 漏洞库（组件版本区间 → CVE 映射） ——
        g2 = QGroupBox("CVE 漏洞库（cve_db.json）")
        v2 = QVBoxLayout(g2)
        v2.setSpacing(6)
        self.c_info = QLabel("")
        self.c_info.setWordWrap(True)
        v2.addWidget(self.c_info)
        tip2 = QLabel("判定规则：组件版本落入条目区间 [min, max] → 命中对应 CVE，在版本漏洞检查中列出。"
                      "可导入厂商/内部数据源更新，更新后直接覆盖 data/cve_db.json 生效。")
        tip2.setObjectName("muted")
        tip2.setWordWrap(True)
        v2.addWidget(tip2)
        self.cve_url_edit = QLineEdit()
        self.cve_url_edit.setText(baseline.default_url("cve"))
        v2.addWidget(self.cve_url_edit)
        row2 = QHBoxLayout()
        c_import = QPushButton("导入本地 JSON")
        c_import.setObjectName("ghost")
        c_import.clicked.connect(lambda: self._import("cve"))
        c_url = QPushButton("从 URL 更新")
        c_url.setObjectName("ghost")
        c_url.clicked.connect(lambda: self._fetch("cve"))
        c_reset = QPushButton("恢复内置 CVE 库")
        c_reset.setObjectName("ghost")
        c_reset.clicked.connect(lambda: self._reset("cve"))
        for b in (c_import, c_url, c_reset):
            row2.addWidget(b)
        row2.addStretch(1)
        v2.addLayout(row2)
        v.addWidget(g2)

        row = QHBoxLayout()
        b_open = QPushButton("打开存储目录")
        b_open.setObjectName("ghost")
        b_open.setToolTip("打开当前生效数据文件所在的目录")
        b_open.clicked.connect(self._open_dir)
        b_close = QPushButton("关闭")
        b_close.clicked.connect(self.accept)
        row.addWidget(b_open)
        row.addStretch(1)
        row.addWidget(b_close)
        v.addLayout(row)
        self._refresh_info()

    def _refresh_info(self):
        """刷新两份数据的版本/路径说明（更新后就地刷新，不关闭窗口）"""
        i = baseline.info()
        n_prod = len(baseline.load().get("products", {}))
        loc = "数据文件：%s" % i["path"]
        if os.path.dirname(i["write_path"]) != os.path.dirname(i["path"]):
            loc += "\n更新将写入：%s（程序目录不可写）" % i["write_path"]
        self.b_info.setText(
            "当前版本：%s（更新日期 %s，覆盖 %d 个产品，来源：%s）\n%s" % (
                i["version"] or "?", i["updated"] or "?", n_prod, i["source"] or "-", loc))

        ci = baseline.cve_info()
        loc2 = "数据文件：%s" % ci["path"]
        if os.path.dirname(ci["write_path"]) != os.path.dirname(ci["path"]):
            loc2 += "\n更新将写入：%s（程序目录不可写）" % ci["write_path"]
        _names = ci["names"].split("、") if ci["names"] else []
        names_s = "、".join(_names[:8]) + (" 等 %d 个组件" % len(_names) if len(_names) > 8 else "")
        self.c_info.setText("当前库：%d 个组件 / %d 条版本区间 / %d 个 CVE\n覆盖组件：%s\n%s" % (
            ci["components"], ci["entries"], ci["cves"], names_s, loc2))

    def _done(self, fn):
        try:
            msg = fn()
        except Exception as e:
            QMessageBox.warning(self, "更新失败", str(e))
            return
        self._refresh_info()   # 就地刷新版本与路径，保持窗口打开
        QMessageBox.information(self, "完成", msg)

    def _import(self, kind):
        path, _ = QFileDialog.getOpenFileName(self, "选择数据文件", "", "JSON 文件 (*.json)")
        if path:
            self._done(lambda: baseline.update_from_file(path) if kind == "baseline"
                       else baseline.update_cves_from_file(path))

    def _fetch(self, kind):
        edit = self.url_edit if kind == "baseline" else self.cve_url_edit
        url = edit.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请填写 JSON 文件下载地址。")
            return
        self._done(lambda: baseline.update_from_url(url) if kind == "baseline"
                   else baseline.update_cves_from_url(url))

    def _reset(self, kind):
        self._done(baseline.reset_to_bundled if kind == "baseline"
                   else baseline.reset_cves_to_bundled)

    def _open_dir(self):
        """打开当前生效数据文件所在的目录（用户更新版在 ~/.ea_dengbao，否则为程序自带 data/）"""
        d = os.path.dirname(baseline.info()["path"])
        if os.path.isdir(d):
            QDesktopServices.openUrl(QUrl.fromLocalFile(d))


# ---------------- 技术检测页 ----------------

class CheckPage(QWidget):
    done = pyqtSignal()
    failed = pyqtSignal(str)  # 检测失败事件（供主窗口写入运行日志）

    def __init__(self, app_state):
        super().__init__()
        self.state = app_state
        self.worker = None
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(10)

        top = QHBoxLayout()
        hb = QVBoxLayout()
        hb.setSpacing(2)
        title = QLabel("技术检测")
        title.setObjectName("pageTitle")
        self.info = QLabel("准备就绪")
        self.info.setObjectName("pageSub")
        hb.addWidget(title)
        hb.addWidget(self.info)
        top.addLayout(hb, 1)
        self.run_btn = QPushButton("开始检测")
        self.run_btn.clicked.connect(self.start_check)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghost")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        top.addWidget(self.run_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(back_about_btn(self))
        top.addSpacing(26)  # 与关于页「开始测评」按钮右边界对齐
        v.addLayout(top)

        # —— 目标机器横幅（醒目红/黄底，让用户知道在检测谁 ——
        self.target_banner = QLabel("")
        self.target_banner.setObjectName("targetBanner")
        self.target_banner.setWordWrap(True)
        self.target_banner.setStyleSheet(
            "QLabel#targetBanner{background:#211708;"
            "color:#ffb733;border-radius:8px;padding:9px 16px;font-size:12px;"
            "font-weight:600;}")
        self.target_banner.setVisible(False)
        v.addWidget(self.target_banner)

        legend = QLabel("结论：✓ 符合 · ✗ 不符合 · △ 部分符合 · ? 需人工核查 · ! 检测失败；"
                        "检测项按等保层面与分类分组显示")
        legend.setObjectName("pageSub")
        legend.setWordWrap(True)
        v.addWidget(legend)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        v.addWidget(self.progress)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["检测项", "结论", "检测结果 / 证据", "整改建议"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setColumnWidth(1, 100)
        self.tree.setColumnWidth(2, 380)
        self.tree.itemSelectionChanged.connect(self._hint)
        v.addWidget(self.tree, 1)

        self.detail = QLabel("点击检测项查看完整信息")
        self.detail.setObjectName("muted")
        self.detail.setWordWrap(True)
        v.addWidget(self.detail)

        self._layer_nodes = {}
        self._cat_nodes = {}
        self._item_widgets = {}

    def _reset(self):
        self.tree.clear()
        self._layer_nodes.clear()
        self._cat_nodes.clear()
        self._item_widgets.clear()
        self.progress.setValue(0)

    def start_check(self):
        self._reset()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        conf = self.state.get("target_conf") or {"mode": "local"}
        desc = self.state.get("target_desc") or "本机"
        # —— 醒目标识正在检测哪台机器 ——
        if conf.get("mode") == "local":
            self.target_banner.setText(
                "检测对象：%s（executor=LocalExecutor，OS=%s）" % (desc, engine.os_info()))
        else:
            self.target_banner.setText(
                "检测对象：%s（executor=%s）" %
                (desc, {"ssh": "SSHExecutor", "winrm": "WinRMExecutor"}[conf["mode"]]))
        self.target_banner.setVisible(True)
        if conf.get("mode") == "local":
            self.info.setText("正在检测：%s（部分项目需管理员/root权限）" % desc)
        else:
            self.info.setText("正在连接 %s 并检测…" % conf.get("host", ""))
        self.worker = CheckWorker(self.state["level"], self.state["target"], conf,
                                  self.state.get("layers"), self.state.get("db_conf"),
                                  self.state.get("net_conf"), self.state.get("mw_conf"),
                                  self.state.get("app_conf"))
        self.worker.progress.connect(self._on_progress)
        self.worker.item_done.connect(self._on_item)
        self.worker.finished_all.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _on_failed(self, err):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        # 红色横幅：明确告诉用户检测未能执行，不是本机偷偷跑的假结果
        self.target_banner.setStyleSheet(
            "QLabel#targetBanner{background:#450a0a;"
            "color:#fca5a5;border-radius:8px;padding:9px 16px;font-size:12px;"
            "font-weight:600;}")
        conf = self.state.get("target_conf") or {"mode": "local"}
        who = self.state.get("target_desc") or (
            "本机" if conf.get("mode") == "local" else conf.get("host", "?"))
        self.target_banner.setText(
            "✗ 检测失败 —— 目标机器 %s 检测未能执行。\n"
            "错误：%s\n\n"
            "!  本次未生成任何检测结果，请勿将本机/其他机器的旧结果当作此次的。"
            % (who, err))
        self.info.setText("检测失败")
        try:
            self.failed.emit(str(err))
        except Exception:
            pass
        QMessageBox.critical(
            self, "检测失败",
            "目标机器 %s 检测未能执行。\n\n错误详情：\n%s\n\n"
            "请检查网络连通性、账号权限或目标机器配置。\n"
            "工具不会回退到本机执行 —— 你没有得到任何假结果。" % (who, err))

    def _stop(self):
        if self.worker:
            self.worker.stop()
        self.info.setText("正在停止…")

    def _on_progress(self, cur, total, name):
        self.progress.setMaximum(total)
        self.progress.setValue(cur)
        self.info.setText("[%d/%d] 正在检测：%s" % (cur, total, name))

    def _layer_node(self, layer):
        if layer not in self._layer_nodes:
            node = QTreeWidgetItem(self.tree, [layer, "", "", ""])
            node.setForeground(0, QColor("#ffb733"))
            f = node.font(0)
            f.setBold(True)
            f.setPointSize(f.pointSize() + 1)
            node.setFont(0, f)
            node.setExpanded(True)
            self._layer_nodes[layer] = node
        return self._layer_nodes[layer]

    def _cat_node(self, cat):
        key = (layer_of(cat), cat)
        if key not in self._cat_nodes:
            node = QTreeWidgetItem(self._layer_node(key[0]), [cat, "", "", ""])
            node.setForeground(0, QColor("#2f9c3a"))
            f = node.font(0)
            f.setBold(True)
            node.setFont(0, f)
            node.setExpanded(True)
            self._cat_nodes[key] = node
        return self._cat_nodes[key]

    def _on_item(self, r):
        color, icon = STATUS_STYLE.get(r.status, ("#6b8a77", "?"))
        node = self._cat_node(r.category)
        w = QTreeWidgetItem(node, ["%s %s" % (r.item_id, r.name),
                                   "%s %s" % (icon, STATUS_TEXT.get(r.status, r.status)),
                                   (r.evidence or "")[:400], r.suggestion])
        w.setForeground(1, QColor(color))
        w.setData(0, Qt.UserRole, r)
        self._item_widgets[r.item_id] = w

    def _hint(self):
        items = self.tree.selectedItems()
        if not items:
            return
        r = items[0].data(0, Qt.UserRole)
        if r:
            self.detail.setText(
                "【%s】%s | 等保条款 %s | 要求：%s | 实测：%s | 建议：%s" % (
                    r.category, r.name, r.clause, r.expected,
                    r.evidence.replace("\n", " ")[:300], r.suggestion))

    def _on_finished(self, summary):
        self.state["summary"] = summary
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        # —— 更新横幅：检测完成，展示实际检测到的机器信息 ——
        desc = self.state.get("target_desc") or getattr(summary, "target_host", "127.0.0.1")
        mode = getattr(summary, "executor_type", "LocalExecutor")
        self.target_banner.setStyleSheet(
            "QLabel#targetBanner{background:#0d3320;"
            "color:#86efac;border-radius:8px;padding:9px 16px;font-size:12px;"
            "font-weight:600;}")
        self.target_banner.setText(
            "✓ 检测完成 —— 检测对象：%s  executor=%s\n"
            "被测对象：%s ｜ 实际 OS：%s ｜ 完成时间：%s" % (
                desc, mode, summary.target,
                summary.os_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.target_banner.setVisible(True)
        self.info.setText(
            "检测完成：综合得分 %.1f ｜ 符合 %d · 不符合 %d · 部分符合 %d · 人工核查 %d" % (
                summary.score, summary.pass_count, summary.fail_count,
                summary.warn_count, summary.manual_count))
        self.done.emit()


# ---------------- 问卷页 ----------------

class QuizPage(QWidget):
    saved = pyqtSignal()

    def __init__(self, app_state):
        super().__init__()
        self.state = app_state
        self._groups = {}
        self._built_level = None
        self._manual_categories = None   # 人工核查问卷分类（None 表示按技术检测结果生成）
        self._asked_draft_keys = set()  # 已询问过草稿恢复的 (级别, 层面) 组合，避免重复弹窗
        # 答案变化后 500ms 防抖自动保存草稿
        self._draft_timer = QTimer(self)
        self._draft_timer.setSingleShot(True)
        self._draft_timer.setInterval(500)
        self._draft_timer.timeout.connect(self._auto_save_draft)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        head = QHBoxLayout()
        hb = QVBoxLayout()
        hb.setSpacing(2)
        title = QLabel("问卷评估")
        title.setObjectName("pageTitle")
        self.info = QLabel("完成技术检测后，按实际检测层面生成对应评估内容")
        self.info.setObjectName("pageSub")
        hb.addWidget(title)
        hb.addWidget(self.info)
        head.addLayout(hb, 1)
        self.export_btn = QPushButton("导出答案")
        self.export_btn.setObjectName("ghost")
        self.export_btn.clicked.connect(self._export_answers)
        self.clear_draft_btn = QPushButton("清空草稿")
        self.clear_draft_btn.setObjectName("ghost")
        self.clear_draft_btn.clicked.connect(self._clear_draft)
        self.save_btn = QPushButton("保存问卷结果")
        self.save_btn.clicked.connect(self._save)
        head.addWidget(self.export_btn)
        head.addWidget(self.clear_draft_btn)
        head.addWidget(self.save_btn)
        head.addWidget(back_about_btn(self))
        head.addSpacing(26)  # 与关于页「开始测评」按钮右边界对齐
        outer.addLayout(head)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        outer.addWidget(self.scroll, 1)
        self.progress = QLabel("")
        self.progress.setObjectName("muted")
        outer.addWidget(self.progress)

    def build(self):
        # 人工核查问卷显示期间，不被技术检测结果覆盖
        if getattr(self, "_manual_categories", None):
            return
        level = self.state.get("level", "三级")
        # 提取本次检测实际覆盖的层面
        layers = self._detected_layers()
        # 未完成技术检测：问卷保持空白，不预生成任何内容
        if not layers:
            if self._built_level == "empty":
                return
            self._built_level = "empty"
            self._groups.clear()
            self._show_empty()
            return
        key = (level, tuple(sorted(layers)))
        if self._built_level == key:
            return
        self._built_level = key
        items = get_quiz_items(level, layers=layers)
        self._render(items, level)

    def build_manual(self, categories):
        """物理与通信 / 安全管理等人工核查层：直接按分类生成问卷，不依赖技术检测结果"""
        if isinstance(categories, str):
            categories = [c.strip() for c in categories.replace("，", ",").split(",")]
        cats = [c for c in (categories or []) if c in QUIZ_CATEGORIES]
        if not cats:
            return
        self._manual_categories = cats
        level = self.state.get("level", "三级")
        items = [q for q in get_quiz_items(level, layers=None) if q.category in cats]
        self._built_level = ("manual", tuple(cats))
        self._render(items, level)
        self.info.setText("人工核查问卷：%s　｜　请按现场取证情况逐项确认"
                          % "、".join(cats))

    def exit_manual(self):
        """退出人工核查问卷模式，下次进入恢复按检测结果生成"""
        self._manual_categories = None
        self._built_level = None

    def _render(self, items, level):
        """按题目列表渲染问卷分组，并回填已保存答案"""
        self._groups.clear()
        self.save_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.clear_draft_btn.setEnabled(True)

        container = QWidget()
        v = QVBoxLayout(container)
        v.setSpacing(12)
        by_cat = {c: [q for q in items if q.category == c] for c in QUIZ_CATEGORIES}
        for cat in QUIZ_CATEGORIES:
            qs = by_cat.get(cat)
            if not qs:
                continue
            box = QGroupBox(cat)
            bv = QVBoxLayout(box)
            bv.setSpacing(8)
            for q in qs:
                card = QFrame()
                card.setObjectName("quizItem")
                qv = QVBoxLayout(card)
                qv.setContentsMargins(12, 10, 12, 10)
                qv.setSpacing(4)
                lb = QLabel("%s  %s" % (q.qid, q.text))
                lb.setWordWrap(True)
                lb.setStyleSheet("font-weight:600;")
                qv.addWidget(lb)
                meta = QLabel("等保条款 %s ｜ 建议：%s" % (q.clause, q.suggestion))
                meta.setObjectName("muted")
                qv.addWidget(meta)
                row = QHBoxLayout()
                row.setSpacing(16)
                grp = QButtonGroup(container)
                grp.setExclusive(True)
                saved_ans = self.state.get("quiz_answers", {}).get(q.qid, {}).get("answer", "")
                for key, label in ANSWER_OPTIONS:
                    rb = QRadioButton(label)
                    grp.addButton(rb)
                    rb.setProperty("answer", key)
                    if key == saved_ans:
                        rb.setChecked(True)
                    rb.toggled.connect(lambda *_: self._on_answer_changed())
                    row.addWidget(rb)
                row.addStretch(1)
                qv.addLayout(row)
                bv.addWidget(card)
                self._groups[q.qid] = (grp, q)
            v.addWidget(box)
        v.addStretch(1)
        self.scroll.setWidget(container)
        self._update_progress()
        self._maybe_restore_draft(level)

    def _detected_layers(self):
        """从检测结果里提取本次实际覆盖的层面集合。
        批量时从 state["batch_layers"] 取（所有目标覆盖层面的并集）。
        未完成技术检测时返回 None，问卷页保持空白。"""
        from core.models import layer_of
        # 批量模式：取所有目标覆盖层面的并集
        batch_layers = self.state.get("batch_layers")
        if batch_layers:
            return batch_layers
        s = self.state.get("summary")
        if not s or not s.results:
            return None  # 没测 → 不生成问卷
        return {layer_of(r.category) for r in s.results}

    def _show_empty(self):
        """问卷空白态：提示先完成技术检测，不预生成任何条款"""
        box = QWidget()
        v = QVBoxLayout(box)
        v.addStretch(1)
        lb = QLabel("尚未完成技术检测")
        lb.setObjectName("pageTitle")
        lb.setAlignment(Qt.AlignCenter)
        v.addWidget(lb)
        tip = QLabel("完成「技术检测」后，系统会按实际检测到的层面自动生成对应的评估问卷。")
        tip.setObjectName("muted")
        tip.setAlignment(Qt.AlignCenter)
        v.addWidget(tip)
        v.addStretch(2)
        self.scroll.setWidget(box)
        self.progress.setText("")
        self.save_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.clear_draft_btn.setEnabled(False)

    def _update_progress(self):
        total = len(self._groups)
        done = 0
        for grp, _ in self._groups.values():
            if grp.checkedButton():
                done += 1
        self.progress.setText("已作答 %d / %d" % (done, total))

    def _on_answer_changed(self):
        """答案变化：刷新进度并启动防抖草稿保存"""
        self._update_progress()
        self._draft_timer.start()

    def _collect_answers(self):
        """从当前控件收集 questionnaire.data 兼容的答案结构"""
        answers = {}
        for qid, (grp, q) in self._groups.items():
            btn = grp.checkedButton()
            answers[qid] = {
                "answer": btn.property("answer") if btn else "",
                "category": q.category, "text": q.text, "level": q.level,
                "clause": q.clause, "suggestion": q.suggestion,
            }
        return answers

    def _auto_save_draft(self):
        """防抖结束后写入草稿（异常不影响问卷填写）"""
        if not self._groups:
            return
        try:
            qd.save_draft(self.state.get("level", "三级"), self._collect_answers())
        except Exception:
            pass

    def _maybe_restore_draft(self, level):
        """构建完成后检测未提交草稿，询问是否恢复；同级别只询问一次"""
        if self.state.get("quiz_answers"):
            return
        key = self._built_level
        if key in self._asked_draft_keys:
            return
        try:
            draft = qd.load_draft(level)
        except Exception:
            return
        answers = (draft or {}).get("answers") or {}
        if not answers:
            return
        self._asked_draft_keys.add(key)
        if QMessageBox.question(
                self, "问卷草稿",
                "发现上次未提交的问卷草稿，是否恢复？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes) == QMessageBox.Yes:
            self._apply_draft(answers)
            self.info.setText("已恢复上次未提交的问卷草稿，确认后请点击「保存问卷结果」")
        else:
            try:
                qd.clear_draft()
            except Exception:
                pass

    def _apply_draft(self, answers):
        """把草稿答案回填到对应单选按钮"""
        for qid, (grp, _q) in self._groups.items():
            value = answers.get(qid)
            ans = value.get("answer", "") if isinstance(value, dict) else (value or "")
            if not ans:
                continue
            for btn in grp.buttons():
                if btn.property("answer") == ans:
                    btn.setChecked(True)
                    break
        self._update_progress()

    def _export_answers(self):
        """导出当前问卷答案为 CSV"""
        level = self.state.get("level", "三级")
        out_dir = appconfig.get("report_dir") or os.path.join(
            os.path.expanduser("~"), "Desktop")
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError:
            out_dir = os.path.expanduser("~")
        default = os.path.join(
            out_dir, "问卷答案-%s-%s.csv" % (
                level, datetime.now().strftime("%Y%m%d")))
        path, _ = QFileDialog.getSaveFileName(
            self, "导出问卷答案", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            qd.export_answers_csv(self._collect_answers(), path, level)
        except Exception as e:
            QMessageBox.warning(self, "导出失败", str(e))
            return
        QMessageBox.information(self, "导出成功", "问卷答案已导出：\n%s" % path)

    def _clear_draft(self):
        """清空问卷草稿"""
        if QMessageBox.question(
                self, "清空草稿",
                "确定清空问卷草稿？") != QMessageBox.Yes:
            return
        try:
            qd.clear_draft()
        except Exception:
            pass
        self._draft_timer.stop()
        self.info.setText("问卷草稿已清空")

    def _save(self):
        answers = self._collect_answers()
        self.state["quiz_answers"] = answers
        # 已正式保存，草稿不再需要
        self._draft_timer.stop()
        try:
            qd.clear_draft()
        except Exception:
            pass
        self.saved.emit()


# ---------------- 报告页 ----------------

class ReportPage(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.state = app_state
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(10)

        # 顶部页头：标题 + 副标题居左，操作按钮居右（与技术检测页保持一致）
        top = QHBoxLayout()
        top.setSpacing(10)
        hb = QVBoxLayout()
        hb.setSpacing(2)
        title = QLabel("检测报告")
        title.setObjectName("pageTitle")
        sub = QLabel("预览、导出与保存检测报告")
        sub.setObjectName("pageSub")
        hb.addWidget(title)
        hb.addWidget(sub)
        top.addLayout(hb, 1)

        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.setObjectName("ghost")
        self.refresh_btn.clicked.connect(self.refresh)

        self.html_btn = QPushButton("导出 HTML")
        self.html_btn.clicked.connect(lambda: self._export("html"))

        self.word_btn = QPushButton("导出 Word")
        self.word_btn.clicked.connect(lambda: self._export("docx"))

        self.pdf_btn = QPushButton("导出 PDF")
        self.pdf_btn.clicked.connect(self._export_pdf)

        self.batch_btn = QPushButton("导出批量汇总")
        self.batch_btn.setVisible(False)
        self.batch_btn.clicked.connect(self._export_batch)

        self.save_btn = QPushButton("保存记录")
        self.save_btn.setObjectName("ghost")
        self.save_btn.clicked.connect(self._save_run)

        self.browser_btn = QPushButton("浏览器打开")
        self.browser_btn.setObjectName("ghost")
        self.browser_btn.clicked.connect(self._preview)

        for b in (self.browser_btn, self.save_btn, self.refresh_btn,
                  self.batch_btn, self.pdf_btn, self.word_btn, self.html_btn):
            top.addWidget(b)
        top.addWidget(back_about_btn(self))
        top.addSpacing(26)  # 与关于页「开始测评」按钮右边界对齐
        v.addLayout(top)

        # 内嵌预览区
        from PyQt5.QtWidgets import QTextBrowser
        self.viewer = QTextBrowser()
        self.viewer.setOpenExternalLinks(True)
        v.addWidget(self.viewer, 1)

        self._empty_html = """
        <p align="center" style="color:#9aa39c;">
          <span style="font-size:15px;">尚未生成检测报告</span><br>
          <span style="font-size:12px;">请先到「技术检测」页完成检测</span>
        </p>"""
        self.viewer.setHtml(self._empty_html)

    def refresh(self):
        batch_results = self.state.get("batch_results")
        s = self.state.get("summary")
        # 批量模式（多于 1 个目标）才显示「导出批量汇总」
        self.batch_btn.setVisible(bool(batch_results and len(batch_results) > 1))
        if batch_results and len(batch_results) > 1:
            # 批量模式：生成多目标汇总 HTML
            html = self._build_batch_summary_html(batch_results)
            self.viewer.setHtml(html)
        elif s:
            # 单目标模式
            tmp = os.path.join(storage.DB_DIR, "_preview.html")
            os.makedirs(storage.DB_DIR, exist_ok=True)
            report.export_html(s, tmp, self._quiz_items(), self.state.get("quiz_answers"))
            with open(tmp, "r", encoding="utf-8") as f:
                html = f.read()
            self.viewer.setHtml(html)
        else:
            self.viewer.setHtml(self._empty_html)

    def _build_batch_summary_html(self, batch_results):
        """生成批量检测汇总报告 HTML（配色跟随界面主题）"""
        from core.models import layer_of, LAYERS
        light = str(appconfig.get("theme", "light") or "light").lower() == "light"
        bg = "#ffffff" if light else "#061410"
        fg = "#111111" if light else "#cfe6d5"
        head_c = "#111111" if light else "#eafbef"
        muted = "#5f6b62" if light else "#86a894"
        panel = "#f5f7f5" if light else "#0c2419"
        line = "#e2efe5" if light else "#1f4a33"
        border = "none" if light else "1px solid #25603f"
        th_c = "#333333" if light else "#9fe6b3"
        rows = ""
        for t, s in batch_results:
            name = getattr(t, "name", None) or str(t)
            layers = sorted({layer_of(r.category) for r in s.results} if s.results else [])
            layer_short = "、".join([l.split("（")[0] for l in layers]) or "无"
            color = "#22c55e" if s.score >= 90 else "#7bc043" if s.score >= 75 else \
                    "#f89800" if s.score >= 60 else "#ef4444"
            rows += ('<tr>'
                     '<td style="padding:10px;border-bottom:1px solid %s;">%s</td>'
                     '<td style="padding:10px;border-bottom:1px solid %s;">%s</td>'
                     '<td style="padding:10px;border-bottom:1px solid %s;color:%s;'
                     'font-weight:700;">%.1f</td>'
                     '<td style="padding:10px;border-bottom:1px solid %s;color:%s;">%d 项</td>'
                     '</tr>' % (line, name, line, layer_short, line, color,
                                s.score, line, muted, s.total))

        scores = [s.score for _, s in batch_results if s.score is not None]
        avg = sum(scores) / len(scores) if scores else 0.0
        passed = sum(1 for _, s in batch_results if s.score is not None and s.score >= 75)
        grade_color = "#22c55e" if avg >= 90 else "#7bc043" if avg >= 75 else \
                     "#f89800" if avg >= 60 else "#ef4444"

        # 各系统不合格项汇总（不符合 + 检测异常）
        fail_html = ""
        fail_rows = ""
        fail_total = 0
        for t, s in batch_results:
            name = getattr(t, "name", None) or str(t)
            for r in (s.results or []):
                if r.status in (STATUS_FAIL, STATUS_ERROR):
                    fail_total += 1
                    fail_rows += ('<tr>'
                                  '<td style="padding:9px;border-bottom:1px solid %s;">%s</td>'
                                  '<td style="padding:9px;border-bottom:1px solid %s;">%s</td>'
                                  '<td style="padding:9px;border-bottom:1px solid %s;">%s</td>'
                                  '<td style="padding:9px;border-bottom:1px solid %s;color:%s;">%s</td>'
                                  '</tr>' % (line, name, line, r.name, line, r.clause,
                                             line, "#ef4444", r.suggestion))
        if fail_rows:
            fail_html = ("<h2 style=\"margin-top:28px;\">不合格项汇总（共 %d 条）</h2>"
                         % fail_total
                         + "<table><tr><th>目标名称</th><th>检测项</th><th>等保条款</th>"
                           "<th>整改建议</th></tr>" + fail_rows + "</table>")

        css = ("""body{background:%s;color:%s;font-family:"Microsoft YaHei";margin:0;padding:24px;}
h2{color:%s;font-size:20px;font-weight:800;margin:0 0 4px;}
.sub{color:%s;font-size:13px;margin-bottom:20px;}
.stat-n{font-size:28px;font-weight:800;color:%s;}
.stat-l{font-size:12px;color:%s;margin-top:4px;}
table{border-collapse:collapse;font-size:13px;}
th{background:%s;color:%s;padding:10px;text-align:left;border-bottom:1px solid %s;}
td.data{padding:10px;text-align:left;border-bottom:1px solid %s;}
.tip{background:%s;border:%s;border-radius:8px;padding:12px 16px;color:%s;
     font-size:13px;margin-top:16px;}"""
               % (bg, fg, head_c, muted, head_c, muted,
                  panel, th_c, line, line, panel, border, muted))
        stat_td = ('<td bgcolor="%s" width="25%%" align="center" '
                   'style="background:%s;padding:16px;">'
                   '<div class="stat-n">%s</div>'
                   '<div class="stat-l">%s</div></td>')
        html = ("<html><head><meta charset=\"utf-8\"><style>" + css + "</style></head><body>"
            + "<h2>批量检测汇总报告</h2>"
            + "<div class=\"sub\">共 " + str(len(batch_results)) + " 个目标，检测时间：" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</div>"
            + "<table border=\"0\" cellspacing=\"10\" cellpadding=\"0\" width=\"100%\"><tr>"
            + stat_td % (panel, panel, str(len(batch_results)), "总目标数")
            + stat_td % (panel, panel, "%.1f" % avg,
                         "<span style=\"color:%s\">平均得分</span>" % grade_color)
            + stat_td % (panel, panel,
                         "<span style=\"color:#22c55e\">%d</span>" % passed, "达标（≥75分）")
            + stat_td % (panel, panel,
                         "<span style=\"color:#f89800\">%d</span>" % (len(batch_results) - passed),
                         "待整改")
            + "</tr></table>"
            + "<table width=\"100%\"><tr><th>目标名称</th><th>检测层面</th><th>得分</th><th>检测项数</th></tr>"
            + rows
            + "</table>"
            + fail_html
            + "<div class=\"tip\">每个目标的独立报告（HTML + Word）已保存到「" + os.path.join(
                self._report_dir(), "批量") + "」文件夹；点击「导出批量汇总」可导出含不合格项汇总的完整批量报告。</div>"
            + "</body></html>")
        return html

    def _quiz_items(self):
        from core.models import layer_of
        # 批量时取所有目标覆盖层面的并集
        batch_layers = self.state.get("batch_layers")
        if batch_layers:
            return get_quiz_items(self.state.get("level", "三级"), layers=batch_layers)
        s = self.state.get("summary")
        layers = None
        if s and s.results:
            layers = {layer_of(r.category) for r in s.results}
        return get_quiz_items(self.state.get("level", "三级"), layers=layers)

    def _export_name(self, s):
        """报告文件名：被测对象-日期时间（如 设备与计算安全-192_168_1_1-20261103_1530）"""
        name = (s.target or "等保自查").strip()
        for ch in '\\/:*?"<>|':
            name = name.replace(ch, "_")
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        return "%s-%s" % (name or "等保自查", stamp)

    def _report_dir(self):
        """报告默认输出目录：配置项 report_dir，不存在时创建"""
        out_dir = appconfig.get("report_dir") or os.path.join(
            os.path.expanduser("~"), "Desktop")
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError:
            out_dir = os.path.expanduser("~")
        return out_dir

    def _batch_items(self):
        """批量结果（≥2 个目标）→ [(名称, RunSummary)]；单目标检测返回 None"""
        batch = self.state.get("batch_results") or []
        if len(batch) >= 2:
            return [(getattr(t, "name", None) or str(t), s) for t, s in batch]
        return None

    def _export(self, kind):
        batch = self._batch_items()
        if batch:
            # 批量检测结果：导出全部目标的批量汇总（而非最后一个目标）
            fmt = "html" if kind == "html" else "docx"
            default = os.path.join(
                self._report_dir(), "批量汇总-%s.%s" % (
                    datetime.now().strftime("%Y%m%d_%H%M"), fmt))
            path, _ = QFileDialog.getSaveFileName(
                self, "导出批量汇总报告", default,
                "HTML文件 (*.html)" if fmt == "html" else "Word文件 (*.docx)")
            if not path:
                return
            try:
                self._export_batch_file(path, fmt)
            except ImportError:
                QMessageBox.warning(self, "缺少依赖", "Word导出需要安装 python-docx：\npip install python-docx")
                return
            except Exception as e:
                QMessageBox.warning(self, "导出失败", "批量汇总导出失败：\n%s" % e)
                return
            self._notify_exported(path)
            return
        s = self.state.get("summary")
        if not s:
            QMessageBox.warning(self, "提示", "请先完成技术检测再导出报告。")
            return
        base = self._export_name(s)
        out_dir = self._report_dir()
        if kind == "html":
            path, _ = QFileDialog.getSaveFileName(
                self, "导出HTML报告",
                os.path.join(out_dir, "%s.html" % base),
                "HTML文件 (*.html)")
            if not path:
                return
            report.export_html(s, path, self._quiz_items(), self.state.get("quiz_answers"))
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "导出Word报告",
                os.path.join(out_dir, "%s.docx" % base),
                "Word文件 (*.docx)")
            if not path:
                return
            try:
                report.export_docx(s, path, self._quiz_items(), self.state.get("quiz_answers"))
            except ImportError:
                QMessageBox.warning(self, "缺少依赖", "Word导出需要安装 python-docx：\npip install python-docx")
                return
        self._notify_exported(path)

    def _open_report_path(self, path):
        """在资源管理器中打开文件所在目录并选中该文件（非 Windows 直接打开目录）"""
        try:
            if os.name == "nt":
                subprocess.Popen(["explorer", "/select,",
                                  os.path.normpath(os.path.abspath(path))])
            else:
                QDesktopServices.openUrl(
                    QUrl.fromLocalFile(os.path.dirname(os.path.abspath(path))))
        except Exception:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
            except Exception:
                pass

    def _notify_exported(self, path, title="导出成功"):
        """导出成功提示：附带「打开报告」「打开报告目录」快捷按钮"""
        mb = QMessageBox(self)
        mb.setWindowTitle(title)
        mb.setText("%s：\n%s" % ("报告已导出" if title == "导出成功" else title, path))
        mb.setIcon(QMessageBox.Information)
        btn_open = mb.addButton("打开报告", QMessageBox.ActionRole)
        btn_dir = mb.addButton("打开报告目录", QMessageBox.ActionRole)
        mb.addButton("关闭", QMessageBox.RejectRole)
        mb.exec_()
        if mb.clickedButton() is btn_open:
            # 直接用系统默认程序打开报告文件
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))
            except Exception:
                self._open_report_path(path)
        elif mb.clickedButton() is btn_dir:
            self._open_report_path(path)

    def _export_pdf(self):
        """导出 PDF 报告（批量结果时导出批量汇总）"""
        batch = self._batch_items()
        if batch:
            default = os.path.join(
                self._report_dir(),
                "批量汇总-%s.pdf" % datetime.now().strftime("%Y%m%d_%H%M"))
            path, _ = QFileDialog.getSaveFileName(
                self, "导出PDF报告", default, "PDF文件 (*.pdf)")
            if not path:
                return
            try:
                self._export_batch_file(path, "pdf")
            except Exception as e:
                QMessageBox.warning(self, "导出失败", "PDF 导出失败：\n%s" % e)
                return
            self._notify_exported(path, "PDF 报告已导出")
            return
        s = self.state.get("summary")
        if not s:
            QMessageBox.warning(self, "提示", "请先完成技术检测再导出报告。")
            return
        base = self._export_name(s)
        path, _ = QFileDialog.getSaveFileName(
            self, "导出PDF报告",
            os.path.join(self._report_dir(), "%s.pdf" % base),
            "PDF文件 (*.pdf)")
        if not path:
            return
        try:
            report.export_pdf(s, path, self._quiz_items(),
                              self.state.get("quiz_answers"))
        except Exception as e:
            QMessageBox.warning(self, "导出失败", "PDF 导出失败：\n%s" % e)
            return
        self._notify_exported(path, "PDF 报告已导出")

    def _export_batch(self):
        """批量模式下导出多目标汇总报告（HTML / Word / PDF）"""
        batch = self.state.get("batch_results") or []
        if len(batch) < 2:
            QMessageBox.warning(self, "提示", "当前不是批量检测结果，无需导出批量汇总。")
            return
        default = os.path.join(
            self._report_dir(),
            "批量汇总-%s.html" % datetime.now().strftime("%Y%m%d_%H%M"))
        path, selected = QFileDialog.getSaveFileName(
            self, "导出批量汇总报告", default,
            "HTML 文件 (*.html);;Word 文件 (*.docx);;PDF 文件 (*.pdf)")
        if not path:
            return
        low = path.lower()
        if low.endswith(".html") or low.endswith(".htm"):
            fmt = "html"
        elif low.endswith(".docx"):
            fmt = "docx"
        elif low.endswith(".pdf"):
            fmt = "pdf"
        else:
            fmt = "docx" if "Word" in (selected or "") else (
                "pdf" if "PDF" in (selected or "") else "html")
            path += {"html": ".html", "docx": ".docx", "pdf": ".pdf"}[fmt]
        try:
            self._export_batch_file(path, fmt)
        except ImportError:
            QMessageBox.warning(self, "缺少依赖", "Word导出需要安装 python-docx：\npip install python-docx")
            return
        except Exception as e:
            QMessageBox.warning(self, "导出失败", "批量汇总导出失败：\n%s" % e)
            return
        self._notify_exported(path, "批量汇总报告已导出")

    def _export_batch_file(self, path, fmt="html"):
        """写入批量汇总文件（供按钮与测试直接调用）"""
        batch = self.state.get("batch_results") or []
        items = [(getattr(t, "name", None) or str(t), s) for t, s in batch]
        report.export_batch(items, path, fmt,
                            quiz_items=self._quiz_items(),
                            quiz_answers=self.state.get("quiz_answers"))
        return path

    def _preview(self):
        """在外部浏览器打开（批量结果时打开批量汇总）"""
        batch = self._batch_items()
        if batch:
            tmp = os.path.join(storage.DB_DIR, "_preview_batch.html")
            os.makedirs(storage.DB_DIR, exist_ok=True)
            self._export_batch_file(tmp, "html")
            webbrowser.open("file://" + tmp)
            return
        s = self.state.get("summary")
        if not s:
            QMessageBox.warning(self, "提示", "请先完成技术检测再预览。")
            return
        tmp = os.path.join(storage.DB_DIR, "_preview.html")
        os.makedirs(storage.DB_DIR, exist_ok=True)
        report.export_html(s, tmp, self._quiz_items(), self.state.get("quiz_answers"))
        webbrowser.open("file://" + tmp)

    def _save_run(self):
        batch = self._batch_items()
        if batch:
            # 批量检测在完成时已自动逐目标入库，避免重复保存
            QMessageBox.information(
                self, "已自动保存",
                "批量检测完成时已自动保存 %d 条检测记录，可在「历史对比」页查看与整改对比，无需重复保存。"
                % len(batch))
            return
        s = self.state.get("summary")
        if not s:
            QMessageBox.warning(self, "提示", "请先完成技术检测再保存。")
            return
        rid = storage.save_run(s)
        QMessageBox.information(self, "已保存", "检测记录已保存（编号 #%d），可在「历史对比」页查看与整改对比。" % rid)


# ---------------- 历史对比页 ----------------

REMEDIATION_TEXT = {
    "done": ("已整改", "#22c55e"),
    "pending": ("待整改", "#f89800"),
    "ignored": ("不适用", "#8b9c90"),
}


class HistoryPage(QWidget):
    def __init__(self, app_state):
        super().__init__()
        self.state = app_state
        self._current_run_id = None
        self._detail_status = {}  # {item_id: 原始检测结论}，用于校验可标记状态
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(8)

        head = QHBoxLayout()
        hb = QVBoxLayout()
        hb.setSpacing(2)
        title = QLabel("历史对比")
        title.setObjectName("pageTitle")
        sub = QLabel("选中一条记录查看明细并标记整改状态；选中两条可对比整改落实情况")
        sub.setObjectName("pageSub")
        hb.addWidget(title)
        hb.addWidget(sub)
        head.addLayout(hb, 1)
        refresh_btn = QPushButton("刷新")
        refresh_btn.setObjectName("ghost")
        refresh_btn.clicked.connect(self.refresh)
        self.cmp_btn = QPushButton("对比选中的两次记录")
        self.cmp_btn.clicked.connect(self._compare)
        self.del_btn = QPushButton("删除选中记录")
        self.del_btn.setObjectName("ghost")
        self.del_btn.clicked.connect(self._delete)
        head.addWidget(refresh_btn)
        head.addWidget(self.cmp_btn)
        head.addWidget(self.del_btn)
        head.addWidget(back_about_btn(self))
        head.addSpacing(26)  # 与关于页「开始测评」按钮右边界对齐
        v.addLayout(head)

        # 得分趋势图（最近 20 次）
        trend_row = QHBoxLayout()
        trend_title = QLabel("得分趋势（最近 20 次）")
        trend_title.setObjectName("muted")
        trend_row.addWidget(trend_title)
        trend_row.addStretch(1)
        v.addLayout(trend_row)
        self.chart = TrendChart()
        v.addWidget(self.chart)

        splitter = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["ID", "被测对象", "系统", "级别", "时间", "得分", "符合", "不符合", "已整改"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_run_selected)
        splitter.addWidget(self.table)

        self.diff = QTableWidget(0, 6)
        self.diff.setHorizontalHeaderLabels(
            ["检测项", "名称", "类别", "上次结论", "本次结论", "对比状态"])
        self.diff.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.diff.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.diff.itemSelectionChanged.connect(self._update_action_buttons)
        splitter.addWidget(self.diff)
        splitter.setSizes([220, 360])
        v.addWidget(splitter, 1)

        # 整改标记操作区
        action = QHBoxLayout()
        self.stats = QLabel("已整改 0 项，待整改 0 项，不适用 0 项")
        self.stats.setObjectName("muted")
        self.btn_done = QPushButton("✓ 标记为已整改")
        self.btn_pending = QPushButton("⏳ 标记为待整改")
        self.btn_ignored = QPushButton("⊘ 标记为不适用")
        for btn in (self.btn_done, self.btn_pending, self.btn_ignored):
            btn.setObjectName("ghost")
            btn.setEnabled(False)
        self.btn_done.clicked.connect(self._mark_done)
        self.btn_pending.clicked.connect(self._mark_pending)
        self.btn_ignored.clicked.connect(self._mark_ignored)
        action.addWidget(self.stats)
        action.addStretch(1)
        action.addWidget(self.btn_done)
        action.addWidget(self.btn_pending)
        action.addWidget(self.btn_ignored)
        v.addLayout(action)

        self.hint = QLabel("选中一条记录可查看明细并标记整改状态；按住 Ctrl 选中两条可进行对比")
        self.hint.setObjectName("muted")
        v.addWidget(self.hint)

    # ---------- 历史列表 ----------

    def refresh(self):
        rows = storage.list_runs()
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            target = str(r[1] or "")
            if r[11]:
                target += "  [批量]"
            vals = [r[0], target, r[2], r[3], r[4], r[5], r[6], r[7]]
            for c, v_ in enumerate(vals):
                item = QTableWidgetItem(str(v_))
                if c == 5:
                    try:
                        score = float(v_)
                        color = "#22c55e" if score >= 90 else "#7bc043" if score >= 75 else \
                                "#f89800" if score >= 60 else "#ef4444"
                        item.setForeground(QColor(color))
                    except (TypeError, ValueError):
                        pass
                self.table.setItem(row, c, item)
            try:
                done = storage.remediation_stats(int(r[0]))[0]
            except Exception:
                done = 0
            done_item = QTableWidgetItem(str(done))
            if done:
                done_item.setForeground(QColor("#22c55e"))
            self.table.setItem(row, 8, done_item)
        self.table.blockSignals(False)

        try:
            self.chart.set_data(storage.score_trend(20))
        except Exception:
            self.chart.set_data([])

    def _selected_ids(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        ids = []
        for r in rows:
            it = self.table.item(r, 0)
            if it:
                ids.append(int(it.text()))
        return ids

    def _on_run_selected(self):
        ids = self._selected_ids()
        if len(ids) == 1:
            self._show_detail(ids[0])
        elif len(ids) == 2:
            self._current_run_id = None
            self._detail_status = {}
            self._set_action_buttons(False, False, False)
            self.hint.setText("已选中 2 条记录，点击「对比选中的两次记录」查看整改变化")
        elif not ids:
            self._current_run_id = None
            self._detail_status = {}
            self._set_action_buttons(False, False, False)

    # ---------- 单次记录明细 + 整改标记 ----------

    def _show_detail(self, run_id):
        if run_id is None:
            self._show_unavailable()
            return
        run, results, _quiz = storage.load_run(run_id)
        if run is None:
            self._show_unavailable()
            return
        self._current_run_id = run_id
        try:
            remediations = storage.get_remediations(run_id)
        except Exception:
            remediations = {}
        self.diff.blockSignals(True)
        self.diff.setColumnCount(5)
        self.diff.setHorizontalHeaderLabels(
            ["检测项", "名称", "类别", "结论", "整改状态"])
        self.diff.setRowCount(0)
        self._detail_status = {}
        for r in results:
            item_id, name, category, status = r[0], r[1], r[2], r[7]
            self._detail_status[item_id] = status
            state_code = (remediations.get(item_id) or ("", "", ""))[0]
            state_text, state_color = REMEDIATION_TEXT.get(
                state_code, ("未标记", "#9ab5a2"))
            row = self.diff.rowCount()
            self.diff.insertRow(row)
            values = [item_id, name, category, STATUS_TEXT.get(status, status), state_text]
            for c, v_ in enumerate(values):
                item = QTableWidgetItem(str(v_))
                if c == 4:
                    item.setForeground(QColor(state_color))
                self.diff.setItem(row, c, item)
        self.diff.blockSignals(False)
        self._update_stats()
        self._update_action_buttons()
        self.hint.setText(
            "记录 #%d 明细：%s，共 %d 项；选中一项后点击下方按钮标记整改状态" % (
                run_id, run[1], len(results)))

    def _show_unavailable(self):
        """旧库记录缺少 run_id 时的提示与清理"""
        self._current_run_id = None
        self._detail_status = {}
        self.diff.setColumnCount(5)
        self.diff.setHorizontalHeaderLabels(
            ["检测项", "名称", "类别", "结论", "整改状态"])
        self.diff.setRowCount(0)
        self._update_stats()
        self._set_action_buttons(False, False, False)
        self.hint.setText("该历史记录来自旧库（缺少 run_id），无法查看明细与整改标记。")

    def _update_stats(self):
        if not self._current_run_id:
            self.stats.setText("已整改 0 项，待整改 0 项，不适用 0 项")
            return
        try:
            done, pending, ignored = storage.remediation_stats(self._current_run_id)
        except Exception:
            done = pending = ignored = 0
        self.stats.setText(
            "已整改 %d 项，待整改 %d 项，不适用 %d 项" % (done, pending, ignored))

    def _set_action_buttons(self, done_on, pending_on, ignored_on):
        self.btn_done.setEnabled(bool(done_on))
        self.btn_pending.setEnabled(bool(pending_on))
        self.btn_ignored.setEnabled(bool(ignored_on))

    def _update_action_buttons(self):
        row = self.diff.currentRow()
        item = self.diff.item(row, 0) if row >= 0 else None
        status = self._detail_status.get(item.text()) if item else None
        if not self._current_run_id or not status:
            self._set_action_buttons(False, False, False)
            return
        can_rectify = status in (STATUS_FAIL, STATUS_WARN)
        self._set_action_buttons(can_rectify, can_rectify, status == STATUS_MANUAL)

    def _mark_done(self):
        self._mark_remediation("done")

    def _mark_pending(self):
        self._mark_remediation("pending")

    def _mark_ignored(self):
        self._mark_remediation("ignored")

    def _mark_remediation(self, state):
        if self._current_run_id is None:
            QMessageBox.warning(
                self, "不可用",
                "该历史记录来自旧库，缺少 run_id，无法标记整改状态。")
            return
        row = self.diff.currentRow()
        item = self.diff.item(row, 0) if row >= 0 else None
        if item is None:
            QMessageBox.information(self, "提示", "请先选中一条检测项明细。")
            return
        item_id = item.text()
        status = self._detail_status.get(item_id)
        if state in ("done", "pending") and status not in (STATUS_FAIL, STATUS_WARN):
            QMessageBox.information(
                self, "提示", "仅「不符合」「部分符合」项可标记为已整改/待整改。")
            return
        if state == "ignored" and status != STATUS_MANUAL:
            QMessageBox.information(
                self, "提示", "仅「需人工核查」项可标记为不适用。")
            return
        try:
            storage.set_remediation(self._current_run_id, item_id, state)
        except Exception as e:
            QMessageBox.warning(self, "标记失败", str(e))
            return
        state_text, state_color = REMEDIATION_TEXT[state]
        cell = self.diff.item(row, 4)
        if cell:
            cell.setText(state_text)
            cell.setForeground(QColor(state_color))
        name_item = self.diff.item(row, 1)
        self._update_stats()
        self._update_run_row(self._current_run_id)
        self.hint.setText("已将「%s」标记为%s" % (
            name_item.text() if name_item else item_id, state_text))

    def _update_run_row(self, run_id):
        """同步更新列表中的「已整改」计数"""
        for row in range(self.table.rowCount()):
            it = self.table.item(row, 0)
            if not it or it.text() != str(run_id):
                continue
            try:
                done = storage.remediation_stats(run_id)[0]
            except Exception:
                done = 0
            cell = self.table.item(row, 8)
            if cell:
                cell.setText(str(done))
                if done:
                    cell.setForeground(QColor("#22c55e"))
            break

    # ---------- 两次记录对比 ----------

    def _compare(self):
        ids = self._selected_ids()
        if len(ids) != 2:
            QMessageBox.information(self, "提示", "请按住 Ctrl 选中两行记录进行对比。")
            return
        old_id, new_id = min(ids), max(ids)
        rows = storage.compare_runs(old_id, new_id)
        self._current_run_id = None
        self._detail_status = {}
        self._update_stats()
        self._set_action_buttons(False, False, False)
        self.diff.setColumnCount(6)
        self.diff.setHorizontalHeaderLabels(
            ["检测项", "名称", "类别", "上次结论", "本次结论", "对比状态"])
        self.diff.setRowCount(0)
        trend_map = {
            "fixed": ("已整改 ✓", "#22c55e"), "still": ("仍不符合", "#ef4444"),
            "new_issue": ("新增问题 ⚠", "#f89800"), "same": ("无变化", "#6b8a77"),
            "changed": ("结论变化", "#7bc043"), "new_item": ("本次新增项", "#8b5cf6"),
        }
        for iid, name, cat, old_s, new_s, trend in rows:
            row = self.diff.rowCount()
            self.diff.insertRow(row)
            text, color = trend_map.get(trend, (trend, "#6b8a77"))
            for c, v_ in enumerate([iid, name, cat, old_s, new_s, text]):
                item = QTableWidgetItem(str(v_))
                if c == 5:
                    item.setForeground(QColor(color))
                self.diff.setItem(row, c, item)
        self.hint.setText("对比结果：记录 #%d（旧） vs 记录 #%d（新），共 %d 项" % (old_id, new_id, len(rows)))

    def _delete(self):
        ids = self._selected_ids()
        if not ids:
            return
        if QMessageBox.question(self, "确认", "确定删除选中的 %d 条记录？" % len(ids)) != QMessageBox.Yes:
            return
        for i in ids:
            storage.delete_run(i)
        self.refresh()


# ---------------- 设置对话框 ----------------

class SettingsDialog(QDialog):
    """系统设置：报告输出、连接参数、主题与历史库备份恢复"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("系统设置")
        self.setWindowIcon(app_icon())
        # 去掉标题栏右上角的「?」帮助按钮
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setMinimumWidth(640)
        self.cfg = appconfig.load()
        self._build()

    def _path_row(self, edit, slot):
        """输入框 + 选择按钮 的横向组合"""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        h.addWidget(edit, 1)
        btn = QPushButton("选择…")
        btn.setObjectName("ghost")
        btn.clicked.connect(slot)
        h.addWidget(btn)
        return w

    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 20, 24, 16)
        v.setSpacing(12)

        title = QLabel("系统设置")
        title.setObjectName("pageTitle")
        v.addWidget(title)
        sub = QLabel("设置保存到本机用户目录，修改后立即生效。")
        sub.setObjectName("pageSub")
        v.addWidget(sub)

        form = QFormLayout()
        form.setContentsMargins(0, 4, 0, 0)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        # —— 报告相关 ——
        self.report_dir_edit = QLineEdit(str(self.cfg.get("report_dir", "")))
        self.report_dir_edit.setPlaceholderText("报告导出目录")
        form.addRow("报告输出目录：", self._path_row(self.report_dir_edit, self._pick_report_dir))

        self.title_edit = QLineEdit(str(self.cfg.get("report_title", "")))
        form.addRow("报告标题：", self.title_edit)

        self.org_edit = QLineEdit(str(self.cfg.get("org_name", "")))
        form.addRow("编制单位：", self.org_edit)

        self.logo_edit = QLineEdit(str(self.cfg.get("logo_path", "")))
        self.logo_edit.setPlaceholderText("可留空，报告将不显示 LOGO")
        form.addRow("LOGO 图片路径：", self._path_row(self.logo_edit, self._pick_logo))

        # —— 连接参数 ——
        self.snmp_edit = QLineEdit(str(self.cfg.get("snmp_community", "")))
        self.snmp_edit.setPlaceholderText("如 public（只读团体字）")
        form.addRow("SNMP 默认团体名：", self.snmp_edit)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setSuffix(" 秒")
        try:
            self.timeout_spin.setValue(int(self.cfg.get("timeout", 15)))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(15)
        form.addRow("连接超时：", self.timeout_spin)

        self.operator_edit = QLineEdit(str(self.cfg.get("operator", "")))
        self.operator_edit.setPlaceholderText("检测人姓名，显示在报告中")
        form.addRow("检测人：", self.operator_edit)

        # —— 主题与行为 ——
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("暗色", "dark")
        self.theme_combo.addItem("亮色", "light")
        self.theme_combo.setCurrentIndex(
            1 if str(self.cfg.get("theme", "light")).lower() == "light" else 0)
        form.addRow("界面主题：", self.theme_combo)
        # 切换下拉即时预览主题（取消/关闭时恢复原主题）
        self.theme_combo.currentIndexChanged.connect(self._preview_theme)

        self.mask_check = QCheckBox("日志与报告中隐藏口令等敏感信息")
        self.mask_check.setChecked(bool(self.cfg.get("mask_secrets", True)))
        form.addRow("敏感信息脱敏：", self.mask_check)

        self.tray_check = QCheckBox("关闭窗口时最小化到系统托盘")
        self.tray_check.setChecked(bool(self.cfg.get("minimize_to_tray", False)))
        form.addRow("托盘行为：", self.tray_check)

        self.sign_check = QCheckBox("在报告末尾附加校验码")
        self.sign_check.setChecked(bool(self.cfg.get("report_signature", True)))
        form.addRow("报告校验码：", self.sign_check)

        v.addLayout(form)

        # —— 历史库备份 / 恢复 + 取消 / 保存 ——
        foot = QHBoxLayout()
        foot.setSpacing(8)
        self.backup_btn = QPushButton("备份历史库")
        self.backup_btn.setObjectName("ghost")
        self.backup_btn.clicked.connect(self._backup_db)
        self.restore_btn = QPushButton("恢复历史库")
        self.restore_btn.setObjectName("ghost")
        self.restore_btn.clicked.connect(self._restore_db)
        foot.addWidget(self.backup_btn)
        foot.addWidget(self.restore_btn)
        foot.addStretch(1)
        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("ghost")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save)
        foot.addWidget(cancel_btn)
        foot.addWidget(save_btn)
        v.addLayout(foot)

    def _pick_report_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "选择报告输出目录", self.report_dir_edit.text().strip() or os.path.expanduser("~"))
        if path:
            self.report_dir_edit.setText(path)

    def _pick_logo(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 LOGO 图片", self.logo_edit.text().strip() or os.path.expanduser("~"),
            "图片文件 (*.png *.jpg *.jpeg *.ico *.bmp);;所有文件 (*)")
        if path:
            self.logo_edit.setText(path)

    def _backup_db(self):
        default = os.path.join(
            os.path.expanduser("~"), "Desktop",
            "等保历史备份-%s.db" % datetime.now().strftime("%Y%m%d"))
        path, _ = QFileDialog.getSaveFileName(
            self, "备份历史库", default, "SQLite 数据库 (*.db);;所有文件 (*)")
        if not path:
            return
        try:
            storage.backup_db(path)
        except Exception as e:
            QMessageBox.warning(self, "备份失败", secret.sanitize(str(e)))
            return
        try:
            storage.add_log("INFO", "历史库已备份：%s" % path)
        except Exception:
            pass
        QMessageBox.information(self, "备份成功", "历史库已备份到：\n%s" % path)

    def _restore_db(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择历史库备份", os.path.join(os.path.expanduser("~"), "Desktop"),
            "SQLite 数据库 (*.db);;所有文件 (*)")
        if not path:
            return
        if QMessageBox.question(
                self, "确认恢复",
                "恢复将用备份文件覆盖当前历史记录。\n"
                "当前历史库会先自动备份为 ea_history.db.before_restore。\n\n确定继续？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            storage.restore_db(path)
        except Exception as e:
            QMessageBox.warning(self, "恢复失败", secret.sanitize(str(e)))
            return
        try:
            storage.add_log("INFO", "历史库已从备份恢复：%s" % path)
        except Exception:
            pass
        # 刷新历史页（HistoryPage 提供 refresh；兼容可能的 reload）
        p = self.parent()
        history_page = getattr(p, "history_page", None) if p is not None else None
        if history_page is not None:
            if hasattr(history_page, "reload"):
                history_page.reload()
            elif hasattr(history_page, "refresh"):
                history_page.refresh()
        QMessageBox.information(self, "恢复成功", "历史库已从备份恢复：\n%s" % path)

    def _preview_theme(self):
        """主题下拉切换时实时预览，不写入配置"""
        p = self.parent()
        if p is None:
            return
        theme = str(self.theme_combo.currentData() or "light").lower()
        p.setStyleSheet(_build_qss(theme))

    def reject(self):
        """取消 / 关闭窗口：把主界面还原为已保存的主题"""
        p = self.parent()
        if p is not None and hasattr(p, "_apply_theme"):
            p._apply_theme()
        super().reject()

    def _save(self):
        cfg = {
            "report_dir": self.report_dir_edit.text().strip(),
            "report_title": self.title_edit.text().strip(),
            "org_name": self.org_edit.text().strip(),
            "logo_path": self.logo_edit.text().strip(),
            "snmp_community": self.snmp_edit.text().strip(),
            "timeout": int(self.timeout_spin.value()),
            "operator": self.operator_edit.text().strip(),
            "theme": self.theme_combo.currentData() or "light",
            "mask_secrets": self.mask_check.isChecked(),
            "minimize_to_tray": self.tray_check.isChecked(),
            "report_signature": self.sign_check.isChecked(),
        }
        try:
            appconfig.save(cfg)
        except Exception as e:
            QMessageBox.warning(self, "保存失败", secret.sanitize(str(e)))
            return
        p = self.parent()
        if p is not None and hasattr(p, "_apply_theme"):
            p._apply_theme()
        try:
            storage.add_log("INFO", "系统设置已保存：主题=%s，超时=%s 秒"
                            % (cfg["theme"], cfg["timeout"]))
        except Exception:
            pass
        QMessageBox.information(self, "设置已保存", "设置已保存并立即生效。")
        self.accept()


# ---------------- 运行日志对话框 ----------------

class LogDialog(QDialog):
    """运行日志查看：关键字过滤、刷新、清空、导出"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("运行日志")
        self.setWindowIcon(app_icon())
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.resize(900, 600)
        self._build()
        self.reload()

    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 18, 20, 16)
        v.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(QLabel("级别："))
        self.level_combo = QComboBox()
        self.level_combo.addItem("全部", "")
        for lv in ("ERROR", "WARNING", "INFO"):
            self.level_combo.addItem(lv, lv)
        self.level_combo.currentIndexChanged.connect(self.reload)
        top.addWidget(self.level_combo)
        top.addWidget(QLabel("关键字："))
        self.keyword_edit = QLineEdit()
        self.keyword_edit.setPlaceholderText("按消息内容过滤，留空显示全部")
        self.keyword_edit.returnPressed.connect(self.reload)
        top.addWidget(self.keyword_edit, 1)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.reload)
        top.addWidget(refresh_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghost")
        clear_btn.clicked.connect(self._clear)
        top.addWidget(clear_btn)
        export_btn = QPushButton("导出")
        export_btn.setObjectName("ghost")
        export_btn.clicked.connect(self._export)
        top.addWidget(export_btn)
        v.addLayout(top)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QPlainTextEdit.NoWrap)
        v.addWidget(self.view, 1)

        self.hint = QLabel("最多显示最近 500 条日志（按时间正序）。")
        self.hint.setObjectName("muted")
        v.addWidget(self.hint)

    def reload(self):
        keyword = self.keyword_edit.text().strip()
        level = str(self.level_combo.currentData() or "").upper()
        try:
            rows = storage.list_logs(500, keyword)
        except Exception as e:
            self.view.setPlainText("读取日志失败：%s" % secret.sanitize(str(e)))
            return
        if level:
            rows = [r for r in rows if str(r[1]).upper() == level]
        lines = ["%s [%s] %s" % (ts, lv, msg) for ts, lv, msg in reversed(rows)]
        self.view.setPlainText("\n".join(lines))
        bar = self.view.verticalScrollBar()
        bar.setValue(bar.maximum())
        scope = ("级别 %s" % level) if level else "全部级别"
        self.hint.setText("共 %d 条日志（%s，最多显示最近 500 条，按时间正序）。"
                          % (len(rows), scope))

    def _clear(self):
        if QMessageBox.question(
                self, "确认清空", "确定清空全部运行日志？此操作不可恢复。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            storage.clear_logs()
        except Exception as e:
            QMessageBox.warning(self, "清空失败", secret.sanitize(str(e)))
            return
        self.reload()

    def _export(self):
        default = os.path.join(
            os.path.expanduser("~"), "Desktop",
            "运行日志-%s.log" % datetime.now().strftime("%Y%m%d"))
        path, _ = QFileDialog.getSaveFileName(
            self, "导出运行日志", default, "日志文件 (*.log);;文本文件 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.view.toPlainText())
        except Exception as e:
            QMessageBox.warning(self, "导出失败", secret.sanitize(str(e)))
            return
        QMessageBox.information(self, "导出成功", "日志已导出到：\n%s" % path)


# ---------------- 主窗口 ----------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("%s %s" % (APP_NAME, APP_VERSION))
        self.setWindowIcon(app_icon())
        # 去掉标题栏右上角的「?」帮助按钮
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.resize(1200, 760)
        self.state = {"level": "三级", "target": "本机",
                      "target_conf": {"mode": "local"},
                      "db_conf": {},
                      "layers": [l for l, _c in LAYERS],
                      "summary": None, "quiz_answers": {}}

        central = QWidget()
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        nav_wrap = QWidget()
        nav_wrap.setObjectName("nav")
        nav_wrap.setFixedWidth(190)
        nv = QVBoxLayout(nav_wrap)
        nv.setContentsMargins(0, 0, 0, 14)
        nv.setSpacing(0)
        # 导航栏顶部：EA 图标（与网站/打包图标统一）
        logo_row = QHBoxLayout()
        logo_row.setContentsMargins(0, 16, 0, 8)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(app_icon().pixmap(QSize(48, 48)))
        logo_row.addStretch(1)
        logo_row.addWidget(logo_lbl)
        logo_row.addStretch(1)
        nv.addLayout(logo_row)
        self.nav = QListWidget()
        self.nav.setFocusPolicy(Qt.NoFocus)
        self.nav.setIconSize(QSize(16, 16))
        self.nav.setSpacing(0)
        for label, icon_name in (("检测范围", "scope"), ("技术检测", "tech"),
                                 ("检测报告", "report"), ("历史对比", "history")):
            QListWidgetItem(asset_icon(icon_name), label, self.nav)
        # 启动后直接显示「关于」页：导航不预选，点击菜单才切换对应界面
        self.nav.blockSignals(True)
        self.nav.setCurrentRow(-1)
        self.nav.blockSignals(False)
        nv.addWidget(self.nav, 1)
        # 导航底部入口：设置 / 运行日志（图标来自 assets/icons，间距紧凑、文字偏下）
        self.settings_btn = QPushButton("系统设置")
        self.settings_btn.setObjectName("aboutLink")
        self.settings_btn.setIcon(asset_icon("settings"))
        self.settings_btn.setIconSize(QSize(16, 16))
        self.settings_btn.setCursor(Qt.PointingHandCursor)
        self.settings_btn.setToolTip("打开系统设置")
        self.settings_btn.clicked.connect(self._open_settings)
        nv.addWidget(self.settings_btn)
        # 安全基线（原「离线安全基线 / CVE 更新」迁入系统设置下方菜单）
        self.baseline_btn = QPushButton("安全基线")
        self.baseline_btn.setObjectName("aboutLink")
        self.baseline_btn.setIcon(asset_icon("tech"))
        self.baseline_btn.setIconSize(QSize(16, 16))
        self.baseline_btn.setCursor(Qt.PointingHandCursor)
        self.baseline_btn.setToolTip("打开安全基线库（CVE / 安全配置基线）")
        self.baseline_btn.clicked.connect(self._open_baseline)
        nv.addWidget(self.baseline_btn)
        # 使用帮助（内嵌使用文档，Windows / Linux 桌面版通用）
        self.help_btn = QPushButton("使用帮助")
        self.help_btn.setObjectName("aboutLink")
        self.help_btn.setIcon(asset_icon("quiz"))
        self.help_btn.setIconSize(QSize(16, 16))
        self.help_btn.setCursor(Qt.PointingHandCursor)
        self.help_btn.setToolTip("查看使用文档（安装 / 检测 / 问卷 / 报告 / 命令行）")
        self.help_btn.clicked.connect(self._open_help)
        nv.addWidget(self.help_btn)
        self.logs_btn = QPushButton("运行日志")
        self.logs_btn.setObjectName("aboutLink")
        self.logs_btn.setIcon(asset_icon("log"))
        self.logs_btn.setIconSize(QSize(16, 16))
        self.logs_btn.setCursor(Qt.PointingHandCursor)
        self.logs_btn.setToolTip("查看运行日志")
        self.logs_btn.clicked.connect(self._open_logs)
        nv.addWidget(self.logs_btn)
        self.about_btn = QPushButton(APP_NAME)
        self.about_btn.setObjectName("aboutLink")
        self.about_btn.setIcon(app_icon())
        self.about_btn.setIconSize(QSize(18, 18))
        self.about_btn.setCursor(Qt.PointingHandCursor)
        self.about_btn.setToolTip("点击查看关于信息")
        self.about_btn.clicked.connect(self._show_about)
        nv.addWidget(self.about_btn)
        h.addWidget(nav_wrap)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)

        self.stack = QStackedWidget()
        self.about_page = AboutPage(self.state)
        self.home = HomePage(self.state)
        self.check_page = CheckPage(self.state)
        self.quiz_page = QuizPage(self.state)
        self.report_page = ReportPage(self.state)
        self.history_page = HistoryPage(self.state)
        for w in (self.about_page, self.home, self.check_page, self.quiz_page,
                  self.report_page, self.history_page):
            self.stack.addWidget(w)
        rv.addWidget(self.stack, 1)

        bar = QLabel("⚠ 本工具仅用于内部等保自测，不作为等保评审依据")
        bar.setObjectName("noticeBar")
        rv.addWidget(bar)
        h.addWidget(right, 1)
        self.setCentralWidget(central)

        self.nav.currentRowChanged.connect(self._switch)
        self.home.start.connect(self._start_flow)
        self.home.manual_quiz.connect(self._open_manual_quiz)
        self.home.batch_finished.connect(self._after_batch)
        self.check_page.done.connect(self._after_check)
        self.check_page.failed.connect(self._log_check_failed)
        self.quiz_page.saved.connect(self._after_quiz)

        # —— 系统托盘 ——
        self._force_quit = False
        self._settings_dlg = None
        self._log_dlg = None
        self._tray_menu = QMenu(self)
        self.tray = QSystemTrayIcon(app_icon(), self)
        self.tray.setToolTip(APP_NAME)
        act_show = self._tray_menu.addAction("显示主界面")
        act_show.triggered.connect(self._restore_from_tray)
        act_settings = self._tray_menu.addAction("打开设置")
        act_settings.triggered.connect(self._open_settings)
        act_quit = self._tray_menu.addAction("退出")
        act_quit.triggered.connect(self._quit_app)
        self.tray.setContextMenu(self._tray_menu)
        self.tray.activated.connect(self._on_tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

        # —— 运行日志：WARNING 及以上写入历史库 ——
        self._install_log_handler()

        # 应用已保存的主题（暗色 / 亮色）
        self._apply_theme()

    def _install_log_handler(self):
        """安装一次全局日志处理器，重复创建窗口时复用"""
        root = logging.getLogger()
        handler = getattr(root, "_ea_db_handler", None)
        if handler is None:
            handler = _DbLogHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            root.addHandler(handler)
            root._ea_db_handler = handler
        self._log_handler = handler

    def _apply_theme(self):
        """按配置切换暗色 / 亮色主题"""
        theme = str(appconfig.get("theme", "light") or "light").lower()
        self.setStyleSheet(_build_qss(theme))

    def _log_check_failed(self, err):
        """检测失败写入运行日志（敏感信息按配置脱敏）"""
        try:
            msg = str(err)
            if appconfig.get("mask_secrets", True):
                msg = secret.sanitize(msg)
            storage.add_log("ERROR", "技术检测失败：%s" % msg)
        except Exception:
            pass

    # ========== 对话框入口 ==========

    def _open_settings(self):
        if not self.isVisible():
            self._restore_from_tray()
        if self._settings_dlg is not None and self._settings_dlg.isVisible():
            self._settings_dlg.raise_()
            self._settings_dlg.activateWindow()
            return
        self._settings_dlg = SettingsDialog(self)
        try:
            self._settings_dlg.exec_()
        finally:
            self._settings_dlg = None

    def _open_logs(self):
        if not self.isVisible():
            self._restore_from_tray()
        if self._log_dlg is not None and self._log_dlg.isVisible():
            self._log_dlg.raise_()
            self._log_dlg.activateWindow()
            return
        self._log_dlg = LogDialog(self)
        try:
            self._log_dlg.exec_()
        finally:
            self._log_dlg = None

    # ========== 系统托盘 ==========

    def _restore_from_tray(self):
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.DoubleClick, QSystemTrayIcon.Trigger):
            self._restore_from_tray()

    def _quit_app(self):
        self._force_quit = True
        try:
            self.tray.hide()
        except Exception:
            pass
        self.close()
        QApplication.quit()

    def closeEvent(self, event):
        """关闭窗口：按配置最小化到托盘，否则真正退出"""
        if (not self._force_quit and appconfig.get("minimize_to_tray")
                and self.tray is not None and QSystemTrayIcon.isSystemTrayAvailable()):
            event.ignore()
            self.hide()
            try:
                self.tray.showMessage(
                    APP_NAME,
                    "已最小化到托盘，双击图标可恢复窗口。",
                    QSystemTrayIcon.Information, 3000)
            except Exception:
                pass
            return
        try:
            if self.tray is not None:
                self.tray.hide()
        except Exception:
            pass
        event.accept()
        QApplication.quit()

    def _after_batch(self, results):
        """批量检测完成 → 写入所有成功目标到 state["batch_results"]，
        报告页显示多目标汇总；问卷按各目标检测层面动态生成。"""
        # 批量窗口已关闭（用户取消）：仅记录日志，不弹窗、不切换页面
        dlg = getattr(self.home, "_batch_dialog", None)
        if dlg is not None and not dlg.isVisible():
            try:
                storage.add_log("INFO", "批量检测在窗口关闭后结束，已跳过完成提示")
            except Exception:
                pass
            return
        total = len(results)
        ok_results = [(t, s) for t, s, e in results if s is not None]
        fail = total - len(ok_results)
        if not ok_results:
            return

        # 1. 保存所有成功结果到 state，报告页显示批量汇总
        self.state["batch_results"] = ok_results

        # 2. 以最后一个成功目标作为当前报告对象（兼容单目标流程）
        t, s = ok_results[-1]
        self.state["summary"] = s
        self.state["level"] = t.level
        self.state["target_desc"] = "批量检测：共 %d 个目标" % len(ok_results)

        # 3. 计算所有目标覆盖的层面（用于问卷动态过滤）
        all_layers = set()
        for _t, _s in ok_results:
            if _s and _s.results:
                from core.models import layer_of
                all_layers.update(layer_of(r.category) for r in _s.results)
        self.state["batch_layers"] = all_layers

        # 4. 问卷提示改为多目标（并退出人工核查问卷模式，按检测结果重新生成）
        self.quiz_page.exit_manual()
        layer_names = []
        for _t, _s in ok_results:
            ls = {layer_of(r.category) for r in _s.results} if _s and _s.results else set()
            if ls:
                layer_names.append("%s（%d个层面）" % (_t.name, len(ls)))
        self.quiz_page.info.setText(
            "批量检测完成（%d个目标），当前覆盖层面：%s；如需人工核查请在检测范围选择物理/管理层面" % (
                len(ok_results), "、".join(layer_names[:3]) + ("…" if len(layer_names) > 3 else "")))

        # 5. 弹窗汇总并询问是否查看检测报告（技术检测完成后不进入问卷评估）
        detail = "批量检测已完成：共 %d 个目标，成功 %d，失败 %d。\n" % (total, len(ok_results), fail)
        for _t, _s in ok_results:
            detail += "　%s：%.1f 分\n" % (_t.name, _s.score)
        detail += "\n报告已保存到「%s」文件夹。\n" % os.path.join(
            appconfig.get("report_dir"), "批量")
        detail += "是否进入「检测报告」查看结果？"
        mb = QMessageBox(self)
        mb.setWindowTitle("批量检测完成")
        mb.setText(detail)
        mb.setIcon(QMessageBox.Question)
        btn_yes = mb.addButton("查看检测报告", QMessageBox.YesRole)
        mb.addButton("稍后再说", QMessageBox.NoRole)
        mb.exec_()
        if mb.clickedButton() is btn_yes:
            dlg = getattr(self.home, "_batch_dialog", None)
            if dlg is not None:
                dlg.accept()
            self.nav.setCurrentRow(2)

    def _after_check(self):
        """技术检测完成：提示结果并引导查看检测报告（不进入问卷评估）"""
        self.report_page.refresh()
        s = self.state.get("summary")
        detail = ""
        if s:
            detail = "共检测 %d 项：符合 %d，不符合 %d，部分符合 %d，需人工核查 %d。\n\n" % (
                s.total, s.pass_count, s.fail_count, s.warn_count, s.manual_count)
        mb = QMessageBox(self)
        mb.setWindowTitle("技术检测完成")
        mb.setText(detail + "是否进入「检测报告」查看结果？\n（物理与通信、安全管理等人工核查项请在检测范围页选择对应层面进入问卷评估）")
        mb.setIcon(QMessageBox.Question)
        btn_yes = mb.addButton("查看检测报告", QMessageBox.YesRole)
        mb.addButton("稍后再说", QMessageBox.NoRole)
        mb.exec_()
        if mb.clickedButton() is btn_yes:
            self.nav.setCurrentRow(2)

    def _after_quiz(self):
        """问卷保存后 → 弹窗提示并引导进入检测报告"""
        self.report_page.refresh()
        mb = QMessageBox(self)
        mb.setWindowTitle("问卷已完成")
        mb.setText("人工核查问卷已保存。\n\n是否进入下一步「检测报告」？")
        mb.setIcon(QMessageBox.Question)
        btn_yes = mb.addButton("进入检测报告", QMessageBox.YesRole)
        mb.addButton("稍后再说", QMessageBox.NoRole)
        mb.exec_()
        if mb.clickedButton() is btn_yes:
            self.nav.setCurrentRow(2)

    def _show_about(self):
        QMessageBox.about(
            self, "关于",
            "<h3>%s %s</h3>"
            "<p>简称：%s（%s）</p>"
            "<p>按 GB/T 22239-2019 等保二级 / 三级要求逐条落地检测项：技术类自动取证，"
            "物理与管理类以问卷评估人工核查，可导出 HTML / Word / PDF 自查报告并跟踪整改。</p>"
            "<p>在线演示：<a href='%s'>%s</a></p>"
            "<p>本工具仅用于内部等保自测，不作为等保评审依据。</p>"
            "<p style='color:#6f8f7c;'>内蒙古勤加软件有限公司　　<a href='https://qinplus.com'>qinplus.com</a></p>"
            % (APP_NAME, APP_VERSION, APP_SHORT, APP_EN, APP_DEMO, APP_DEMO))

    def _goto_about_page(self):
        """返回启动时的关于界面（清空左侧导航选中态）"""
        self.nav.blockSignals(True)
        self.nav.setCurrentRow(-1)
        self.nav.blockSignals(False)
        self.stack.setCurrentIndex(0)

    def _goto_home(self):
        """关于页「开始测评」→ 检测范围界面"""
        self.nav.setCurrentRow(0)
        self._switch(0)  # 兜底：nav 已在第 0 行时不触发 currentRowChanged

    def _open_baseline(self):
        if not self.isVisible():
            self._restore_from_tray()
        dlg = BaselineDialog(self)
        dlg.exec_()

    def _open_help(self):
        """使用帮助：内嵌使用文档（离线可用，Windows / Linux 通用）"""
        if not self.isVisible():
            self._restore_from_tray()
        dlg = QDialog(self)
        dlg.setWindowTitle("使用帮助 - %s" % APP_NAME)
        dlg.resize(820, 620)
        v = QVBoxLayout(dlg)
        v.setContentsMargins(12, 12, 12, 12)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        # 关闭横向滚动条并允许代码块折行，避免底部出现多余的横向滚动条
        browser.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        browser.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        browser.document().setDefaultStyleSheet("pre{white-space:pre-wrap;}")
        browser.setHtml(HELP_HTML)
        v.addWidget(browser, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dlg.accept)
        row.addWidget(close_btn)
        v.addLayout(row)
        dlg.exec_()

    def _switch(self, row):
        # 导航行 → 页面栈索引：0=检测范围 1=技术检测 2=检测报告 3=历史对比
        # （关于=0、问卷评估=3 不在左侧菜单中：启动直接显示关于，问卷由人工核查层进入）
        idx = {0: 1, 1: 2, 2: 4, 3: 5}.get(row, 0)
        self.stack.setCurrentIndex(idx)
        if idx == 4:
            self.report_page.refresh()
        elif idx == 5:
            self.history_page.refresh()

    def _open_manual_quiz(self, categories):
        """物理与通信 / 安全管理等人工核查层：直接进入问卷评估（不经左侧菜单）"""
        self.quiz_page.build_manual(categories)
        self.stack.setCurrentIndex(3)

    def _start_flow(self):
        self.quiz_page.exit_manual()
        self.nav.setCurrentRow(1)
        self.check_page.start_check()
