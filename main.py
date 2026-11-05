# -*- coding: utf-8 -*-
"""勤加等保测评助手 - 桌面版入口（Windows / 国产Linux）"""
import os
import sys

# 保证以脚本所在目录为根导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from ui.main_window import MainWindow, QSS, LIGHT_QSS, app_icon
    from core import appconfig

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    # 默认明亮主题；暗色时再切到深色样式
    theme = str(appconfig.get("theme", "light") or "light").lower()
    app.setStyleSheet(LIGHT_QSS if theme == "light" else QSS)
    app.setWindowIcon(app_icon())

    # 启动即写入一条运行日志，保证日志页非空
    try:
        from core import storage
        storage.add_log("INFO", "应用启动：勤加等保测评助手 v1.0")
    except Exception:
        pass

    # 已按需求取消启动动画：直接打开主界面
    w = MainWindow()
    w.show()
    w.raise_()
    w.activateWindow()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
