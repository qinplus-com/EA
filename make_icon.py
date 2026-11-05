# -*- coding: utf-8 -*-
"""生成应用图标（蓝色盾牌 + EA 字样）
输出：assets/icon.ico (Windows) / assets/icon.png (Linux)
依赖 PyQt5（已在 requirements 中）
"""
import os
from pathlib import Path
from PyQt5.QtCore import Qt, QRectF
from PyQt5.QtGui import QPainter, QPixmap, QColor, QFont, QPainterPath, QBrush, QPen
from PyQt5.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ASSETS.mkdir(exist_ok=True)


def make_icon(size=256):
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.TextAntialiasing)

    # 背景圆形渐变
    grad_rect = QRectF(0, 0, size, size)
    from PyQt5.QtGui import QRadialGradient
    grad = QRadialGradient(grad_rect.center(), size / 2)
    grad.setColorAt(0, QColor("#3b82f6"))
    grad.setColorAt(1, QColor("#1d4ed8"))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.NoPen)
    p.drawEllipse(grad_rect)

    # 盾牌形状
    path = QPainterPath()
    w = size * 0.56
    h = size * 0.66
    x = (size - w) / 2
    y = size * 0.16
    path.moveTo(x + w / 2, y)
    path.lineTo(x + w, y + h * 0.18)
    path.lineTo(x + w, y + h * 0.55)
    path.quadTo(x + w / 2, y + h * 1.05, x + w / 2, y + h * 1.05)
    path.quadTo(x + w / 2, y + h * 1.05, x, y + h * 0.55)
    path.lineTo(x, y + h * 0.18)
    path.closeSubpath()

    # 盾牌内部深色
    p.setBrush(QBrush(QColor("#1e3a8a")))
    p.drawPath(path)

    # 盾牌边框
    p.setPen(QPen(QColor("#93c5fd"), size * 0.02))
    p.setBrush(Qt.NoBrush)
    p.drawPath(path)

    # "EA" 文字
    font = QFont("Arial Black")
    font.setPixelSize(int(size * 0.26))
    font.setBold(True)
    p.setFont(font)
    p.setPen(QColor("#ffffff"))
    text_rect = QRectF(0, y + h * 0.12, size, size * 0.32)
    p.drawText(text_rect, Qt.AlignCenter, "EA")

    p.end()
    return pix


def main():
    app = QApplication([])
    pix = make_icon(256)

    # PNG (Linux)
    png = ASSETS / "icon.png"
    pix.save(str(png), "PNG")
    print("✓", png)

    # ICO (Windows) - 保存多尺寸
    ico = ASSETS / "icon.ico"
    sizes = [16, 32, 48, 64, 128, 256]
    pix_list = [make_icon(s) for s in sizes]
    # QPixmap 不能直接存多尺寸 ico，用 PIL 或逐帧；这里用 Qt 的 write 到单一尺寸
    # 为兼容，直接用 256 尺寸保存为 ico（Windows 会自动缩放）
    pix.save(str(ico), "ICO")
    print("✓", ico)


if __name__ == "__main__":
    main()
