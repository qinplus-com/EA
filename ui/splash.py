# -*- coding: utf-8 -*-
"""启动动画：用 assets/video 下的分镜图片做淡入淡出播放。

设计要点：
- 不依赖视频解码库（Qt Multimedia 打包后受系统解码器影响，容易黑屏）
- 6 张分镜，512×512 显示，每张 600ms，共 3.6 秒（满足「至少 3 秒」）
- 分镜全部播完后才显示「勤加软件 / qinplus.com」，停留后自动关闭
- 底部显示「正在加载」状态文字（单次绘制，无描边，避免重影）
- 整窗透明，图案带品牌色光晕；播放结束自动隐藏并释放，不会悬浮在主界面之上
"""
import os
import sys

from PyQt5.QtCore import Qt, QTimer, QElapsedTimer, QRect, QPoint, pyqtSignal
from PyQt5.QtGui import (QPixmap, QPainter, QColor, QFont, QLinearGradient)
from PyQt5.QtWidgets import QApplication, QWidget

# 分镜播放时长（6 张 × 600ms = 3.6s）
VIDEO_MS = 3600
# 分镜播完后 LOGO 淡出，窗口收拢并移动到左下角，品牌文字单独显示后淡出
LOGO_FADE_OUT_MS = 300
MOVE_START_MS = 3900
MOVE_MS = 350
END_W, END_H = 210, 64      # 左下角小窗尺寸（与主界面底部品牌位对齐）
BRAND_START_MS = 3900
BRAND_FADE_MS = 350
BRAND_OUT_START_MS = 4600
BRAND_OUT_MS = 350
TOTAL_MS = 5000
FADE_MS = 240               # 相邻分镜交叉淡入淡出时长

LOGO_SIZE = 512             # 分镜显示边长（512×512）
BAND_HEIGHT = 64            # 底部状态/品牌栏
WINDOW_HEIGHT = LOGO_SIZE + BAND_HEIGHT
BRAND_TEXT = "勤加软件"
BRAND_DOMAIN = "qinplus.com"


def _asset_dir():
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    # 优先使用抠白底后的透明分镜（毛玻璃下才能透出背景）
    clean = os.path.join(base, "assets", "video", "clean")
    if os.path.isdir(clean) and os.listdir(clean):
        return clean
    return os.path.join(base, "assets", "video")


def load_frames():
    """按文件名顺序加载分镜图片（01.png ~ 06.png）"""
    d = _asset_dir()
    frames = []
    if not os.path.isdir(d):
        return frames
    for name in sorted(os.listdir(d)):
        if not name.lower().endswith((".png", ".jpg", ".jpeg")):
            continue
        pm = QPixmap(os.path.join(d, name))
        if pm.isNull():
            continue
        frames.append(pm.scaled(LOGO_SIZE, LOGO_SIZE, Qt.KeepAspectRatio,
                                Qt.SmoothTransformation))
    return frames


class SplashWindow(QWidget):
    """无边框启动动画窗口"""

    finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.frames = load_frames()
        self._done = False
        self._elapsed = QElapsedTimer()
        self._tints = {}          # 缓存各分镜的轮廓色块（描边/柔光用）

        self.setWindowFlags(Qt.Tool | Qt.FramelessWindowHint |
                            Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        # 整窗透明：只有图案与文字，不铺底色、不加白框
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setMinimumSize(1, 1)
        self.resize(LOGO_SIZE, WINDOW_HEIGHT)

        self._timer = QTimer(self)
        self._timer.setInterval(16)          # ≈60fps
        self._timer.timeout.connect(self._tick)
        self._start_geo = None
        self._end_geo = None
        self._target = None
        self._center()

    # ---------------- 生命周期 ----------------
    def has_frames(self):
        return bool(self.frames)

    def set_target(self, widget):
        """设置落点参照窗口（通常为主界面），最后收拢到其左下角"""
        self._target = widget
        self._refresh_end_geo()

    def _refresh_end_geo(self):
        """终点：主界面左下角「勤加软件 v1.0」位置；无主界面时退回屏幕左下角"""
        tw = getattr(self, "_target", None)
        if tw is not None:
            try:
                origin = tw.mapToGlobal(QPoint(0, 0))
                self._end_geo = QRect(origin.x() + 18,
                                      origin.y() + tw.height() - END_H - 14,
                                      END_W, END_H)
                return
            except Exception:
                pass
        screen = QApplication.primaryScreen()
        if not screen:
            return
        g = screen.availableGeometry()
        self._end_geo = QRect(g.left() + 18, g.bottom() - END_H - 14,
                              END_W, END_H)

    def _center(self):
        screen = QApplication.primaryScreen()
        if not screen:
            return
        g = screen.availableGeometry()
        self._start_geo = QRect(g.center().x() - LOGO_SIZE // 2,
                                g.center().y() - WINDOW_HEIGHT // 2,
                                LOGO_SIZE, WINDOW_HEIGHT)
        self._end_geo = None
        self._refresh_end_geo()
        self.setGeometry(self._start_geo)

    def start(self):
        """开始播放；无分镜时直接结束"""
        if not self.frames:
            self._finish()
            return
        self._elapsed.start()
        self._timer.start()

    def is_finished(self):
        return self._done

    def _finish(self):
        if self._done:
            return
        self._done = True
        self._timer.stop()
        self.finished.emit()
        # 结束后隐藏并释放，避免窗口滞留在最上层
        self.hide()
        self.setWindowFlag(Qt.WindowStaysOnTopHint, False)
        QTimer.singleShot(0, self.deleteLater)

    def skip(self):
        """跳过动画（直接到最后一帧并结束）"""
        if self._done:
            return
        self._elapsed.start() if not self._elapsed.isValid() else None
        self._finish()

    # ---------------- 绘制 ----------------
    def _tick(self):
        el = self._elapsed.elapsed()
        if el >= TOTAL_MS:
            self.update()
            self._finish()
            return
        # LOGO 淡出后，窗口向主界面左下角收拢
        if el > MOVE_START_MS and self._start_geo:
            if getattr(self, "_target", None) is not None:
                self._refresh_end_geo()
            if not self._end_geo:
                self._refresh_end_geo()
            pr = min(1.0, (el - MOVE_START_MS) / MOVE_MS)
            ease = 1 - (1 - pr) ** 3
            s, e = self._start_geo, self._end_geo
            self.setGeometry(QRect(
                int(s.x() + (e.x() - s.x()) * ease),
                int(s.y() + (e.y() - s.y()) * ease),
                int(s.width() + (e.width() - s.width()) * ease),
                int(s.height() + (e.height() - s.height()) * ease)))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)
        w, h = self.width(), self.height()
        # 透明背景：不绘制任何底色或边框
        if not self.frames:
            p.end()
            return

        t = min(self._elapsed.elapsed(), TOTAL_MS) if self._elapsed.isValid() else TOTAL_MS
        n = len(self.frames)
        # 分镜按 VIDEO_MS 铺满，播完后淡出，画面只留品牌文字
        vt = min(t, VIDEO_MS)
        slot = VIDEO_MS / n
        idx = min(int(vt // slot), n - 1)
        into = vt - idx * slot
        cur = self.frames[idx]
        logo_alpha = 1.0
        if t > VIDEO_MS:
            logo_alpha = max(0.0, 1.0 - (t - VIDEO_MS) / LOGO_FADE_OUT_MS)
        if logo_alpha > 0:
            x0 = (w - cur.width()) // 2
            # 沿 logo 轮廓叠两层品牌色柔光：透明背景上的「毛玻璃描边」
            self._draw_halo(p, idx, cur, x0, 0, logo_alpha)
            p.setOpacity(logo_alpha)
            p.drawPixmap(x0, 0, cur)

            # 与下一张交叉淡入
            if idx < n - 1 and into > slot - FADE_MS and vt < VIDEO_MS:
                nxt = self.frames[idx + 1]
                alpha = (into - (slot - FADE_MS)) / FADE_MS
                p.setOpacity(max(0.0, min(1.0, alpha)) * logo_alpha)
                p.drawPixmap((w - nxt.width()) // 2, 0, nxt)
            p.setOpacity(1.0)

        # LOGO 播完后，品牌文字单独显示（背景透明，仅文字浮在毛玻璃上）
        alpha_in = max(0.0, min(1.0, (t - BRAND_START_MS) / BRAND_FADE_MS))
        alpha_out = 1.0
        if t > BRAND_OUT_START_MS:
            alpha_out = max(0.0, 1.0 - (t - BRAND_OUT_START_MS) / BRAND_OUT_MS)
        text_alpha = alpha_in * alpha_out
        if text_alpha > 0:
            self._draw_brand(p, w, text_alpha)

        # 底部进度线（仅分镜阶段）
        if t < MOVE_START_MS:
            grad = QLinearGradient(0, 0, w, 0)
            grad.setColorAt(0.0, QColor("#0d74c4"))
            grad.setColorAt(1.0, QColor("#19d3f3"))
            p.setPen(Qt.NoPen)
            p.fillRect(0, h - 3, int(w * (t / MOVE_START_MS)), 3, grad)

        # 加载状态（仅 LOGO 播放阶段显示，单次绘制避免重影）
        if t < VIDEO_MS:
            dots = "." * (int(t // 400) % 4)
            p.setFont(QFont("Microsoft YaHei", 9))
            p.setPen(QColor(0, 0, 0, 70))
            p.drawText(1, LOGO_SIZE + 37, w - 16, 18,
                       Qt.AlignRight | Qt.AlignVCenter, "正在加载" + dots)
            p.setPen(QColor(255, 255, 255, 235))
            p.drawText(0, LOGO_SIZE + 36, w - 16, 18,
                       Qt.AlignRight | Qt.AlignVCenter, "正在加载" + dots)
        p.end()

    def _tint(self, idx, pm, color):
        """按分镜 alpha 轮廓生成纯色块（SourceIn），作为描边/柔光的形状底"""
        key = (idx, color.rgb())
        cached = self._tints.get(key)
        if cached is not None:
            return cached
        tint = QPixmap(pm.size())
        tint.fill(Qt.transparent)
        tp = QPainter(tint)
        tp.drawPixmap(0, 0, pm)
        tp.setCompositionMode(QPainter.CompositionMode_SourceIn)
        tp.fillRect(tint.rect(), color)
        tp.end()
        self._tints[key] = tint
        return tint

    def _draw_halo(self, p, idx, pm, x0, y0, opacity):
        """沿图案外轮廓叠三层品牌色柔光（越外越淡），透明背景下的毛玻璃描边"""
        layers = ((14, QColor(13, 116, 196), 14),
                  (8, QColor(25, 211, 243), 22),
                  (4, QColor(25, 211, 243), 30))
        for grow, color, alpha in layers:
            tint = self._tint(idx, pm, color)
            p.setOpacity((alpha / 100.0) * opacity)
            p.drawPixmap(x0 - grow, y0 - grow,
                         pm.width() + grow * 2, pm.height() + grow * 2, tint)
        p.setOpacity(1.0)

    def _draw_brand(self, p, w, alpha):
        """品牌文字靠左下角对齐：窗内向屏幕左下角收拢后落在「勤加软件 v1.0」位置"""
        h = self.height()
        x = 18
        f1 = QFont("Microsoft YaHei", 11, QFont.Bold)
        f1.setLetterSpacing(QFont.PercentageSpacing, 108)
        p.setFont(f1)
        p.setPen(QColor(0, 0, 0, 60))
        p.drawText(x + 1, h - 45, w - x - 6, 24, Qt.AlignLeft | Qt.AlignVCenter,
                   BRAND_TEXT)
        c = QColor(245, 252, 255)
        c.setAlphaF(alpha)
        p.setPen(c)
        p.drawText(x, h - 46, w - x - 6, 24, Qt.AlignLeft | Qt.AlignVCenter,
                   BRAND_TEXT)

        f2 = QFont("Microsoft YaHei", 8)
        f2.setLetterSpacing(QFont.PercentageSpacing, 104)
        p.setFont(f2)
        c2 = QColor(25, 211, 243)
        c2.setAlphaF(alpha)
        p.setPen(c2)
        p.drawText(x, h - 21, w - x - 6, 15, Qt.AlignLeft | Qt.AlignVCenter,
                   BRAND_DOMAIN)

    # ---------------- 交互 ----------------
    def keyPressEvent(self, event):
        # 保留 ESC 跳过（不对外提示）
        if event.key() == Qt.Key_Escape:
            self.skip()
        else:
            super().keyPressEvent(event)


class LogoAnim(QWidget):
    """导航栏顶部的循环 logo 动画：分镜依次淡入淡出、无限重复"""

    def __init__(self, size=120, slot_ms=600, fade_ms=180, parent=None):
        super().__init__(parent)
        self.frames = load_frames()
        self._slot = slot_ms
        self._fade = fade_ms
        self._idx = 0
        self._t = 0
        self._scaled = {}
        self.setFixedSize(size, size)
        # 只显示图案本身，背景交给导航栏
        self.setStyleSheet("background:transparent;border:none;")
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)
        if self.frames:
            self._timer.start()

    def _tick(self):
        if not self.frames:
            return
        self._t += 16
        while self._t >= self._slot:
            self._t -= self._slot
            self._idx = (self._idx + 1) % len(self.frames)
        self.update()

    def _pix(self, i):
        key = (i, self.width(), self.height())
        pm = self._scaled.get(key)
        if pm is None:
            pm = self.frames[i].scaled(self.width(), self.height(),
                                       Qt.KeepAspectRatio,
                                       Qt.SmoothTransformation)
            self._scaled[key] = pm
        return pm

    def paintEvent(self, event):
        if not self.frames:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)
        cur = self._pix(self._idx)
        p.drawPixmap((self.width() - cur.width()) // 2,
                     (self.height() - cur.height()) // 2, cur)
        # 与下一张交叉淡入，衔接更自然
        if self._t > self._slot - self._fade:
            nxt = self._pix((self._idx + 1) % len(self.frames))
            p.setOpacity((self._t - (self._slot - self._fade)) / self._fade)
            p.drawPixmap((self.width() - nxt.width()) // 2,
                         (self.height() - nxt.height()) // 2, nxt)
            p.setOpacity(1.0)
        p.end()
