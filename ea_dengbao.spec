# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('assets/icon.ico', 'assets'), ('assets/icon.png', 'assets'),
         ('data/security_baseline.json', 'data'), ('data/cve_db.json', 'data')]
# 导航与功能图标（扁平风格 PNG，保留图标自身配色）
import glob as _glob
for _p in _glob.glob('assets/icons/*.png'):
    datas.append((_p, 'assets/icons'))
binaries = []
# 启动动画分镜（透明背景版，毛玻璃窗口下显示）
for _n in ('01.png', '02.png', '03.png', '04.png', '05.png', '06.png'):
    datas.append(('assets/video/clean/' + _n, 'assets/video/clean'))
hiddenimports = ['openpyxl', 'paramiko', 'cryptography', 'PyQt5.sip', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'PyQt5.QtPrintSupport', 'docx', 'core.models', 'core.engine', 'core.storage', 'core.report', 'core.remote', 'core.baseline', 'core.config_loader', 'core.appconfig', 'core.secret', 'checks.advanced_checks', 'core.netdev', 'checks.network_checks', 'checks.windows_checks', 'checks.linux_checks', 'checks.db_checks', 'checks.middleware_checks', 'checks.app_checks', 'checks.platform_util', 'questionnaire', 'questionnaire.data', 'ui.splash']
tmp_ret = collect_all('pysnmp')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('docx')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ea_dengbao',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['assets\\icon.ico'],
)
