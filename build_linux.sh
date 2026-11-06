#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Linux 打包脚本：生成独立可执行文件 + .deb 安装包（适配麒麟 Kylin V10 / 统信 UOS / Deepin）
#
# 说明：如需 configure / make / make install 或 RPM 安装方式，
#       请直接使用仓库根目录的 configure 与 Makefile.in：
#         ./configure --prefix=/usr && make && sudo make install
#         make rpm
#
# 运行：
#   chmod +x build_linux.sh
#   ./build_linux.sh
#
# 依赖：
#   sudo apt install python3-pip python3-dev binutils
#   pip3 install pyinstaller PyQt5 python-docx paramiko
#   pip3 install pywinrm   # 可选：需要在Linux上检测远程Windows服务器时安装
#   （.deb 打包需要 dpkg-deb，通常系统自带）

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="qinplus-dengbao"
VERSION="1.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
DIST="$ROOT/dist"
BUILD="$ROOT/build"

echo "============================================================"
echo " 勤加软件等保测评助手 - Linux 打包 (架构: $ARCH)"
echo "============================================================"

# ---- 1. 清理 ----
echo "[1/4] 清理旧产物..."
rm -rf "$DIST" "$BUILD"

# ---- 2. PyInstaller 打包 ----
echo "[2/4] PyInstaller 打包..."
python3 -m PyInstaller --noconfirm "$ROOT/ea_dengbao.spec"

BIN="$DIST/ea_dengbao"
if [ ! -f "$BIN" ]; then
    echo "✗ 未找到产物 $BIN"
    exit 1
fi
echo "✓ 生成可执行文件: $BIN ($(du -m "$BIN" | cut -f1) MB)"

# ---- 3. 构建 .deb 包目录 ----
echo "[3/4] 构建 .deb 安装包结构..."
DEB_ROOT="$DIST/deb/${APP_NAME}_${VERSION}_${ARCH}"
rm -rf "$DEB_ROOT"

# DEBIAN 控制信息
mkdir -p "$DEB_ROOT/DEBIAN"
cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: qinplus-dengbao
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libc6, libgl1, libegl1
Maintainer: EA Dengbao <support@example.com>
Description: 勤加软件等保测评助手
 按 GB/T 22239-2019 等保二级/三级要求执行技术检测与人工核查问卷，
 支持导出 HTML / Word / PDF 自查报告。
 .
 适配 麒麟Kylin V10 / 统信UOS / Deepin 等国产 Linux 发行版。
Installed-Size: $(du -k "$BIN" | cut -f1)
EOF

# postinst 脚本：创建桌面快捷方式、确保可执行
cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOFX'
#!/bin/sh
set -e
# 刷新桌面数据库
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
fi
# 创建数据目录
mkdir -p /root/.ea_dengbao 2>/dev/null || true
# 有图形桌面时，在安装者桌面创建快捷方式（纯服务器自动跳过）
for u in "${SUDO_USER:-}" "$(logname 2>/dev/null || true)"; do
    [ -n "$u" ] || continue
    [ "$u" != "root" ] || continue
    H="$(getent passwd "$u" 2>/dev/null | cut -d: -f6)"
    [ -n "$H" ] && [ -d "$H" ] || continue
    D="$(sudo -u "$u" xdg-user-dir DESKTOP 2>/dev/null || true)"
    [ -n "$D" ] && [ -d "$D" ] || D="$H/Desktop"
    [ -d "$D" ] || D="$H/桌面"
    [ -d "$D" ] || continue
    cp -f /usr/share/applications/qinplus-dengbao.desktop "$D/qinplus-dengbao.desktop" 2>/dev/null || continue
    chmod 755 "$D/qinplus-dengbao.desktop" 2>/dev/null || true
    chown "$u": "$D/qinplus-dengbao.desktop" 2>/dev/null || true
    sudo -u "$u" gio set "$D/qinplus-dengbao.desktop" metadata::trusted true 2>/dev/null || true
    break
done
exit 0
EOFX
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

# postrm 脚本
cat > "$DEB_ROOT/DEBIAN/postrm" <<'EOFX'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
fi
exit 0
EOFX
chmod 755 "$DEB_ROOT/DEBIAN/postrm"

# 可执行文件
mkdir -p "$DEB_ROOT/usr/bin"
cp "$BIN" "$DEB_ROOT/usr/bin/${APP_NAME}"
chmod 755 "$DEB_ROOT/usr/bin/${APP_NAME}"

# 桌面入口
mkdir -p "$DEB_ROOT/usr/share/applications"
cat > "$DEB_ROOT/usr/share/applications/${APP_NAME}.desktop" <<EOF
[Desktop Entry]
Name=勤加软件等保测评助手
Name[zh_CN]=勤加软件等保测评助手
Comment=等保 2.0 自查与测评辅助（技术检测 / 问卷评估 / 报告输出）
Exec=${APP_NAME}
Icon=${APP_NAME}
Terminal=false
Type=Application
Categories=System;Security;Utility;
StartupNotify=true
EOF

# 图标（用系统默认盾牌图标占位；如需自定义，替换 assets/icon.png 并在此复制）
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps"
if [ -f "$ROOT/assets/icon.png" ]; then
    cp "$ROOT/assets/icon.png" "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png"
else
    # 生成一个简单的蓝色盾牌占位图标（SVG 转 PNG 需要工具，这里直接用系统图标名）
    # 无自定义图标时使用系统 security 图标
    cp /usr/share/icons/hicolor/256x256/apps/preferences-system-security.png \
       "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png" 2>/dev/null || true
fi

# ---- 4. 打包 .deb ----
echo "[4/4] 打包 .deb ..."
dpkg-deb --build --root-owner-group "$DEB_ROOT" "$DIST"
DEB_FILE="$DIST/${APP_NAME}_${VERSION}_${ARCH}.deb"

echo ""
echo "============================================================"
echo " 打包完成！"
echo "============================================================"
echo "独立可执行文件: $BIN"
echo "安装包 (.deb) : $DEB_FILE"
echo ""
echo "安装方式："
echo "  sudo dpkg -i \"$DEB_FILE\""
echo "  sudo apt-get install -f   # 修复依赖（如需要）"
echo ""
echo "卸载方式："
echo "  sudo dpkg -r qinplus-dengbao"
echo ""
echo "注意：部分检测项（如 /etc/shadow、auditd 配置）需要 root 权限运行："
echo "  sudo qinplus-dengbao"
