#!/bin/sh
# 勤加软件等保测评助手 - 桌面快捷方式安装
#
# 用法：sh install_desktop_shortcut.sh <已安装的 .desktop 路径>
# 说明：仅当系统存在图形桌面目录时创建；无桌面（纯服务器）时静默跳过。
set -e

SRC="$1"
[ -n "$SRC" ] && [ -f "$SRC" ] || exit 0

# 目标用户：sudo 调用者 > logname > 当前用户
TARGET_USER="${SUDO_USER:-}"
[ -z "$TARGET_USER" ] && TARGET_USER="$(logname 2>/dev/null || true)"
[ -z "$TARGET_USER" ] && TARGET_USER="$(id -un)"
[ "$TARGET_USER" = "root" ] && exit 0

HOME_DIR="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$HOME_DIR" ] || HOME_DIR="/home/$TARGET_USER"
[ -d "$HOME_DIR" ] || exit 0

# 桌面目录：优先 XDG 配置（可能为「桌面」「Bureaublad」等本地化名称）
DESK="$(
    sudo -u "$TARGET_USER" xdg-user-dir DESKTOP 2>/dev/null || true
)"
if [ -z "$DESK" ] || [ ! -d "$DESK" ]; then
    for d in "$HOME_DIR/桌面" "$HOME_DIR/Desktop" "$HOME_DIR/デスクトップ"; do
        [ -d "$d" ] && DESK="$d" && break
    done
fi
# 无图形桌面（目录不存在）则跳过
[ -n "$DESK" ] && [ -d "$DESK" ] || exit 0

DEST="$DESK/$(basename "$SRC")"
cp -f "$SRC" "$DEST"
chmod 755 "$DEST"
chown "$TARGET_USER": "$DEST" 2>/dev/null || true

# GNOME 需标记为可信，否则双击提示「不受信任的启动器」
sudo -u "$TARGET_USER" gio set "$DEST" metadata::trusted true 2>/dev/null || true
# KDE / XFCE 需可执行权限（上面已 chmod 755）

echo "已创建桌面快捷方式：$DEST"
exit 0
