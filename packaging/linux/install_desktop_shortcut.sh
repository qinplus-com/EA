#!/bin/sh
# 勤加软件等保测评助手 - 桌面快捷方式安装
#
# 用法：sh install_desktop_shortcut.sh <已安装的 .desktop 路径>
# 说明：
#   1. 仅当目标用户存在图形桌面目录时创建，纯服务器自动跳过；
#   2. 会把 Icon= 改写为绝对路径，避免 PREFIX 非 /usr 时图标主题找不到图；
#   3. 以该用户的 D-Bus 会话执行 gio，确保 metadata::trusted 能被 GNOME 识别。
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
DESK="$(sudo -u "$TARGET_USER" xdg-user-dir DESKTOP 2>/dev/null || true)"
if [ -z "$DESK" ] || [ ! -d "$DESK" ]; then
    for d in "$HOME_DIR/桌面" "$HOME_DIR/Desktop" "$HOME_DIR/デスクトップ"; do
        if [ -d "$d" ]; then DESK="$d"; break; fi
    done
fi
# 无图形桌面（目录不存在）则跳过
[ -n "$DESK" ] && [ -d "$DESK" ] || exit 0

# 由 Exec 反推安装前缀，定位实际图标文件
EXEC_PATH="$(sed -n 's/^Exec=//p' "$SRC" | head -n1 | awk '{print $1}')"
PREFIX_DIR="$(dirname "$(dirname "$EXEC_PATH")")"
ICON_FILE=""
for c in \
    "$PREFIX_DIR/share/icons/hicolor/256x256/apps/qinplus-dengbao.png" \
    "$PREFIX_DIR/share/qinplus-dengbao/assets/icon.png" \
    "/usr/share/icons/hicolor/256x256/apps/qinplus-dengbao.png" \
    "/usr/local/share/icons/hicolor/256x256/apps/qinplus-dengbao.png"; do
    if [ -f "$c" ]; then ICON_FILE="$c"; break; fi
done

DEST="$DESK/$(basename "$SRC")"
if [ -n "$ICON_FILE" ]; then
    # 绝对路径图标：任何主题/缓存状态下都能显示
    sed -e "s|^Icon=.*|Icon=$ICON_FILE|" "$SRC" > "$DEST"
else
    cp -f "$SRC" "$DEST"
fi
chmod 755 "$DEST"
chown "$TARGET_USER": "$DEST" 2>/dev/null || true

# GNOME 需要 metadata::trusted，且必须带上该用户的 D-Bus 会话地址
UID_NUM="$(id -u "$TARGET_USER" 2>/dev/null || true)"
BUS=""
if [ -n "$UID_NUM" ] && [ -S "/run/user/$UID_NUM/bus" ]; then
    BUS="unix:path=/run/user/$UID_NUM/bus"
fi

TRUSTED=0
if command -v gio >/dev/null 2>&1; then
    if [ "$(id -un)" = "$TARGET_USER" ]; then
        if gio set "$DEST" metadata::trusted true 2>/dev/null; then TRUSTED=1; fi
    elif command -v sudo >/dev/null 2>&1; then
        if [ -n "$BUS" ]; then
            if sudo -u "$TARGET_USER" env DBUS_SESSION_BUS_ADDRESS="$BUS" \
                gio set "$DEST" metadata::trusted true 2>/dev/null; then
                TRUSTED=1
            fi
        else
            if sudo -u "$TARGET_USER" gio set "$DEST" metadata::trusted true 2>/dev/null; then
                TRUSTED=1
            fi
        fi
    fi
fi

echo "已创建桌面快捷方式：$DEST"
if [ -z "$ICON_FILE" ]; then
    echo "提示：未找到图标文件，快捷方式可能显示默认图标。" >&2
fi
if [ "$TRUSTED" != "1" ]; then
    echo "提示：若桌面提示「不受信任的启动器」，右键图标选择「允许启动」即可。" >&2
fi
exit 0
