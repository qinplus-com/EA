#!/bin/sh
# 勤加软件等保测评助手 - 桌面快捷方式安装
#
# 用法：sh install_desktop_shortcut.sh <已安装的 .desktop 路径>
#       可在 root（make install / deb / rpm 的 postinst）或普通用户下执行。
#
# 说明：
#   1. 目标用户：sudo 调用者 > logname > 所有普通用户（兼容图形包管理器安装）；
#   2. 桌面目录优先取用户的 XDG 配置（含「桌面」等本地化名称），
#      自动排除 xdg-user-dir 未配置时返回 $HOME 的误导结果；
#   3. 有图形会话但桌面目录尚未生成时，自动创建（中文环境用「桌面」）；
#   4. 会把 Icon= 改写为绝对路径，避免图标主题缓存未刷新时看不到图标；
#   5. GNOME 系桌面额外标记 metadata::trusted（Kylin/UOS 的 UKUI、Peony 不依赖它）。
set -e

SRC="$1"
[ -n "$SRC" ] && [ -f "$SRC" ] || exit 0

# ---------------- 基础工具 ----------------

user_home() {
    _h="$(getent passwd "$1" 2>/dev/null | cut -d: -f6)"
    if [ -z "$_h" ]; then
        _h="$(awk -F: -v u="$1" '$1==u {print $6}' /etc/passwd 2>/dev/null)"
    fi
    printf '%s' "$_h"
}

# 读取 XDG 桌面目录：$1=用户  $2=家目录
desktop_dir_of() {
    _u="$1"
    _h="$2"
    _d=""

    # 1) 直接读用户的 user-dirs.dirs，不依赖 xdg-user-dir 是否安装
    _cfg="$_h/.config/user-dirs.dirs"
    if [ -r "$_cfg" ]; then
        _d="$(sed -n 's/^[[:space:]]*XDG_DESKTOP_DIR=//p' "$_cfg" 2>/dev/null | head -n1)"
        _d="$(printf '%s' "$_d" | sed -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' \
                                           -e "s|\$HOME|$_h|g" -e 's/[[:space:]]*$//')"
    fi

    # 2) 退而求其次用 xdg-user-dir（需要在目标用户身份下执行）
    if [ -z "$_d" ] && command -v xdg-user-dir >/dev/null 2>&1; then
        if [ "$(id -un)" = "$_u" ]; then
            _d="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
        elif command -v sudo >/dev/null 2>&1; then
            _d="$(sudo -u "$_u" xdg-user-dir DESKTOP 2>/dev/null || true)"
        fi
    fi

    # 未配置时 xdg-user-dir 会返回 $HOME，必须排除，否则快捷方式会落到家目录
    while :; do
        case "$_d" in
            */) _d="${_d%/}";;
            *) break;;
        esac
    done
    if [ -z "$_d" ] || [ "$_d" = "$_h" ] || [ ! -d "$_d" ]; then
        _d=""
        for _c in "$_h/桌面" "$_h/Desktop" "$_h/デスクトップ"; do
            if [ -d "$_c" ]; then _d="$_c"; break; fi
        done
    fi

    printf '%s' "$_d"
}

# 系统语言是否为中文（决定新桌面目录名）
system_lang_is_zh() {
    _l=""
    for _f in /etc/locale.conf /etc/default/locale /etc/sysconfig/i18n; do
        [ -r "$_f" ] || continue
        _l="$(sed -n 's/^[[:space:]]*LANG=//p' "$_f" 2>/dev/null | head -n1 | tr -d '"')"
        [ -n "$_l" ] && break
    done
    [ -n "$_l" ] || _l="${LANG:-}"
    case "$_l" in
        zh*) return 0;;
        *)   return 1;;
    esac
}

# 是否存在图形会话（只有桌面用户才值得创建快捷方式）
has_desktop_session() {
    _u="$1"
    _id="$2"
    [ -d "/run/user/$_id" ] && return 0
    if command -v loginctl >/dev/null 2>&1; then
        if loginctl show-user "$_u" -p Display 2>/dev/null | grep -q 'Display=.'; then
            return 0
        fi
    fi
    return 1
}

# 为单个用户创建快捷方式；返回 0 表示已创建
install_for() {
    _u="$1"
    [ "$_u" = "root" ] && return 1

    _h="$(user_home "$_u")"
    [ -n "$_h" ] || _h="/home/$_u"
    [ -d "$_h" ] || return 1

    _uid="$(id -u "$_u" 2>/dev/null || true)"
    [ -n "$_uid" ] || return 1

    _desk="$(desktop_dir_of "$_u" "$_h")"
    if [ -z "$_desk" ]; then
        # 有图形会话但还没有桌面目录（首次登录前安装），按语言补建
        if has_desktop_session "$_u" "$_uid"; then
            if system_lang_is_zh; then
                _desk="$_h/桌面"
            else
                _desk="$_h/Desktop"
            fi
            mkdir -p "$_desk" 2>/dev/null || return 1
            chown "$_u": "$_desk" 2>/dev/null || true
        else
            return 1
        fi
    fi

    # 由 Exec 反推安装前缀，定位实际图标文件
    _exec="$(sed -n 's/^Exec=//p' "$SRC" | head -n1 | awk '{print $1}')"
    _prefix="$(dirname "$(dirname "$_exec")")"
    _icon=""
    for _c in \
        "$_prefix/share/icons/hicolor/256x256/apps/qinplus-dengbao.png" \
        "$_prefix/share/qinplus-dengbao/assets/icon.png" \
        "/usr/share/icons/hicolor/256x256/apps/qinplus-dengbao.png" \
        "/usr/local/share/icons/hicolor/256x256/apps/qinplus-dengbao.png"; do
        if [ -f "$_c" ]; then _icon="$_c"; break; fi
    done

    _dest="$_desk/$(basename "$SRC")"
    if [ -n "$_icon" ]; then
        sed -e "s|^Icon=.*|Icon=$_icon|" "$SRC" > "$_dest"
    else
        cp -f "$SRC" "$_dest"
    fi
    chmod 755 "$_dest"
    chown "$_u": "$_dest" 2>/dev/null || true

    # GNOME 需要 metadata::trusted，且必须带上该用户的 D-Bus 会话地址
    _bus=""
    if [ -S "/run/user/$_uid/bus" ]; then
        _bus="unix:path=/run/user/$_uid/bus"
    fi
    _trusted=0
    if command -v gio >/dev/null 2>&1; then
        if [ "$(id -un)" = "$_u" ]; then
            if gio set "$_dest" metadata::trusted true 2>/dev/null; then _trusted=1; fi
        elif command -v sudo >/dev/null 2>&1; then
            if [ -n "$_bus" ]; then
                if sudo -u "$_u" env DBUS_SESSION_BUS_ADDRESS="$_bus" \
                    gio set "$_dest" metadata::trusted true 2>/dev/null; then
                    _trusted=1
                fi
            elif sudo -u "$_u" gio set "$_dest" metadata::trusted true 2>/dev/null; then
                _trusted=1
            fi
        fi
    fi

    echo "已创建桌面快捷方式：$_dest"
    [ -n "$_icon" ] || echo "提示：未找到图标文件，快捷方式可能显示默认图标。" >&2
    [ "$_trusted" = "1" ] || echo "提示：若桌面提示「不受信任的启动器」，右键图标选择「允许启动」即可。" >&2
    return 0
}

# ---------------- 目标用户 ----------------

USERS=""
add_user() {
    [ -n "$1" ] || return 0
    case " $USERS " in
        *" $1 "*) ;;
        *) USERS="$USERS $1";;
    esac
}

# 1) sudo 调用者（sudo make install / sudo dpkg -i）
add_user "${SUDO_USER:-}"
# 2) 当前登录用户
add_user "$(logname 2>/dev/null || true)"

# 3) 兜底：图形包管理器 / su 安装时没有 SUDO_USER，遍历普通用户
if [ -z "$USERS" ]; then
    while IFS=: read -r _n _p _uid _gid _gecos _hd _sh; do
        case "$_uid" in ''|*[!0-9]*) continue;; esac
        [ "$_uid" -ge 1000 ] || continue
        [ "$_uid" -lt 60000 ] || continue
        case "$_sh" in */nologin|*/false) continue;; esac
        add_user "$_n"
    done < /etc/passwd
fi

CREATED=0
for _user in $USERS; do
    if install_for "$_user"; then CREATED=1; fi
done

if [ "$CREATED" = "0" ]; then
    echo "提示：未检测到可用的图形桌面用户，已跳过桌面快捷方式。" >&2
    echo "      需要时请以桌面用户身份执行：sh $(basename "$0") $SRC" >&2
fi

exit 0
