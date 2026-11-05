#!/bin/sh
# 勤加软件等保测评助手 - DEB 打包脚本
# 由 make deb 调用：sh packaging/linux/build_deb.sh <version> <distdir> <name>
# 适配 Debian / Ubuntu / 统信 UOS / 麒麟桌面版 / Deepin
set -e

VERSION="${1:-1.0}"
DISTDIR="${2:-dist}"
NAME="${3:-qinplus-dengbao}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

[ -d "$DISTDIR" ] || { echo "缺少目录 $DISTDIR"; exit 1; }
DISTDIR="$(cd "$DISTDIR" && pwd)"
SRC="$DISTDIR/$NAME-$VERSION"
DEB_ROOT="$DISTDIR/deb/${NAME}_${VERSION}_${ARCH}"
OUT="$DISTDIR/${NAME}_${VERSION}_${ARCH}.deb"

[ -d "$SRC" ] || { echo "缺少源码目录 $SRC，请先执行 make dist"; exit 1; }

rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"

# 安装文件（DESTDIR 指到打包根，前缀用 /usr）
( cd "$SRC" && sh ./configure --prefix=/usr >/dev/null && make install DESTDIR="$DEB_ROOT" >/dev/null )
# make install 使用 PREFIX=/usr，故实际落在 $DEB_ROOT/usr/...，无需再次复制

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3, python3-pyqt5
Recommends: python3-paramiko, python3-docx
Maintainer: Qinplus Software <support@qinplus.com>
Homepage: https://ea.qinplus.com
Description: 勤加软件等保测评助手（等保 2.0 自查与测评辅助）
 按 GB/T 22239-2019 等保二级/三级要求执行技术检测与人工核查问卷，
 支持导出 HTML/Word 报告。包含桌面版 qinplus-dengbao 与命令行版 qinplus-dengbao-cli。
 .
 适配统信 UOS、麒麟 Kylin、Deepin 等国产 Linux 发行版。
Installed-Size: $(du -sk "$DEB_ROOT" | cut -f1)
EOF

cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOFX'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOFX
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

cat > "$DEB_ROOT/DEBIAN/postrm" <<'EOFX'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOFX
chmod 755 "$DEB_ROOT/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$DEB_ROOT" "$OUT"
echo "DEB 安装包：$OUT"
