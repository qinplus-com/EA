#!/usr/bin/env bash
# =============================================================================
# 勤加等保测评助手（Linux 版：qinplus-dengbao） - 基线数据每日自动更新脚本
#
# 用途：
#   每日自动生成基线数据并发布到 ea.qinplus.com 站点目录，客户端通过
#   「安全基线」对话框的默认链接在线更新：
#     https://ea.qinplus.com/security_baseline.<YYYY-MM-DD>.json   版本基线
#     https://ea.qinplus.com/cve_db.<YYYY-MM-DD>.json              CVE 漏洞库
#
# 数据来源：
#   1) 人工维护的主数据（版本区间规则）：$SRC_DIR/security_baseline.json、$SRC_DIR/cve_db.json
#   2) NVD 公开 API 按组件关键字拉取近 7 天新发布 CVE，自动并入 `_nvd_recent`
#      信息区（不参与区间判定，供人工审核后归入正式条目）
#
# 依赖：bash、curl、jq、python3
#
# 部署：
#   sudo install -m 755 update_baseline.sh /opt/qinplus-dengbao/update_baseline.sh
#   # 每日 03:30 自动执行（cron）：
#   30 3 * * * /opt/qinplus-dengbao/update_baseline.sh >> /var/log/qinplus-dengbao-baseline.log 2>&1
# =============================================================================
set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/qinplus-dengbao/baseline-src}"   # 主数据目录（人工维护）
WEB_ROOT="${WEB_ROOT:-/var/www/ea}"                        # ea.qinplus.com 站点根目录
NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
DAYS=7                                                     # 拉取最近 N 天发布/更新的 CVE
DAY="$(date +%F)"
START="$(date -d "-${DAYS} days" +%FT%H:%M:%S.000Z 2>/dev/null || date -v-${DAYS}d +%FT%H:%M:%S.000Z)"
END="$(date +%FT%H:%M:%S.000Z 2>/dev/null || date -u +%FT%H:%M:%S.000Z)"

# 关注组件（与 data/cve_db.json 的键一致）→ NVD 关键字
declare -A KW=(
  [nginx]="nginx"                    [apache-httpd]="apache http server"
  [tomcat]="apache tomcat"           [openssl]="openssl"
  [openssh]="openssh"                [glibc]="glibc"
  [redis]="redis"                    [docker]="docker"
  [kubernetes]="kubernetes"          [nodejs]="node.js"
  [python]="python"                  [jenkins]="jenkins"
  [mongodb]="mongodb"                [mysql]="oracle mysql"
  [bileiwaf]="openresty"             [kernel-centos-7]="linux kernel"
)

echo "[$(date '+%F %T')] === 基线数据日更开始（$DAY） ==="

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------- 1. NVD 拉取近 N 天 CVE ----------
RECENT="$TMP/nvd_recent.json"
echo '{}' > "$RECENT"
for comp in "${!KW[@]}"; do
  kw="${KW[$comp]}"
  echo "  NVD 查询: $comp ($kw)"
  resp="$TMP/nvd_${comp}.json"
  if curl -fsS --retry 2 --connect-timeout 15 \
      -G "$NVD_API" --data-urlencode "keywordSearch=$kw" \
      --data-urlencode "pubStartDate=$START" --data-urlencode "pubEndDate=$END" \
      --data-urlencode "resultsPerPage=40" -o "$resp"; then
    ids=$(jq -r '[.vulnerabilities[]?.cve.id] | unique | .[]' "$resp" 2>/dev/null || true)
    if [ -n "$ids" ]; then
      # 合并进汇总：{comp: [CVE-...]}
      jq --arg c "$comp" --argjson ids "$(echo "$ids" | jq -R . | jq -sc 'unique')" \
         '.[$c] = ((.[$c] // []) + $ids | unique)' "$RECENT" > "$TMP/r.json" && mv "$TMP/r.json" "$RECENT"
    fi
  else
    echo "  警告: NVD 查询失败（$comp），本次跳过" >&2
  fi
  sleep 7   # NVD 匿名限速（约 5 次/30 秒），防止被封
done
NEW_TOTAL=$(jq '[.[] | length] | add // 0' "$RECENT")
echo "  近 ${DAYS} 天新增/更新 CVE 合计: $NEW_TOTAL"

# ---------- 2. 生成 CVE 漏洞库（主数据 + _nvd_recent） ----------
SRC_CVE="$SRC_DIR/cve_db.json"
[ -f "$SRC_CVE" ] || { echo "✗ 缺少主数据 $SRC_CVE" >&2; exit 1; }

python3 - "$SRC_CVE" "$RECENT" "$WEB_ROOT/cve_db.$DAY.json" <<'PYEOF'
import json, sys
src, recent_path, out = sys.argv[1:4]
with open(src, encoding="utf-8") as f:
    db = json.load(f)
with open(recent_path, encoding="utf-8") as f:
    recent = json.load(f)
db.pop("_nvd_recent", None)
if any(recent.values()):
    db["_nvd_recent"] = {
        "note": "NVD 每日同步：近 7 天新发布/更新的 CVE，供人工审核后归入上方区间条目；不参与自动判定",
        "items": recent,
    }
with open(out, "w", encoding="utf-8") as f:
    json.dump(db, f, ensure_ascii=False, indent=2)
print("  写出", out)
PYEOF

# ---------- 3. 生成版本基线（刷新 updated/version 为当日） ----------
SRC_BASE="$SRC_DIR/security_baseline.json"
[ -f "$SRC_BASE" ] || { echo "✗ 缺少主数据 $SRC_BASE" >&2; exit 1; }

python3 - "$SRC_BASE" "$WEB_ROOT/security_baseline.$DAY.json" "$DAY" <<'PYEOF'
import json, sys
src, out, day = sys.argv[1:4]
with open(src, encoding="utf-8") as f:
    d = json.load(f)
d["updated"] = day
d["version"] = day.replace("-", ".")
d["source"] = "qinplus-daily"
with open(out, "w", encoding="utf-8") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
print("  写出", out)
PYEOF

# ---------- 4. 刷新 latest 副本（便于人工核对最新版） ----------
cp -f "$WEB_ROOT/cve_db.$DAY.json" "$WEB_ROOT/cve_db.latest.json"
cp -f "$WEB_ROOT/security_baseline.$DAY.json" "$WEB_ROOT/security_baseline.latest.json"

# ---------- 5. 清理 30 天前的历史快照 ----------
find "$WEB_ROOT" -name 'cve_db.20*.json' -mtime +30 -delete 2>/dev/null || true
find "$WEB_ROOT" -name 'security_baseline.20*.json' -mtime +30 -delete 2>/dev/null || true

echo "[$(date '+%F %T')] === 完成 ==="
echo "客户端更新链接："
echo "  https://ea.qinplus.com/security_baseline.$DAY.json"
echo "  https://ea.qinplus.com/cve_db.$DAY.json"
