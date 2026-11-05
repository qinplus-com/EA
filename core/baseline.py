# -*- coding: utf-8 -*-
"""离线安全基线 / CVE 数据：加载、比对、更新

- 版本基线：data/security_baseline.json（products 版本下限 + cves 修复版本）
- CVE 漏洞库：data/cve_db.json（组件版本区间 → CVE 映射，供版本漏洞比对）
- 用户更新后的文件保存在 ~/.ea_dengbao/，优先于内置生效
- 支持从本地 JSON 文件导入，或从指定 URL 下载（需联网）
"""
import json
import re
import sys
import urllib.request
from datetime import date as _date
from pathlib import Path

_DATA_FILE = "security_baseline.json"
_CVE_FILE = "cve_db.json"
_UPDATE_BASE = "https://ea.qinplus.com"


def default_url(kind="baseline"):
    """在线更新默认链接：https://ea.qinplus.com/<数据名>.<当天日期>.json

    服务端由 update_baseline.sh 每日生成当天日期命名的数据文件。
    """
    name = "security_baseline" if kind == "baseline" else "cve_db"
    return "%s/%s.%s.json" % (_UPDATE_BASE, name, _date.today().isoformat())


def _bundled_path():
    # 打包版优先使用 exe 同级 data/security_baseline.json（用户可见、可直接查看/编辑）
    if getattr(sys, "frozen", False):
        p = Path(sys.executable).resolve().parent / "data" / _DATA_FILE
        if p.exists():
            return p
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return Path(base) / "data" / _DATA_FILE


def user_path():
    return Path.home() / ".ea_dengbao" / _DATA_FILE


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load():
    """优先用户基线，其次内置基线；异常时回退内置。"""
    for p in (user_path(), _bundled_path()):
        try:
            if p.exists():
                data = _read(p)
                if isinstance(data, dict) and "products" in data:
                    return data
        except (OSError, ValueError):
            continue
    return {"version": "0", "updated": "", "products": {}, "cves": []}


def info():
    d = load()
    up = user_path()
    using_user = up.exists()
    return {"version": d.get("version", ""), "updated": d.get("updated", ""),
            "source": d.get("source", ""),
            # path：当前实际生效的用户基线路径（仅在用用户基线时非空）
            "path": str(up) if using_user else "",
            # user_path：用户基线的目标位置（导入/更新后保存在此）
            "user_path": str(up),
            "using_user": using_user}


def _vt(v):
    m = re.search(r"([0-9]+(?:\.[0-9]+)*)", str(v or ""))
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a, b):
    """比较版本元组，不足位补 0"""
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return (a > b) - (a < b)


def evaluate(product, version):
    """返回 (状态, 最低安全版本说明, 备注)

    状态：True=达标、False=低于基线、None=无基线/无法解析
    """
    p = load().get("products", {}).get(product)
    if not p:
        return None, "", ""
    note = p.get("note", "")
    if "min_builds" in p:
        return None, "", note
    cur = _vt(version)
    if not cur:
        return None, "", note
    min_major = p.get("min_major")
    min_build = p.get("min_build")
    if min_build:
        req = _vt(min_build)
        ok = _cmp(cur, req) >= 0 or (min_major is not None and cur[0] >= min_major)
        need = ">= %s" % min_build
        if min_major is not None:
            need += "（主版本>=%s）" % min_major
        return ok, need, note
    if min_major is not None and not p.get("min_version"):
        return cur[0] >= int(min_major), ">= %s.x" % min_major, note
    req = p.get("min_version")
    if req:
        return _cmp(cur, _vt(req)) >= 0, ">= %s" % req, note
    return None, "", note


def windows_build_status(caption, build):
    """按 Windows 版本名 + 构建号判定是否达到基线"""
    p = load().get("products", {}).get("windows", {})
    builds = p.get("min_builds", {})
    try:
        cur = int(str(build).strip())
    except ValueError:
        return None, "", p.get("note", "")
    cap = str(caption or "")
    for label, minimum in builds.items():
        if label.lower() in cap.lower():
            return cur >= int(minimum), ">= %s（%s）" % (minimum, label), p.get("note", "")
    if "Server" in cap:
        minimum = max(int(v) for k, v in builds.items() if k.startswith("Server"))
        return cur >= minimum, ">= %s（受支持的 Server 基线）" % minimum, p.get("note", "")
    if "Windows 11" in cap:
        minimum = builds.get("Windows 11", 0)
        return cur >= int(minimum), ">= %s（Windows 11）" % minimum, p.get("note", "")
    if "Windows 10" in cap:
        minimum = builds.get("Windows 10", 0)
        return cur >= int(minimum), ">= %s（Windows 10）" % minimum, p.get("note", "")
    return None, "", p.get("note", "")


def cves_for(product, version):
    """返回适用于当前版本（低于 fixed 版本）的 CVE 列表"""
    cur = _vt(version)
    out = []
    for c in load().get("cves", []):
        if str(c.get("product", "")).lower() != product.lower():
            continue
        fixed = _vt(c.get("fixed"))
        if not cur or not fixed:
            continue
        if _cmp(cur, fixed) < 0:
            out.append(c)
    return out


def _validate(data):
    if not isinstance(data, dict) or not isinstance(data.get("products"), dict):
        raise ValueError("基线文件格式错误：缺少 products 字段")
    return data


def update_from_file(src):
    data = _validate(_read(Path(src)))
    _save(data)
    return "已导入基线 %s（更新日期 %s）" % (data.get("version", "?"), data.get("updated", "?"))


def update_from_url(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "EA-Dengbao/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = _validate(json.loads(resp.read().decode("utf-8")))
    _save(data)
    return "已从 %s 更新基线 %s" % (url, data.get("version", "?"))


def reset_to_bundled():
    p = user_path()
    if p.exists():
        p.unlink()
    return "已恢复为内置基线"


def _save(data):
    p = user_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ---------------- CVE 漏洞库（cve_db.json） ----------------

def _bundled_cve_path():
    # 打包版优先 exe 同级 data/cve_db.json（用户可见、可编辑）
    if getattr(sys, "frozen", False):
        p = Path(sys.executable).resolve().parent / "data" / _CVE_FILE
        if p.exists():
            return p
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return Path(base) / "data" / _CVE_FILE


def cve_user_path():
    return Path.home() / ".ea_dengbao" / _CVE_FILE


def load_cves():
    """CVE 库：优先用户版，其次内置。返回 {组件键: [版本区间条目...]}"""
    for p in (cve_user_path(), _bundled_cve_path()):
        try:
            if p.exists():
                data = _read(p)
                if isinstance(data, dict):
                    return data
        except (OSError, ValueError):
            continue
    return {}


def cve_info():
    d = load_cves()
    comps = [k for k, v in d.items() if isinstance(v, list)]
    entries = sum(len(d[k]) for k in comps)
    n_cve = sum(len(e.get("cve", [])) for k in comps for e in d[k])
    up = cve_user_path()
    return {"components": len(comps), "entries": entries, "cves": n_cve,
            "names": "、".join(comps),
            "using_user": up.exists(),
            "path": str(up) if up.exists() else "",
            "user_path": str(up)}


def _validate_cves(data):
    if not isinstance(data, dict) or not any(isinstance(v, list) for v in data.values()):
        raise ValueError("CVE 文件格式错误：应为 {组件: [条目...]} 结构")
    return data


def _save_cves(data):
    p = cve_user_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def update_cves_from_file(src):
    data = _validate_cves(_read(Path(src)))
    _save_cves(data)
    i = cve_info()
    return "已导入 CVE 库（%d 个组件 / %d 条区间 / %d 个 CVE）" % (
        i["components"], i["entries"], i["cves"])


def update_cves_from_url(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "EA-Dengbao/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = _validate_cves(json.loads(resp.read().decode("utf-8")))
    _save_cves(data)
    i = cve_info()
    return "已从 %s 更新 CVE 库（%d 个组件 / %d 个 CVE）" % (
        url, i["components"], i["cves"])


def reset_cves_to_bundled():
    p = cve_user_path()
    if p.exists():
        p.unlink()
    return "已恢复为内置 CVE 库"
