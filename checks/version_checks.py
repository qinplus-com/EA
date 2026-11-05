# -*- coding: utf-8 -*-
"""版本号探测 + CVE 漏洞匹配 + 未知软件信息呈现。

使用方式（供 middleware_checks / linux_checks / advanced_checks 等调用）：
    from .version_checks import detect_running_software, match_cves, check_host_cves
"""
import json
import os
import re
import sys

from core.models import STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_MANUAL, STATUS_ERROR
from .platform_util import run_cmd, run_powershell, get_executor

# ---------------------------------------------------------------------------
# 漏洞库加载：data/cve_db.json（PyInstaller onefile 模式下 _MEIPASS / 源码模式下 data/）
# ---------------------------------------------------------------------------

def _cve_db_path():
    # 用户更新版优先（~/.ea_dengbao/cve_db.json，由「安全基线」对话框导入）
    up = os.path.join(os.path.expanduser("~"), ".ea_dengbao", "cve_db.json")
    if os.path.exists(up):
        return up
    # 打包版其次 exe 同级 data/（用户可见、可编辑）
    if getattr(sys, "frozen", False):
        p = os.path.join(os.path.dirname(sys.executable), "data", "cve_db.json")
        if os.path.exists(p):
            return p
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    p = os.path.join(base, "data", "cve_db.json")
    if os.path.exists(p):
        return p
    # 源码 fallback
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p2 = os.path.join(here, "data", "cve_db.json")
    return p2


def _load_cve_db():
    # 缓存按 (路径, mtime) 键控：导入/更新 CVE 库后自动失效重载
    try:
        path = _cve_db_path()
        mtime = os.path.getmtime(path)
    except OSError:
        path, mtime = "", None
    if _load_cve_db.cache.get("key") != (path, mtime):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        _load_cve_db.cache = {"key": (path, mtime), "data": data}
    return _load_cve_db.cache["data"]


_load_cve_db.cache = {}


# ---------------------------------------------------------------------------
# 版本比较（PEP 440 子集，纯字符串实现，不依赖第三方包）
# ---------------------------------------------------------------------------

def _parse_ver(s):
    """解析版本号为 tuple of ints + 预发布标记，用于比较。未知版本返回 (0,)。"""
    if not s:
        return (0,)
    s = s.strip().lstrip("vV")
    # 剥离常见后缀：-rc1、-beta2、-alpha、-release、.RELEASE
    s = re.split(r"[-_\.]\s*(rc|alpha|beta|pre|patch|rel|release|debian|ubuntu|el|centos)\b", s, flags=re.I)[0]
    nums = re.findall(r"\d+", s)
    return tuple(int(n) for n in nums) if nums else (0,)


def _ver_le(a_str, b_str):
    """a <= b 按版本语义比较。"""
    a, b = _parse_ver(a_str), _parse_ver(b_str)
    # 补齐相同长度
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a <= b


def _ver_in_range(ver, lo, hi):
    """lo <= ver <= hi。lo/hi 为 "0" 视为无下限；"99999" 视为无上限。"""
    if not ver or ver in ("unknown", "", None):
        return False  # 未知版本一律视为"信息不足，不判定有漏洞"
    return _ver_le(lo, ver) and _ver_le(ver, hi)


# ---------------------------------------------------------------------------
# 版本提取：从命令输出里抓第一个像版本号的字符串
# ---------------------------------------------------------------------------

_VER_PATTERNS = [
    re.compile(r"version\s*[:=]?\s*([\d]+(?:\.[\d]+){0,3}(?:[-_.][A-Za-z0-9]+)?)", re.I),
    re.compile(r"\b(\d+\.\d+(?:\.\d+){0,2}[pP]?\d*(?:[-_.][A-Za-z0-9]+)*)\b"),
]


def _pick_version(text):
    if not text:
        return ""
    text = text.strip()
    for pat in _VER_PATTERNS:
        m = pat.search(text)
        if m:
            v = m.group(1)
            # 剔除明显不是版本号的（如 IPv4）
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                continue
            return v
    return ""


# ---------------------------------------------------------------------------
# 已知软件 → 获取版本的方法（命令 + 正则）
# ---------------------------------------------------------------------------

# (key_for_db, display_name, [list of (cmd, expected_version_pattern)])
_VERSION_GETTERS_LINUX = [
    ("nginx", "Nginx",
     [("nginx -v 2>&1", None),
      ("rpm -q nginx 2>/dev/null || rpm -q nginx-all-modules 2>/dev/null", None),
      ("dpkg -l nginx 2>/dev/null | tail -1", None)]),
    ("apache-httpd", "Apache HTTP Server",
     [("httpd -v 2>&1 || apache2 -v 2>&1", None),
      ("rpm -q httpd 2>/dev/null", None),
      ("dpkg -l apache2 2>/dev/null | tail -1", None)]),
    ("tomcat", "Apache Tomcat",
     [("CATALINA_HOME=$(dirname $(dirname $(readlink -f $(which startup.sh 2>/dev/null || echo /dev/null)) 2>/dev/null)); [ -z \"$CATALINA_HOME\" ] && CATALINA_HOME=$(find /opt /usr/share -maxdepth 4 -name 'catalina.jar' 2>/dev/null | head -1 | xargs dirname 2>/dev/null); [ -n \"$CATALINA_HOME\" ] && (java -cp \"$CATALINA_HOME/lib/catalina.jar\" org.apache.catalina.util.ServerInfo 2>/dev/null || head -1 \"$CATALINA_HOME/lib/catalina.jar\" 2>/dev/null) || echo",
      None),
      ("rpm -q tomcat 2>/dev/null || rpm -q apache-tomcat 2>/dev/null", None)]),
    ("openssl", "OpenSSL",
     [("rpm -q openssl-libs 2>/dev/null || rpm -q openssl 2>/dev/null", None),
      ("dpkg -l openssl 2>/dev/null | tail -1", None),
      ("openssl version 2>&1", None)]),
    ("openssh", "OpenSSH",
     [("rpm -q openssh-server 2>/dev/null || rpm -q openssh 2>/dev/null", None),
      ("dpkg -l openssh-server 2>/dev/null | tail -1", None),
      ("ssh -V 2>&1 | head -1", None)]),
    ("redis", "Redis",
     [("redis-server --version 2>&1", None),
      ("rpm -q redis 2>/dev/null", None)]),
    ("docker", "Docker Engine",
     [("docker version --format '{{.Server.Version}}' 2>&1", None),
      ("rpm -q docker 2>/dev/null || rpm -q docker-ce 2>/dev/null", None)]),
    ("kubernetes", "Kubernetes",
     [("kubectl version --short 2>&1", None)]),
    ("nodejs", "Node.js",
     [("node --version 2>&1", None)]),
    ("python", "Python",
     [("python3 --version 2>&1 || python --version 2>&1", None)]),
    ("jenkins", "Jenkins",
     [("rpm -q jenkins 2>/dev/null", None),
      ("dpkg -l jenkins 2>/dev/null | tail -1", None)]),
    ("mongodb", "MongoDB",
     [("mongod --version 2>&1 | head -1", None),
      ("rpm -q mongodb-org 2>/dev/null", None)]),
    ("mysql", "MySQL/MariaDB",
     [("mysql --version 2>&1 || mysqld --version 2>&1", None),
      ("rpm -q mysql-server 2>/dev/null || rpm -q mariadb-server 2>/dev/null", None)]),
    ("glibc", "glibc",
     [("ldd --version 2>&1 | head -1", None),
      ("rpm -q glibc 2>/dev/null", None)]),
    ("bileiwaf", "BileiWAF(壁垒WAF)",
     [("ls -1 /opt/bileiwaf 2>/dev/null; rpm -q bileiwaf 2>/dev/null; /opt/bileiwaf/bin/bileiwaf --version 2>/dev/null || /opt/bileiwaf/waf --version 2>/dev/null", None)]),
]

_VERSION_GETTERS_WINDOWS = [
    ("nginx", "Nginx",
     [("nginx -v 2>&1", None)]),
    ("apache-httpd", "Apache HTTP Server",
     [("httpd -v 2>&1", None)]),
    ("docker", "Docker Engine",
     [("docker version --format '{{.Server.Version}}' 2>&1", None)]),
    ("nodejs", "Node.js",
     [("node --version 2>&1", None)]),
    ("python", "Python",
     [("python --version 2>&1", None)]),
]


# ---------------------------------------------------------------------------
# 进程 → 软件 key 的模糊映射
# ---------------------------------------------------------------------------

_PROCESS_TO_DBKEY = [
    (re.compile(r"\bnginx\b", re.I), "nginx"),
    (re.compile(r"\bhttpd\b|\bapache2?\b", re.I), "apache-httpd"),
    (re.compile(r"\bcatalina\b|\btomcat", re.I), "tomcat"),
    (re.compile(r"\bredis", re.I), "redis"),
    (re.compile(r"\bdockerd?\b", re.I), "docker"),
    (re.compile(r"\bkubelet\b|\bkube-proxy\b", re.I), "kubernetes"),
    (re.compile(r"\bnode\b"), "nodejs"),
    (re.compile(r"\bjenkins\b", re.I), "jenkins"),
    (re.compile(r"\bmongod\b"), "mongodb"),
    (re.compile(r"\bmysqld\b|\bmariadbd\b", re.I), "mysql"),
    (re.compile(r"\bbileiwaf\b|\bbilei-waf\b", re.I), "bileiwaf"),
    (re.compile(r"\bsshd\b"), "openssh"),
    (re.compile(r"\bopenssh\b", re.I), "openssh"),
]


def _proc_to_dbkey(proc_name):
    for pat, key in _PROCESS_TO_DBKEY:
        if pat.search(proc_name or ""):
            return key
    return None


# ---------------------------------------------------------------------------
# 主 API：获取运行中软件清单 + CVE 匹配
# ---------------------------------------------------------------------------

def detect_running_software():
    """返回 [{key, name, proc, path, version, cves:[], is_known}]
    key:     cve_db 中的键；未知软件为 None
    name:    显示名称（已知用 getter 里的 display_name，未知用 proc）
    proc:    进程名
    path:    可执行文件路径
    version: 版本号字符串，"" 表示探测失败
    """
    plat = getattr(get_executor(), "platform", "linux")
    getters = _VERSION_GETTERS_WINDOWS if plat == "windows" else _VERSION_GETTERS_LINUX

    # 1) 先从进程扫描拿到运行中的应用（调用 middleware_checks._listening_ports 不可靠；这里独立 pgrep）
    if plat == "windows":
        rc, out = run_powershell(
            "Get-Process | Where-Object { $_.ProcessName -match 'nginx|httpd|tomcat|catalina|redis|docker|jenkins|mongod|mysqld|bileiwaf|node|sshd' } | "
            "Select-Object -Unique ProcessName,Path | ForEach-Object { $_.ProcessName + '|' + ($_.Path -replace '\\|','/') }",
            timeout=30)
    else:
        # 用 grep + awk 的方式枚举中间件/服务进程；避免在 Python 字符串内嵌 bash 单引号
        cmd = (
            "ps -eo comm,args --no-headers 2>/dev/null | "
            "grep -E '^(nginx|httpd|apache2|catalina|tomcat|redis-server|dockerd|kubelet|kube-proxy|node|jenkins|mongod|mysqld|mariadbd|bileiwaf|bilei-waf|sshd)\\b' | "
            "grep -v grep | "
            "awk '{"
            "p=$1; $1=\"\"; sub(/^ /,\"\"); a=$0;"
            "print p \"|\" a"
            "}'"
        )
        rc, out = run_cmd(["bash", "-c", cmd], timeout=20)

    results = {}  # key -> dict；按 key 去重

    for line in (out or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        proc, _, rest = line.partition("|")
        proc = proc.strip()
        # 解析出 pid / path
        tokens = rest.split()
        path = ""
        # 先找绝对路径（以 / 或 C:\ 开头）
        for t in tokens:
            if t.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", t):
                path = t
                break
        # pgrep 输出里常带路径，也从 proc 里提取
        if "/" in proc or "\\" in proc:
            path = proc
            proc = os.path.basename(proc.replace("\\", "/"))

        key = _proc_to_dbkey(proc)
        if not key:
            # 未知软件：仍然记录进报告（让用户看到有什么在跑）
            uk = "_unknown_" + proc.lower()
            if uk not in results:
                results[uk] = {
                    "key": None, "name": proc, "proc": proc, "path": path,
                    "version": "", "cves": [], "is_known": False,
                }
            continue

        if key in results:
            continue
        # 调用 getter 取版本
        name = proc
        version = ""
        for gkey, gname, cmds in getters:
            if gkey == key:
                name = gname
                for cmd, _pat in cmds:
                    rc2, out2 = run_cmd(["bash", "-c", cmd], timeout=15) \
                        if plat != "windows" else run_powershell(cmd, timeout=15)
                    v = _pick_version(out2)
                    if v:
                        version = v
                        break
                break

        results[key] = {
            "key": key, "name": name, "proc": proc, "path": path,
            "version": version, "cves": [], "is_known": True,
        }

    # 2) 额外：对所有已运行但未被进程匹配命中的已知软件，尝试直接取版本
    if plat != "windows":
        for gkey, gname, cmds in getters:
            if gkey in results:
                continue
            for cmd, _pat in cmds:
                rc2, out2 = run_cmd(["bash", "-c", cmd], timeout=15)
                v = _pick_version(out2)
                if v:
                    results[gkey] = {
                        "key": gkey, "name": gname, "proc": gkey, "path": "",
                        "version": v, "cves": [], "is_known": True,
                    }
                    break
    else:
        for gkey, gname, cmds in getters:
            if gkey in results:
                continue
            for cmd, _pat in cmds:
                rc2, out2 = run_powershell(cmd, timeout=15)
                v = _pick_version(out2)
                if v:
                    results[gkey] = {
                        "key": gkey, "name": gname, "proc": gkey, "path": "",
                        "version": v, "cves": [], "is_known": True,
                    }
                    break

    # 3) CVE 匹配
    db = _load_cve_db()
    for key, item in results.items():
        if not item["key"] or not item["version"]:
            continue
        entries = db.get(item["key"], [])
        hits = []
        for e in entries:
            if _ver_in_range(item["version"], e.get("min", "0"), e.get("max", "99999")):
                hits.append(e)
        item["cves"] = hits

    return list(results.values())


# ---------------------------------------------------------------------------
# 宿主机 CVE（内核 + glibc + openssl + openssh）
# ---------------------------------------------------------------------------

def _host_kernel_key():
    """猜测内核漏洞库 key。CentOS 7 的内核版本号形如 3.10.0-1160.el7.x86_64"""
    rc, out = run_cmd(["bash", "-c", "cat /etc/os-release 2>/dev/null; uname -r 2>/dev/null; uname -a 2>/dev/null"],
                      timeout=10)
    text = (out or "").lower()
    ver_line = ""
    for ln in (out or "").splitlines():
        v = _pick_version(ln)
        if v and "." in v:
            ver_line = ln
            break
    if "centos" in text or "rhel 7" in text or "el7" in text:
        return "kernel-centos-7", ver_line
    if "centos linux 8" in text or "rhel 8" in text or "el8" in text:
        return "kernel-centos-8", ver_line
    # Debian / Ubuntu 走 glibc/openssl/openssh 的通用条目即可
    return "kernel-unknown", ver_line


def check_host_cves():
    """宿主系统关键软件（内核/glibc/openssl/openssh）的 CVE 匹配。
    返回 [{name, version, cves:[], key}]"""
    plat = getattr(get_executor(), "platform", "linux")
    if plat == "windows":
        return []
    db = _load_cve_db()
    items = []
    for gkey, gname, cmds in _VERSION_GETTERS_LINUX:
        if gkey not in ("glibc", "openssl", "openssh"):
            continue
        for cmd, _ in cmds:
            rc, out = run_cmd(["bash", "-c", cmd], timeout=15)
            v = _pick_version(out)
            if v:
                hits = [e for e in db.get(gkey, [])
                        if _ver_in_range(v, e.get("min", "0"), e.get("max", "99999"))]
                items.append({"name": gname, "key": gkey, "version": v, "cves": hits})
                break
    # 内核（CentOS/RHEL 特定匹配）
    kkey, kval = _host_kernel_key()
    if kval:
        # 内核版本号含 arch，只取到第一个带 '.' 的段即可
        v = _pick_version(kval) or kval.split()[0]
        hits = [e for e in db.get(kkey, [])
                if _ver_in_range(v, e.get("min", "0"), e.get("max", "99999"))]
        items.append({"name": "内核(%s)" % kkey, "key": kkey, "version": v, "cves": hits})
    return items
