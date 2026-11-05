# -*- coding: utf-8 -*-
"""数据库安全检测（MySQL/MariaDB、PostgreSQL、Redis、SQL Server、MongoDB 等）
通过目标机的配置文件、服务/进程、端口监听状态自动识别并评估。
"""
import os
import re
import shutil
import subprocess
import time
from functools import partial

from core import baseline
from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_DB, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, run_powershell

DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            1433: "SQL Server", 1521: "Oracle", 5236: "达梦", 54321: "人大金仓",
            5258: "GBase",
            5000: "SAP ASE/IQ/RS", 5001: "SAP ASE 备份服务", 2638: "SAP SQL Anywhere",
            6000: "SAP ASE"}

DB_PRODUCT_LABELS = {
    "sqlserver": "Microsoft SQL Server",
    "sap_ase": "SAP ASE（原 Sybase ASE）",
    "sap_iq": "SAP IQ（原 Sybase IQ）",
    "sap_sqlanywhere": "SAP SQL Anywhere",
    "sap_rs": "SAP Replication Server",
    "mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL",
    "redis": "Redis", "mongodb": "MongoDB", "oracle": "Oracle", "db2": "IBM DB2",
    "dm": "达梦数据库", "kingbase": "人大金仓", "gbase": "GBase", "gaussdb": "GaussDB",
}

# 厂商：同架构不同厂商（如 PG 系的 PostgreSQL / KingbaseES / GaussDB，MySQL 系的 MySQL / MariaDB）
DB_VENDORS = {
    "sqlserver": "Microsoft",
    "sap_ase": "SAP（原 Sybase）",
    "sap_iq": "SAP（原 Sybase）",
    "sap_sqlanywhere": "SAP（原 Sybase）",
    "sap_rs": "SAP（原 Sybase）",
    "mysql": "Oracle",
    "mariadb": "MariaDB Foundation",
    "postgresql": "PostgreSQL 全球开发组",
    "gaussdb": "华为（openGauss/GaussDB，PG系）",
    "kingbase": "人大金仓（KingbaseES，PG系）",
    "redis": "Redis Ltd.",
    "mongodb": "MongoDB Inc.",
    "oracle": "Oracle",
    "db2": "IBM",
    "dm": "达梦数据（DM，Oracle系）",
    "gbase": "南大通用（GBase，MySQL/PG系）",
}

# 各数据库的等保审计策略（8.1.4.3 安全审计）：机制、关键配置、留存要求各不相同
DB_AUDIT_STRATEGY = {
    "mysql": "开启审计插件 audit_log（audit_log_policy=ALL）或 general_log，覆盖登录、DDL、权限变更；留存≥6个月",
    "mariadb": "启用 server_audit 插件（EVENTS=CONNECT,QUERY_DDL,QUERY_DML）并外送 syslog；留存≥6个月",
    "postgresql": "配置 log_statement=all、log_connections=on、log_disconnections=on，建议启用 pgaudit；留存≥6个月",
    "sqlserver": "启用 SQL Server Audit（服务器/数据库审计规范）记录登录与权限变更，输出文件或安全日志；留存≥6个月",
    "oracle": "启用统一审计 Unified Auditing（AUDIT_TRAIL=DB,EXTENDED），覆盖登录与权限变更；留存≥6个月",
    "sap_ase": "启用 sybsecurity 审计库并用 sp_audit 记录登录与对象访问；留存≥6个月",
    "sap_iq": "启用 IQ 审计选项（auditing options）并保留事务日志；留存≥6个月",
    "sap_sqlanywhere": "启用 SQL Anywhere auditing 到独立审计库；留存≥6个月",
    "sap_rs": "通过 Replication Server 日志与 sybase 审计库记录复制操作；留存≥6个月",
    "mongodb": "启用 auditLog（filter 覆盖 authCheck/createUser/dropUser/roleGrant）；留存≥6个月",
    "redis": "Redis 无内置审计，需在网络层/跳板机或代理侧记录访问日志，并开启 requirepass+rename-command；留存≥6个月",
    "dm": "启用达梦审计（审计开关/SP_AUDIT）记录登录与权限变更；留存≥6个月",
    "kingbase": "启用 KingbaseES 审计（sys_audit 相关参数）并留存≥6个月",
    "gbase": "启用 GBase 审计（审计日志表/日志外送）并留存≥6个月",
    "db2": "启用 DB2 审计（db2audit）并定期导出审计记录；留存≥6个月",
}


def _vendor_label(key, ver=""):
    """厂商判定：优先按版本字符串识别，其次按产品 key"""
    t = (ver or "").lower()
    if "mariadb" in t:
        return DB_VENDORS["mariadb"]
    if "opengauss" in t or "gaussdb" in t:
        return DB_VENDORS["gaussdb"]
    if "kingbase" in t:
        return DB_VENDORS["kingbase"]
    if "gbase" in t:
        return DB_VENDORS["gbase"]
    if "dameng" in t or "dm8" in t:
        return DB_VENDORS["dm"]
    if "percona" in t:
        return "Percona（MySQL系）"
    if "tidb" in t:
        return "PingCAP（TiDB，MySQL系）"
    if "polar" in t:
        return "阿里云（PolarDB）"
    return DB_VENDORS.get(key, "未知厂商")


def _audit_advice(keys):
    """按识别到的数据库产品给出各自的等保审计策略"""
    out, seen = [], set()
    for k in keys:
        tip = DB_AUDIT_STRATEGY.get(k)
        if tip and k not in seen:
            seen.add(k)
            out.append("%s: %s" % (DB_PRODUCT_LABELS.get(k, k), tip))
    return "；".join(out)

# 缓存一轮检测内的数据库清单（进程/服务/端口查询较慢）
_INV_CACHE = {"t": 0.0, "windows": None, "linux": None}

_DB_CONF = {}


def _product_key(name, path="", extra=""):
    """按进程名 → 服务名/显示名 → 安装路径识别数据库产品。

    关键点：Microsoft SQL Server 进程是 sqlservr.exe，
    原 Sybase/SAP ASE 进程是 sqlsrvr.exe（少一个 e），必须先于 SQL Server 判断。
    """
    n = (name or "").strip().lower()
    p = (path or "").strip().lower()
    t = (extra or "").strip().lower()
    if re.search(r"^sqlsrvr(\.exe)?$", n):
        return "sap_ase"
    if re.search(r"^sqlservr(\.exe)?$", n):
        return "sqlserver"
    if re.search(r"^iqsrv\w*(\.exe)?$", n):
        return "sap_iq"
    if re.search(r"^dbsrv\w*(\.exe)?$", n):
        return "sap_sqlanywhere"
    if re.search(r"^repsrvr\w*(\.exe)?$", n):
        return "sap_rs"
    if re.search(r"^mysqld(\.exe)?$", n):
        return "mysql"
    if re.search(r"^mariadbd(\.exe)?$", n):
        return "mariadb"
    if re.search(r"^postgres(\.exe)?$", n):
        return "postgresql"
    if re.search(r"^redis-server(\.exe)?$", n):
        return "redis"
    if re.search(r"^mongod(\.exe)?$", n):
        return "mongodb"
    if re.search(r"^(oracle|tnslsnr)(\.exe)?$", n):
        return "oracle"
    if re.search(r"^db2sysc", n):
        return "db2"
    if re.search(r"^dmserver", n):
        return "dm"
    if re.search(r"^kingbase", n):
        return "kingbase"
    if re.search(r"^gaussdb", n):
        return "gaussdb"
    if re.search(r"^gbase", n):
        return "gbase"

    text = " ".join((n, p, t))
    # SAP 产品先判，避免 "Sybase SQLServer" 被误判为 Microsoft SQL Server
    if re.search(r"sap ase|sybase.*(ase|sqlserver|adaptive)|adaptive server|sybsql|\base-\d|/ase-", text):
        return "sap_ase"
    if re.search(r"sap iq|sybase iq|iqsrv|iq-\d|/iq-", text):
        return "sap_iq"
    if re.search(r"sql anywhere|sqlanywhere|dbsrv|sqlany", text):
        return "sap_sqlanywhere"
    if re.search(r"sap replication|sybase replication|replication server|repsrvr|rep-\d", text):
        return "sap_rs"
    if re.search(r"mssql|microsoft sql server|sqlserveragent|sql server \(|sql server\b", text):
        return "sqlserver"
    if re.search(r"mysql", text):
        return "mysql"
    if re.search(r"mariadb|maria", text):
        return "mariadb"
    if re.search(r"postgres|pgsql", text):
        return "postgresql"
    if re.search(r"redis", text):
        return "redis"
    if re.search(r"mongo", text):
        return "mongodb"
    if re.search(r"oracle|tnslsnr", text):
        return "oracle"
    if re.search(r"db2", text):
        return "db2"
    if re.search(r"达梦|dmserver|dm_?serv", text):
        return "dm"
    if re.search(r"kingbase|金仓", text):
        return "kingbase"
    if re.search(r"gbase", text):
        return "gbase"
    if re.search(r"gauss", text):
        return "gaussdb"
    return ""


def _is_db_helper_service(name, display):
    """SQL Server 的 VSS Writer / Browser / Agent 等辅助服务不代表数据库引擎在运行"""
    return bool(re.search(r"SQLWriter|SQLBrowser|SQLSERVERAGENT|SQLAgent|"
                          r"SQL Server VSS Writer|SQL Server Browser|SQL Server Agent|"
                          r"MSSQLFDLauncher|Full-Text", "%s %s" % (name, display), re.I))


def _inv_add(inv, key, proc="", path="", version="", port=None,
             service="", running=None, conf_port=None):
    if not key:
        return
    d = inv.get(key)
    if not d:
        d = {"key": key, "label": DB_PRODUCT_LABELS.get(key, key),
             "procs": set(), "paths": set(), "versions": set(), "ports": set(),
             "services": set(), "conf_ports": set(), "running": False}
        inv[key] = d
    if proc:
        d["procs"].add(proc)
    if path:
        d["paths"].add(path)
    if version:
        d["versions"].add(str(version).strip())
    if port:
        num = int(port)
        if 0 < num <= 65535:
            d["ports"].add(num)
    if conf_port:
        num = int(conf_port)
        if 0 < num <= 65535:
            d["conf_ports"].add(num)
    if service:
        d["services"].add(service)
    if running is not None:
        d["running"] = d["running"] or bool(running)
    return d


def _sap_version_from_text(text):
    """从安装路径/参数推断 SAP 产品版本，如 ASE-16_0 → 16.0"""
    m = re.search(r"(?:ASE|IQ|REP|SQL Anywhere)[-_ ]?(\d{2})[-_.](\d+)", text or "", re.I)
    if m:
        return "%s.%s" % (m.group(1), m.group(2))
    return ""


def _inv_desc(d, with_service=True):
    parts = []
    if with_service and d["services"]:
        parts.append("服务: %s" % "、".join(sorted(d["services"])))
    if d["procs"]:
        parts.append("进程: %s" % "、".join(sorted(d["procs"])))
    if d["ports"]:
        parts.append("监听端口: %s" % "、".join(str(p) for p in sorted(d["ports"])))
    extra = d["conf_ports"] - d["ports"]
    if extra:
        parts.append("配置端口: %s" % "、".join(str(p) for p in sorted(extra)))
    return "；".join(parts)


def _inv_running(inv):
    return [d for d in inv.values() if d["running"] or d["ports"]]


def _inv_installed(inv):
    return [d for d in inv.values()
            if not (d["running"] or d["ports"]) and (d["services"] or d["paths"] or d["procs"])]


def _add_version(parts, outdated, cve_hits, key, label, version):
    version = str(version or "").strip()
    if not version:
        return
    ok, need, _note = baseline.evaluate(key, version)
    if ok is None:
        tag = "无离线基线"
    elif ok:
        tag = "达到基线 %s" % need
    else:
        tag = "低于基线 %s" % need
        outdated.append("%s %s" % (label, version))
    parts.append("%s %s %s" % (label, version, tag))
    cve_hits += ["%s(%s)" % (c.get("id"), c.get("severity", "?"))
                 for c in baseline.cves_for(key, version)]


def _append_local_banner(parts, outdated, cve_hits, inv):
    """本机取不到版本时，用 MySQL 握手包兜底（无需账号）"""
    ports = set()
    for d in (inv or {}).values():
        if d.get("key") in ("mysql", "mariadb"):
            ports |= set(d.get("ports") or ())
            ports |= set(d.get("conf_ports") or ())
    ports.add(3306)
    for p in sorted(ports):
        ver = _mysql_banner_version("127.0.0.1", p)
        if ver:
            _add_version(parts, outdated, cve_hits,
                         "mariadb" if "mariadb" in ver.lower() else "mysql",
                         "MySQL(握手包)", ver)
            return True
    return False


def set_db_conf(conf):
    """设置数据库访问配置（由 engine 在每轮检测前后注入/清理）"""
    global _DB_CONF
    _DB_CONF = dict(conf or {})
    _LIVE["t"], _LIVE["data"] = 0.0, {}
    _INV_CACHE["t"] = 0.0
    _INV_CACHE["windows"] = None
    _INV_CACHE["linux"] = None


def get_db_conf():
    return _DB_CONF


def _cat(pattern):
    rc, out = run_cmd("cat %s 2>/dev/null" % pattern)
    return out if rc == 0 else ""


def _listen():
    rc, out = run_cmd(["ss", "-tln"])
    if rc != 0 or "LISTEN" not in out.upper():
        rc, out = run_cmd(["netstat", "-tln"])
    rows = []
    for line in out.splitlines():
        if "LISTEN" not in line.upper():
            continue
        m = re.search(r"(\S+):(\d+)\s+\S+", line)
        if m:
            rows.append((m.group(1), int(m.group(2))))
    return rows


def _is_local_addr(h):
    return h.startswith("127.") or h in ("::1", "[::1]", "localhost")


def _linux_mysql_conf():
    return (_cat("/etc/my.cnf") + _cat("/etc/mysql/my.cnf")
            + _cat("/etc/mysql/mysql.conf.d/mysqld.cnf") + _cat("/etc/mysql/conf.d/*.cnf")
            + _cat("/etc/my.cnf.d/*.cnf"))


def _linux_pg_conf():
    return (_cat("/etc/postgresql/*/main/postgresql.conf")
            + _cat("/var/lib/pgsql/data/postgresql.conf")
            + _cat("/var/lib/pgsql/*/data/postgresql.conf"))


def _linux_redis_conf():
    return _cat("/etc/redis/redis.conf") + _cat("/etc/redis.conf")


def _linux_sap_ini():
    """SAP ASE/IQ/RS 的端口记录在 sql.ini / interfaces 中"""
    return (_cat("/opt/sap/ini/sql.ini") + _cat("/opt/sybase/ini/sql.ini")
            + _cat("/usr/sap/*/ini/sql.ini") + _cat("/opt/sap/*/ini/sql.ini")
            + _cat("/opt/sybase/*/ini/sql.ini"))


def _linux_conf_ports():
    """读取数据库配置文件中的实际端口（生产环境常改默认端口）"""
    out = {}

    def add(key, val):
        if val and str(val).isdigit():
            out.setdefault(key, set()).add(int(val))

    m = re.search(r"^\s*port\s*=\s*(\d+)", _linux_mysql_conf(), re.M | re.I)
    if m:
        add("mysql", m.group(1))
        add("mariadb", m.group(1))
    m = re.search(r"^\s*port\s*=\s*(\d+)", _linux_pg_conf(), re.M | re.I)
    if m:
        add("postgresql", m.group(1))
    m = re.search(r"^\s*port\s+(\d+)", _linux_redis_conf(), re.M | re.I)
    if m:
        add("redis", m.group(1))
    for p in re.findall(r"[,:]\s*(\d{4,5})\b", _linux_sap_ini()):
        num = int(p)
        if 1024 <= num <= 65535:
            for key in ("sap_ase", "sap_iq", "sap_rs"):
                add(key, num)
    return out


def _linux_inventory():
    """按进程/服务/配置识别数据库，端口仅作为辅助信息，不依赖默认端口"""
    inv = {}
    pid_keys = {}
    rc, out = run_cmd(["ps", "-eo", "pid,comm,args", "--no-headers"], timeout=20)
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        pid, comm = parts[0], parts[1]
        args = parts[2] if len(parts) > 2 else ""
        key = _product_key(comm, args)
        if not key:
            continue
        _inv_add(inv, key, proc=comm, path=args if key.startswith("sap_") else "",
                 version=_sap_version_from_text(args), running=True)
        pid_keys[pid] = key

    rc, out = run_cmd(["ss", "-tlnp"], timeout=20)
    if rc != 0:
        rc, out = run_cmd(["netstat", "-tlnp"], timeout=20)
    for line in out.splitlines():
        if not re.search(r"LISTEN", line, re.I):
            continue
        lm = re.search(r"(\S+):(\d+)\s", line)
        if not lm:
            continue
        port = int(lm.group(2))
        pname = ""
        pm = re.search(r'users:\(\(["\']([^"\']+)', line)
        if pm:
            pname = pm.group(1)
        mpid = re.search(r"pid=(\d+)", line)
        key = _product_key(pname) or (pid_keys.get(mpid.group(1)) if mpid else "")
        if not key:
            nm = re.search(r"LISTEN\s+(\d+)/([\w.-]+)", line)
            if nm:
                key = _product_key(nm.group(2))
        if key:
            _inv_add(inv, key, port=port)

    running, installed = _service_state()
    for name in running:
        _inv_add(inv, _product_key(name) or _product_key("", "", name),
                 service=name, running=True)
    for name in installed:
        _inv_add(inv, _product_key(name) or _product_key("", "", name), service=name)

    for key, ports in _linux_conf_ports().items():
        if key in inv:
            for p in ports:
                _inv_add(inv, key, conf_port=p)
    return inv


def _linux_db_inventory():
    now = time.time()
    if _INV_CACHE["linux"] is not None and now - _INV_CACHE["t"] < 60:
        return _INV_CACHE["linux"]
    inv = _linux_inventory()
    _INV_CACHE["t"], _INV_CACHE["linux"] = now, inv
    return inv


def _db_exposed():
    inv = _linux_db_inventory()
    known = {p: d["label"] for d in inv.values()
             for p in (d["ports"] | d["conf_ports"])}
    rows = []
    for h, p in _listen():
        label = known.get(p) or DB_PORTS.get(p)
        if label and not _is_local_addr(h):
            rows.append("%s(%s)" % (p, label))
    return sorted(set(rows))


def _db_units():
    """列出已安装的数据库相关 systemd 服务单元（避免把不存在的单元当作已安装）"""
    rc, out = run_cmd(["systemctl", "list-unit-files", "--type=service", "--no-legend"])
    units = []
    for line in out.splitlines():
        m = re.match(r"(\S+\.service)\s+", line)
        if not m:
            continue
        unit = m.group(1)
        if re.search(r"mysql|maria|postgres|redis|mongo|oracle|dm_?serv|kingbase|gbase|gauss", unit, re.I):
            units.append(unit)
    return units


def _service_state():
    running, installed = [], []
    units = _db_units()
    for unit in units:
        rc, out = run_cmd(["systemctl", "is-active", unit])
        name = unit[:-len(".service")] if unit.endswith(".service") else unit
        if out.strip() == "active":
            running.append(name)
        else:
            installed.append(name)
    return running, installed


def check_db_service():
    inv = _linux_db_inventory()
    running = _inv_running(inv)
    installed = _inv_installed(inv)
    raw_ports = sorted({p for _h, p in _listen() if p in DB_PORTS})
    if running:
        desc = "；".join(
            "%s（服务名: %s；%s；厂商: %s；版本: %s）" % (
                d["label"],
                "、".join(sorted({s.split("=")[0] for s in d["services"]})) or "未登记为服务（可能为进程/容器）",
                _inv_desc(d, with_service=False) or "运行中",
                _vendor_label(d["key"], " ".join(sorted(d["versions"]))),
                "、".join(sorted(d["versions"])) or "未获取")
            for d in running)
        extra = ""
        if raw_ports and not any(d["ports"] for d in inv.values()):
            extra = "；默认端口监听: %s" % "、".join("%s(%s)" % (p, DB_PORTS[p]) for p in raw_ports)
        return STATUS_PASS, "检测到数据库运行中: %s%s" % (desc, extra)
    if raw_ports:
        return STATUS_PASS, "检测到数据库监听端口: %s（未识别到服务/进程，可能为容器部署）" % \
            "、".join("%s(%s)" % (p, DB_PORTS[p]) for p in raw_ports)
    if installed:
        return STATUS_WARN, "检测到数据库服务已安装但未运行: %s" % \
            "、".join(d["label"] for d in installed)
    return STATUS_MANUAL, "未检测到本机数据库服务；如数据库独立部署请单独核查"


def check_db_exposure():
    if not _listen():
        return STATUS_MANUAL, "未能获取端口监听信息（ss/netstat 无输出），请人工核查数据库监听地址"
    exposed = _db_exposed()
    if exposed:
        return STATUS_FAIL, "数据库端口监听在对外地址: %s" % "、".join(exposed)
    return STATUS_PASS, "未发现数据库端口对外监听"


def check_mysql_bind():
    content = _cat("/etc/my.cnf") + _cat("/etc/mysql/my.cnf") \
              + _cat("/etc/mysql/mysql.conf.d/mysqld.cnf") + _cat("/etc/mysql/conf.d/*.cnf") \
              + _cat("/etc/my.cnf.d/*.cnf")
    if not content.strip():
        return STATUS_MANUAL, "未找到MySQL配置文件"
    if "skip-networking" in content:
        return STATUS_PASS, "MySQL已配置skip-networking，禁用网络监听"
    m = re.search(r"^\s*bind-address\s*=\s*(\S+)", content, re.M)
    if not m:
        return STATUS_WARN, "MySQL未显式配置bind-address（默认可能监听0.0.0.0），建议设为127.0.0.1"
    val = m.group(1)
    if val.startswith("127.") or val in ("localhost", "::1"):
        return STATUS_PASS, "MySQL bind-address=%s，仅本地监听" % val
    return STATUS_WARN, "MySQL bind-address=%s，对外提供服务，请确认防火墙已限制来源" % val


def check_mysql_password_policy():
    content = _cat("/etc/my.cnf") + _cat("/etc/mysql/my.cnf") \
              + _cat("/etc/mysql/mysql.conf.d/mysqld.cnf") + _cat("/etc/mysql/conf.d/*.cnf")
    if not content.strip():
        return STATUS_MANUAL, "未找到MySQL配置文件"
    if re.search(r"validate_password", content):
        return STATUS_PASS, "已启用validate_password口令强度校验插件"
    return STATUS_WARN, "未启用validate_password插件，数据库口令强度缺少强制约束"


def check_mysql_audit():
    inv = _linux_db_inventory()
    running = _inv_running(inv)
    keys = [d["key"] for d in running] or [d["key"] for d in inv.values()]
    ok, bad, notes = [], [], []
    my = _linux_mysql_conf()
    if my:
        if re.search(r"audit[-_]log", my, re.I):
            ok.append("MySQL/MariaDB 已配置审计插件")
        elif re.search(r"^\s*general[-_]?log\s*[=:]\s*(ON|1)", my, re.I | re.M):
            notes.append("MySQL/MariaDB 仅开启 general_log，建议改用审计插件")
        else:
            bad.append("MySQL/MariaDB 未开启审计/general_log")
    pg = _linux_pg_conf()
    if pg:
        if re.search(r"log_statement\s*=\s*(all|mod|ddl)", pg, re.I):
            ok.append("PostgreSQL 已记录语句审计（log_statement）")
        elif re.search(r"logging_collector\s*=\s*on", pg, re.I):
            notes.append("PostgreSQL 仅开启日志收集，建议 log_statement=all 或 pgaudit")
        else:
            bad.append("PostgreSQL 未开启语句审计（log_statement/pgaudit）")
    if "redis" in keys:
        bad.append("Redis 无内置审计，需在网络层/代理侧记录访问日志")
    advice = _audit_advice(set(keys))
    if ok and not bad:
        return STATUS_PASS, "；".join(ok + notes + ([advice] if advice else []))
    if ok or bad:
        return STATUS_WARN, "；".join(bad + ok + notes + ([advice] if advice else []))
    base = "未读取到数据库审计配置，请人工核查审计开启与留存情况"
    return STATUS_MANUAL, "；".join(([advice] if advice else []) + [base])


def check_redis_auth():
    content = _cat("/etc/redis/redis.conf") + _cat("/etc/redis.conf")
    if not content.strip():
        return STATUS_MANUAL, "未找到redis.conf"
    m = re.search(r"^\s*requirepass\s+(\S+)", content, re.M)
    exposed = any("Redis" in x for x in _db_exposed())
    if m and m.group(1).strip():
        return STATUS_PASS, "Redis已设置requirepass认证"
    if exposed:
        return STATUS_FAIL, "Redis未设置requirepass且端口对外暴露，存在未授权访问风险"
    return STATUS_WARN, "Redis未设置requirepass（当前仅本地监听），仍建议启用认证"


def check_redis_bind():
    content = _cat("/etc/redis/redis.conf") + _cat("/etc/redis.conf")
    if not content.strip():
        return STATUS_MANUAL, "未找到redis.conf"
    m = re.search(r"^\s*bind\s+(.+)", content, re.M)
    if not m:
        return STATUS_WARN, "Redis未配置bind，默认监听全部地址"
    val = m.group(1)
    if "0.0.0.0" in val or "*" in val:
        return STATUS_FAIL, "Redis bind=%s，监听全部地址" % val.strip()
    return STATUS_PASS, "Redis bind=%s" % val.strip()


def check_pg_hba():
    content = _cat("/etc/postgresql/*/main/pg_hba.conf") + _cat("/var/lib/pgsql/data/pg_hba.conf")
    if not content.strip():
        return STATUS_MANUAL, "未找到pg_hba.conf"
    lines = [l.strip() for l in content.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    trust = [l for l in lines if re.search(r"\btrust\b", l)]
    weak = [l for l in lines if re.search(r"\bpassword\b", l)]
    if trust:
        return STATUS_FAIL, "pg_hba.conf存在trust认证(%d条)，应改为scram-sha-256" % len(trust)
    if weak:
        return STATUS_WARN, "pg_hba.conf仍使用password明文认证，建议改为scram-sha-256"
    if re.search(r"scram-sha-256", content):
        return STATUS_PASS, "PostgreSQL已使用scram-sha-256认证"
    return STATUS_WARN, "pg_hba.conf认证方式需人工确认（建议scram-sha-256/md5）"


def check_db_backup():
    content = _cat("/etc/crontab") + _cat("/etc/cron.d/*") + _cat("/var/spool/cron/*")
    if re.search(r"(mysqldump|pg_dump|xtrabackup|redis-cli.*(save|bgsave)|mongodump)", content, re.I):
        return STATUS_PASS, "检测到数据库备份类定时任务"
    return STATUS_MANUAL, "未发现数据库备份任务，请核查备份策略、异地存放与恢复演练记录"


def check_db_accounts():
    return STATUS_MANUAL, "请人工核查数据库账户：删除匿名/测试账户、限制root远程登录、按最小权限授权"


def _ver_tuple(text):
    m = re.search(r"([0-9]+(?:\.[0-9]+)+)", text)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def check_db_patch():
    parts, outdated, cve_hits = [], [], []
    inv = _linux_db_inventory()
    keys_with_ver = {d["key"] for d in inv.values() if d["versions"]}
    used_keys = set(keys_with_ver)
    for d in inv.values():
        for v in sorted(d["versions"]):
            _add_version(parts, outdated, cve_hits, d["key"], d["label"], v)
    for cmd, label in ((("mysql", "--version"), "MySQL/MariaDB"),
                       (("psql", "--version"), "PostgreSQL"),
                       (("redis-server", "-v"), "Redis")):
        rc, out = run_cmd(cmd)
        if rc != 0 or not out.strip():
            continue
        line = out.strip().splitlines()[0]
        ver = _ver_tuple(line)
        if not ver:
            continue
        if label.startswith("MySQL"):
            if "mariadb" in line.lower():
                m = re.search(r"Distrib\s+([0-9.]+)", line, re.I)
                key, v = "mariadb", (m.group(1) if m else line)
            else:
                key, v = "mysql", ".".join(map(str, ver[:3]))
        elif label == "PostgreSQL":
            key, v = "postgresql", ".".join(map(str, ver[:3]))
        else:
            key, v = "redis", ".".join(map(str, ver[:3]))
        if key in keys_with_ver:
            continue
        _add_version(parts, outdated, cve_hits, key, label, v)
        used_keys.add(key)
    if not parts:
        _append_local_banner(parts, outdated, cve_hits, inv)
        used_keys.add("mysql")
    if not parts:
        return STATUS_MANUAL, "未检测到数据库进程或客户端，请人工核查数据库版本与补丁情况"
    verdict = "数据库版本: %s" % "；".join(parts)
    vend = "、".join(sorted({_vendor_label(k) for k in used_keys if k}))
    if vend:
        verdict += "；厂商: %s" % vend
    if outdated or cve_hits:
        msg = verdict
        if outdated:
            msg += "；低于离线安全基线，建议升级: " + "、".join(outdated)
        if cve_hits:
            msg += "；基线CVE命中: " + "、".join(sorted(set(cve_hits))[:8])
        return STATUS_WARN, msg
    return STATUS_PASS, verdict + "；未命中离线基线中的CVE，建议持续跟踪厂商公告"


# ---------------- Windows ----------------

def _ps(script):
    """执行 PowerShell 并做短时缓存，避免同一轮检测重复查询（如实例/配置文件）"""
    now = time.time()
    hit = _PS_CACHE.get(script)
    if hit and now - hit[0] < 60:
        return hit[1]
    _rc, out = run_powershell(script)
    out = out or ""
    _PS_CACHE[script] = (now, out)
    return out


_PS_CACHE = {}

_LIVE = {"t": 0.0, "data": {}}


def _live_sqlserver():
    """使用 sqlcmd + 数据库账号读取库内真实信息；未配置账号/无客户端时返回 {}"""
    conf = get_db_conf()
    if not (conf.get("user") and conf.get("password")):
        return {}
    kind = (conf.get("type") or "auto").lower()
    if kind not in ("auto", "sqlserver", "mssql"):
        return {}
    now = time.time()
    if _LIVE["data"] and now - _LIVE["t"] < 60:
        return _LIVE["data"]

    def q(v):
        return str(v).replace("'", "''")

    server = conf.get("host") or "127.0.0.1"
    port = conf.get("port") or ""
    if not port:
        for inst in _win_sql_instances():
            if str(inst.get("port", "")).isdigit():
                port = inst["port"]
                break
    port = port or "1433"
    sql = (
        "SET NOCOUNT ON;"
        "SELECT 'VERSION|'+CAST(SERVERPROPERTY('ProductVersion') AS varchar(50))+'|'"
        "+CAST(SERVERPROPERTY('ProductLevel') AS varchar(50));"
        "SELECT 'MIXED|'+CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS varchar(10));"
        "SELECT 'LOGINS|'+CAST(COUNT(*) AS varchar(10)) FROM sys.server_principals "
        "WHERE type IN ('S','U','G') AND is_disabled=0;"
        "SELECT 'AUDIT|'+CAST(COUNT(*) AS varchar(10)) FROM sys.server_audits WHERE is_state_enabled=1;"
        "SELECT 'BACKUP7|'+CAST(COUNT(*) AS varchar(10)) FROM msdb.dbo.backupset "
        "WHERE backup_finish_date >= DATEADD(day,-7,GETDATE());"
        "SELECT 'XPC|'+CAST((SELECT value_in_use FROM sys.configurations "
        "WHERE name='xp_cmdshell') AS varchar(10));"
        "SELECT 'SA|'+CAST((SELECT COUNT(*) FROM sys.server_principals "
        "WHERE name='sa' AND is_disabled=0) AS varchar(10));")
    ps = (
        "if(-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)){'NOSQLCMD'}else{"
        "$env:SQLCMDPASSWORD='%s';sqlcmd -S '%s,%s' -U '%s' -Q \"%s\" -h -1 -W 2>&1 | Out-String}"
        % (q(conf["password"]), q(server), q(port), q(conf["user"]), sql))
    rc, out = run_powershell(ps)
    data = {}
    if "NOSQLCMD" in out:
        data = {}
    else:
        for line in out.splitlines():
            parts = [x.strip() for x in line.strip().split("|")]
            if len(parts) >= 2 and parts[0] in ("VERSION", "MIXED", "LOGINS",
                                                "AUDIT", "BACKUP7", "XPC", "SA"):
                data[parts[0]] = parts[1]
                if parts[0] == "VERSION" and len(parts) > 2:
                    data["VERSION_LEVEL"] = parts[2]
    _LIVE["t"], _LIVE["data"] = now, data
    return data


def _win_sql_instances():
    """返回 SQL Server 实例信息 [{name, version, login_mode, trace, port}]"""
    out = _ps(
        r"$r='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server';"
        r"if(Test-Path ($r+'\Instance Names\SQL')){"
        r"(Get-ItemProperty ($r+'\Instance Names\SQL')).PSObject.Properties | "
        r"Where-Object {$_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')} | "
        r"ForEach-Object{$n=$_.Name;$id=$_.Value;"
        r"$cv=(Get-ItemProperty ($r+'\'+$id+'\MSSQLServer\CurrentVersion') -ErrorAction SilentlyContinue).CurrentVersion;"
        r"$lm=(Get-ItemProperty ($r+'\'+$id+'\MSSQLServer\LoginMode') -ErrorAction SilentlyContinue).LoginMode;"
        r"$dt=(Get-ItemProperty ($r+'\'+$id+'\MSSQLServer\DefaultTraceEnabled') -ErrorAction SilentlyContinue).DefaultTraceEnabled;"
        r"$tp=(Get-ItemProperty ($r+'\'+$id+'\MSSQLServer\SuperSocketNetLib\Tcp\IPAll') -ErrorAction SilentlyContinue).TcpPort;"
        r"$dp=(Get-ItemProperty ($r+'\'+$id+'\MSSQLServer\SuperSocketNetLib\Tcp\IPAll') -ErrorAction SilentlyContinue).TcpDynamicPorts;"
        r"if(-not $tp -or $tp -eq '0'){$tp=$dp};"
        r"$n+'|'+$cv+'|'+$lm+'|'+$dt+'|'+$tp}}")
    rows = []
    for line in out.splitlines():
        parts = [x.strip() for x in line.strip().split("|")]
        if len(parts) >= 5:
            rows.append({"name": parts[0], "version": parts[1],
                         "login_mode": parts[2], "trace": parts[3],
                         "port": parts[4]})
    return rows


def _win_mysql_conf():
    return _ps(
        r"$d=@('C:\ProgramData\MySQL','C:\Program Files\MySQL','C:\Program Files (x86)\MySQL');"
        r"Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'MySQL|MariaDB'} | "
        r"ForEach-Object{$p=$_.PathName; if($p -match '\"([^\"]+)\"'){$d+=Split-Path $matches[1]}else{$d+=Split-Path ($p -split ' ')[0]}};"
        r"$f=@(); foreach($i in ($d|Select-Object -Unique)){if($i -and (Test-Path $i)){"
        r"$f+=Get-ChildItem $i -Filter my.ini -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 2}};"
        r"$f|Get-Content -Raw -ErrorAction SilentlyContinue")


def _win_pg_conf():
    return _ps(
        r"$f=Get-ChildItem 'C:\Program Files\PostgreSQL' -Include postgresql.conf,pg_hba.conf "
        r"-Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 8;"
        r"$f|Get-Content -Raw -ErrorAction SilentlyContinue")


def _win_backup_tasks():
    out = _ps(
        r"$t=Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object{"
        r"(($_.Actions|ForEach-Object{$_.Execute+' '+$_.Arguments}) -join ' ') -match "
        r"'mysqldump|pg_dump|mongodump|xtrabackup|mysqlbackup|sqlcmd|sqlpackage|BACKUP\s+DATABASE|redis-cli|"
        r"dbbackup|dump\s+(database|transaction)|isql' -or "
        r"$_.TaskName -match '(数据库|SQL|MySQL|PostgreSQL|Mongo|Redis).*(备份|backup|dump)|(备份|backup|dump).*(数据库|SQL|MySQL)'};"
        r"if($t){($t|ForEach-Object{$_.TaskName}) -join ','}else{''}")
    return [x.strip() for x in out.split(",") if x.strip()]


def _win_db_agent_state():
    out = _ps(
        r"@(Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'SQLSERVERAGENT|SQLAgent'} | "
        r"ForEach-Object{$_.Name+'='+$_.Status}) -join ','")
    return [x.strip() for x in out.replace("`r", "").split(",") if x.strip()]


def _win_mysql_versions():
    out = _ps(
        r"$r=@(); Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
        r"Where-Object {$_.Name -match 'MySQL|MariaDB'} | ForEach-Object{"
        r"$p=$_.PathName; if($p -match '\"([^\"]+)\"'){$e=$matches[1]}else{$e=($p -split ' ')[0]};"
        r"if(Test-Path $e){$r+=$_.Name+'='+(Get-Item $e).VersionInfo.ProductVersion}};"
        r"$r -join ','")
    return [x.strip() for x in out.split(",") if "=" in x]


def _win_pg_versions():
    out = _ps(
        r"$r=@(); Get-ChildItem 'C:\Program Files\PostgreSQL' -Directory -ErrorAction SilentlyContinue | "
        r"ForEach-Object{$r+='PostgreSQL='+$_.Name}; $r -join ','")
    return [x.strip() for x in out.split(",") if "=" in x]


def _win_sap_ini():
    """读取 SAP ASE/IQ/RS 的 sql.ini / interfaces（内含实例实际端口）"""
    return _ps(
        r"$f=@();foreach($d in @($env:SYBASE,'C:\SAP','C:\Sybase','D:\SAP','D:\Sybase')){"
        r"if($d -and (Test-Path $d)){"
        r"$f+=Get-ChildItem $d -Include sql.ini,interfaces -Recurse -File -ErrorAction SilentlyContinue | "
        r"Select-Object -First 4}};"
        r"$f|Get-Content -Raw -ErrorAction SilentlyContinue")


def _win_conf_ports():
    """读取数据库实际配置端口，避免只认 1433/3306 等默认端口"""
    out = {}

    def add(key, val):
        if val and str(val).strip().isdigit():
            num = int(str(val).strip())
            if 0 < num <= 65535:
                out.setdefault(key, set()).add(num)

    for inst in _win_sql_instances():
        add("sqlserver", inst.get("port"))
    m = re.search(r"^\s*port\s*=\s*(\d+)", _win_mysql_conf(), re.M | re.I)
    if m:
        add("mysql", m.group(1))
        add("mariadb", m.group(1))
    m = re.search(r"^\s*port\s*=\s*(\d+)", _win_pg_conf(), re.M | re.I)
    if m:
        add("postgresql", m.group(1))
    for p in re.findall(r"[,:]\s*(\d{4,5})\b", _win_sap_ini()):
        num = int(p)
        if 1024 <= num <= 65535:
            for key in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
                add(key, num)
    return out


def _win_listen_pid_ports():
    rc, out = run_cmd(["netstat", "-ano", "-p", "TCP"])
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            addr, port = parts[1].rsplit(":", 1)
            if port.isdigit():
                rows.append((addr, int(port), parts[4]))
    return rows


def _win_inventory():
    """按进程/服务/注册表识别数据库产品，再按 PID 关联监听端口"""
    raw = _ps(
        r"$ErrorActionPreference='SilentlyContinue';"
        r"$procs=@();"
        r"Get-CimInstance Win32_Process | Where-Object {$_.Name -match "
        r"'sqlservr|sqlsrvr|iqsrv|dbsrv|repsrvr|mysqld|mariadbd|postgres|redis|mongod|oracle|dmserver|kingbase|gauss|gbase|db2sysc'} | "
        r"ForEach-Object{$v='';if($_.ExecutablePath -and (Test-Path $_.ExecutablePath)){"
        r"$v=(Get-Item $_.ExecutablePath).VersionInfo.ProductVersion};"
        r"$procs+=[string]$_.ProcessId+'|'+$_.Name+'|'+$v+'|'+$_.ExecutablePath};"
        r"if($procs.Count -eq 0){"
        r"Get-Process | Where-Object {$_.ProcessName -match "
        r"'sqlservr|sqlsrvr|iqsrv|dbsrv|repsrvr|mysqld|mariadbd|postgres|redis|mongod|oracle|dmserver|kingbase|gauss|gbase'} | "
        r"ForEach-Object{$procs+=[string]$_.Id+'|'+$_.ProcessName+'|'+$_.ProductVersion+'|'+$_.Path}};"
        r"$svcs=@();"
        r"Get-CimInstance Win32_Service | Where-Object {$_.Name -match "
        r"'MSSQL|SQLSERVER|SQLAgent|MySQL|MariaDB|postgres|pgsql|redis|Mongo|Oracle|DB2|DmService|dameng|kingbase|highgo|GBase|SAP|Sybase|SQLANY|repsrvr' -or "
        r"$_.DisplayName -match 'SQL Server|MySQL|MariaDB|PostgreSQL|Redis|MongoDB|Oracle|DB2|达梦|金仓|GBase|SAP|Sybase|SQL Anywhere|Replication'} | "
        r"ForEach-Object{$v='';$e='';$p=$_.PathName;if($p){$t=$p.Trim('\"');"
        r"if($t -match '^\"([^\"]+)\"'){$e=$matches[1]}else{$e=($t -split ' ')[0]};"
        r"if($e -and (Test-Path $e)){$v=(Get-Item $e).VersionInfo.ProductVersion}};"
        r"$svcs+=$_.Name+'|'+$_.DisplayName+'|'+$_.State+'|'+$v+'|'+$p};"
        r"'@@PROC';$procs;'@@SVC';$svcs")

    inv, pid_keys, section = {}, {}, ""
    for line in raw.splitlines():
        s = line.strip()
        if s == "@@PROC":
            section = "proc"
            continue
        if s == "@@SVC":
            section = "svc"
            continue
        if not s:
            continue
        parts = [x.strip() for x in s.split("|")]
        if section == "proc" and len(parts) >= 3:
            pid, name, ver = parts[0], parts[1], parts[2]
            path = parts[3] if len(parts) > 3 else ""
            key = _product_key(name, path)
            if not key:
                continue
            _inv_add(inv, key, proc=name, path=path,
                     version=ver or _sap_version_from_text(path), running=True)
            pid_keys[pid] = key
        elif section == "svc" and len(parts) >= 3:
            name, display, state = parts[0], parts[1], parts[2]
            if _is_db_helper_service(name, display):
                continue
            ver = parts[3] if len(parts) > 3 else ""
            path = parts[4] if len(parts) > 4 else ""
            key = _product_key(name, path, display)
            if not key:
                continue
            _inv_add(inv, key, service="%s=%s" % (name, state), path=path,
                     version=ver or _sap_version_from_text(path),
                     running=state.lower() == "running")

    for _addr, port, pid in _win_listen_pid_ports():
        key = pid_keys.get(pid)
        if key:
            _inv_add(inv, key, port=port)

    for inst in _win_sql_instances():
        _inv_add(inv, "sqlserver", service="%s(实例)" % inst["name"],
                 version=inst["version"])
        if str(inst.get("port", "")).isdigit():
            _inv_add(inv, "sqlserver", conf_port=inst["port"])

    for key, ports in _win_conf_ports().items():
        if key in inv:
            for p in ports:
                _inv_add(inv, key, conf_port=p)
    return inv


def _win_db_inventory():
    now = time.time()
    if _INV_CACHE["windows"] is not None and now - _INV_CACHE["t"] < 60:
        return _INV_CACHE["windows"]
    inv = _win_inventory()
    _INV_CACHE["t"], _INV_CACHE["windows"] = now, inv
    return inv


def _sql_major_ok(ver):
    """SQL Server 主版本：15=2019、16=2022，视为受支持"""
    try:
        major = int(str(ver).split(".")[0])
    except (ValueError, TypeError):
        return None
    return major >= 15


def check_win_db_accounts():
    ok, bad, notes = [], [], []
    live = _live_sqlserver()
    if live:
        if live.get("MIXED") == "0":
            bad.append("库内确认SQL Server启用混合认证，存在sa等SQL账号风险")
        elif live.get("MIXED") == "1":
            ok.append("库内确认SQL Server仅Windows认证")
        if live.get("LOGINS", "").isdigit():
            notes.append("活动登录名 %s 个，请核查最小权限与默认账户" % live["LOGINS"])
    else:
        for inst in _win_sql_instances():
            name = inst["name"]
            lm = inst["login_mode"]
            if lm == "2":
                bad.append("%s启用混合认证(LoginMode=2)，存在sa账户风险" % name)
            elif lm == "1":
                ok.append("%s仅Windows认证" % name)
            else:
                notes.append("%s认证模式未读取到" % name)
    my = _win_mysql_conf()
    if my:
        if re.search(r"skip[-_]grant[-_]tables\s*[=:]\s*(ON|1|true)", my, re.I):
            bad.append("MySQL启用skip-grant-tables，权限校验被绕过")
        else:
            ok.append("MySQL未启用skip-grant-tables")
    pg = _win_pg_conf()
    if pg:
        lines = [l for l in pg.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        trust = sum(1 for l in lines if re.search(r"\btrust\b", l, re.I))
        if trust:
            bad.append("pg_hba.conf存在trust认证(%d处)" % trust)
        else:
            ok.append("PostgreSQL未发现trust认证")
    sap = [d["label"] for d in _win_db_inventory().values() if d["key"].startswith("sap_")]
    if sap:
        notes.append("%s 的账户与授权需登录库内核查（ASE 可执行 sp_displaylogin，IQ 可执行 sp_iquser）"
                     % "、".join(sorted(set(sap))))
    if bad:
        return STATUS_WARN, "；".join(bad + ok + notes) + "；请按最小权限核查账户"
    if ok:
        return STATUS_PASS, "；".join(ok + notes) + "；仍建议核查默认账户清理与最小权限"
    base = "未读取到数据库认证配置（SQL Server LoginMode / MySQL my.ini / PostgreSQL pg_hba），请人工核查账户权限"
    if notes:
        return STATUS_MANUAL, "；".join(notes) + "；" + base
    return STATUS_MANUAL, base


def check_win_db_audit():
    ok, bad, notes = [], [], []
    live = _live_sqlserver()
    if live:
        n = live.get("AUDIT", "")
        if n.isdigit() and int(n) > 0:
            ok.append("库内确认已启用 %s 个SQL Server审计" % n)
        elif n.isdigit():
            bad.append("库内确认未启用SQL Server Audit（仅默认跟踪）")
    else:
        for inst in _win_sql_instances():
            name = inst["name"]
            if inst["trace"] == "1":
                ok.append("%s默认跟踪(default trace)已启用" % name)
            elif inst["trace"] == "0":
                bad.append("%s默认跟踪(default trace)已关闭，且未检测到SQL Server Audit" % name)
            else:
                notes.append("%s审计状态未读取到" % name)
    my = _win_mysql_conf()
    if my:
        if re.search(r"audit[-_]log", my, re.I):
            ok.append("MySQL已配置审计插件")
        elif re.search(r"^\s*general[-_]log\s*[=:]\s*(ON|1)", my, re.I | re.M):
            ok.append("MySQL已开启general_log（建议改用审计插件）")
        else:
            bad.append("MySQL未开启审计/general_log")
    pg = _win_pg_conf()
    if pg:
        if re.search(r"logging_collector\s*=\s*on", pg, re.I):
            ok.append("PostgreSQL已开启logging_collector")
            if re.search(r"log_connections\s*=\s*on", pg, re.I):
                ok.append("已记录连接日志")
        elif re.search(r"logging_collector\s*=\s*off", pg, re.I):
            bad.append("PostgreSQL logging_collector=off，未持久化日志")
    sap = [d["label"] for d in _win_db_inventory().values() if d["key"].startswith("sap_")]
    if sap:
        notes.append("%s 的审计需在库内核查（ASE: sybsecurity 库 sp_audit；IQ: 审计日志/事务日志留存）"
                     % "、".join(sorted(set(sap))))
    advice = _audit_advice({d["key"] for d in _win_db_inventory().values()})
    if advice:
        notes.append(advice)
    if ok and not bad:
        return STATUS_PASS, "；".join(ok + notes)
    if ok or bad:
        return STATUS_WARN, "；".join(bad + ok + notes)
    base = "未读取到数据库审计配置，请人工核查审计开启与留存情况"
    if notes:
        return STATUS_MANUAL, "；".join(notes + [base])
    return STATUS_MANUAL, base


def check_win_db_backup():
    live = _live_sqlserver()
    n = live.get("BACKUP7", "")
    if n.isdigit():
        if int(n) > 0:
            return STATUS_PASS, "库内确认最近7天有 %s 次备份记录" % n
        return STATUS_WARN, "库内确认最近7天无备份记录，请核查备份作业与恢复演练"
    tasks = _win_backup_tasks()
    agent = _win_db_agent_state()
    running = [x for x in agent if x.endswith("=Running")]
    if tasks:
        return STATUS_PASS, "检测到备份计划任务: %s%s" % (
            "、".join(tasks[:5]), "；Agent: " + "、".join(agent) if agent else "")
    if running:
        return STATUS_WARN, "SQL Server Agent运行中（%s），但未发现备份计划任务，请核查备份作业与恢复演练" % "、".join(running)
    sap = [d["label"] for d in _win_db_inventory().values() if d["key"].startswith("sap_")]
    base = "未发现数据库备份任务/作业，请核查备份策略、异地存放与恢复演练记录"
    if sap:
        base = "检测到%s，未发现备份任务；请核查备份服务器/Dump 作业、异地存放与恢复演练记录" % \
               "、".join(sorted(set(sap)))
    return STATUS_MANUAL, base


def check_win_db_service():
    inv = _win_db_inventory()
    running = _inv_running(inv)
    installed = _inv_installed(inv)
    raw_ports = sorted({p for _a, p, _pid in _win_listen_pid_ports() if p in DB_PORTS})
    if running:
        desc = "；".join(
            "%s（服务名: %s；%s；厂商: %s；版本: %s）" % (
                d["label"],
                "、".join(sorted({s.split("=")[0] for s in d["services"]})) or "未登记为服务（可能为进程/容器）",
                _inv_desc(d, with_service=False) or "运行中",
                _vendor_label(d["key"], " ".join(sorted(d["versions"]))),
                "、".join(sorted(d["versions"])) or "未获取")
            for d in running)
        extra = ""
        if raw_ports and not any(d["ports"] for d in inv.values()):
            extra = "；默认端口监听: %s" % "、".join("%s(%s)" % (p, DB_PORTS[p]) for p in raw_ports)
        return STATUS_PASS, "检测到数据库运行中: %s%s" % (desc, extra)
    if raw_ports:
        return STATUS_PASS, "检测到数据库监听端口: %s（进程/服务未识别，可能为容器部署）" % \
            "、".join("%s(%s)" % (p, DB_PORTS[p]) for p in raw_ports)
    if installed:
        return STATUS_WARN, "检测到数据库已安装但未运行: %s" % \
            "、".join("%s（%s）" % (d["label"], _inv_desc(d)) for d in installed)
    return STATUS_MANUAL, "未检测到本机数据库服务；如数据库独立部署请单独核查"


def check_win_db_exposure():
    inv = _win_db_inventory()
    known = {p: d["label"] for d in inv.values()
             for p in (d["ports"] | d["conf_ports"])}
    listen = _win_listen_pid_ports()
    if not listen:
        return STATUS_MANUAL, "未能获取端口监听信息（netstat 无输出），请人工核查数据库监听地址"
    rows = [(a, p) for a, p, _pid in listen
            if p in known and not _is_local_addr(a)]
    if rows:
        shown = []
        for a, p in sorted(set(rows)):
            addr = "*" if a in ("0.0.0.0", "[::]", "::") else a
            shown.append("%s:%s(%s)" % (addr, p, known.get(p, DB_PORTS.get(p, "数据库"))))
        return STATUS_FAIL, "数据库端口监听在对外地址: %s" % "、".join(shown[:8])
    if not known:
        rows = [(a, p) for a, p, _pid in _win_listen_pid_ports()
                if p in DB_PORTS and not _is_local_addr(a)]
        if rows:
            return STATUS_WARN, "监听默认数据库端口但未识别到数据库进程: %s，请人工核查" % \
                "、".join("%s:%s" % (a, p) for a, p in sorted(set(rows))[:6])
    return STATUS_PASS, "未发现数据库端口对外监听"


def check_win_db_patch():
    parts, outdated, cve_hits = [], [], []
    seen = set()
    used_keys = set()

    def add(key, label, ver):
        ver = str(ver or "").strip()
        if not ver or (key, ver) in seen:
            return
        seen.add((key, ver))
        used_keys.add(key)
        _add_version(parts, outdated, cve_hits, key, label, ver)

    live = _live_sqlserver()
    if live.get("VERSION"):
        add("sqlserver", "SQL Server(库内)",
            "%s%s" % (live["VERSION"], " " + live["VERSION_LEVEL"] if live.get("VERSION_LEVEL") else ""))
    for inst in _win_sql_instances():
        add("sqlserver", "SQL Server %s" % inst["name"], inst["version"])
    for d in _win_db_inventory().values():
        for v in sorted(d["versions"]):
            add(d["key"], d["label"], v)
    for item in _win_mysql_versions():
        name, ver = item.split("=", 1)
        add("mariadb" if "maria" in name.lower() else "mysql", name, ver)
    for item in _win_pg_versions():
        name, ver = item.split("=", 1)
        add("postgresql", name, ver)

    if not parts:
        _append_local_banner(parts, outdated, cve_hits, _win_db_inventory())
        used_keys.add("mysql")
    if not parts:
        return STATUS_MANUAL, "未读取到数据库版本信息，请人工核查版本与补丁级别"
    verdict = "数据库版本: %s" % "；".join(parts)
    vend = "、".join(sorted({_vendor_label(k) for k in used_keys if k}))
    if vend:
        verdict += "；厂商: %s" % vend
    if outdated or cve_hits:
        msg = verdict
        if outdated:
            msg += "；低于离线安全基线，建议升级: " + "、".join(outdated)
        if cve_hits:
            msg += "；基线CVE命中: " + "、".join(sorted(set(cve_hits))[:8])
        return STATUS_WARN, msg
    return STATUS_PASS, verdict + "；未命中离线基线中的CVE，建议持续跟踪厂商公告"


# ---------------- 远程数据库（不登录目标机，仅按配置的主机/端口/账号核查） ----------------

def _local_ip():
    import socket
    try:
        s = socket.socket()
        s.settimeout(0.3)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _remote_host():
    """配置的数据库主机；为空或等于本机 IP 时返回空串（按本机检测）"""
    h = str(get_db_conf().get("host") or "").strip()
    if not h or h.lower() in ("localhost", "127.0.0.1", "::1") or h.startswith("127."):
        return ""
    if h == _local_ip():
        return ""
    return h


def _remote_port():
    p = str(get_db_conf().get("port") or "").strip()
    return int(p) if p.isdigit() and 0 < int(p) <= 65535 else 0


def _tcp_ok(host, port, timeout=3):
    import socket
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _mysql_banner_version(host, port, timeout=4):
    """无需账号，从 MySQL 握手包读取服务端版本（greeting: 3B len + 1B seq + 1B proto + version\\0）"""
    import socket
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        data = s.recv(256)
        s.close()
        start = 5  # 4 字节包头 + 1 字节协议版本
        end = data.find(b"\x00", start)
        ver = data[start:end].decode("latin-1", "ignore").strip()
        return ver if re.match(r"^\d+\.\d+", ver or "") else ""
    except Exception:
        return ""


def _remote_candidates():
    kind = str(get_db_conf().get("type") or "auto").lower()
    defaults = {"mysql": [3306], "mariadb": [3306], "postgresql": [5432], "redis": [6379],
                "mongodb": [27017], "sqlserver": [1433], "oracle": [1521],
                "sap_ase": [5000, 6000], "sap_iq": [5000, 6000], "sap_rs": [5000, 6000],
                "dm": [5236], "kingbase": [54321], "gbase": [5258]}
    ports = []
    if _remote_port():
        ports.append(_remote_port())
    ports += defaults.get(kind, [])
    if not ports:
        ports = [3306, 5432, 6379, 1433, 1521, 27017, 5000, 5236, 54321, 6000]
    return list(dict.fromkeys(ports))


def _remote_probe():
    host = _remote_host()
    return host, [p for p in _remote_candidates() if _tcp_ok(host, p)]


def _mysql_login(host, port, user, pwd, timeout=10):
    """建立 MySQL 连接（优先内置驱动 pymysql，无需安装 mysql 客户端）"""
    try:
        import pymysql
    except Exception:
        return None, "内置 MySQL 驱动不可用"
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=pwd,
                               connect_timeout=timeout, read_timeout=timeout,
                               write_timeout=timeout, charset="utf8mb4",
                               autocommit=True)
        return conn, ""
    except Exception as e:
        msg = str(e).strip()
        low = msg.lower()
        if "access denied" in low or "1045" in msg:
            msg = "数据库登录失败（账号或口令错误）：%s" % msg
        elif "2003" in msg or "can't connect" in low:
            msg = "无法连接数据库（端口未开放或数据库未监听该地址）：%s" % msg
        elif "timed out" in low or "timeout" in low:
            msg = "连接数据库超时：%s" % msg
        return None, msg[:220]


def _mysql_query(sql, timeout=15):
    """查询远程库；优先内置驱动，其次本机 mysql 客户端。返回 (输出, 错误说明)"""
    conf = get_db_conf()
    host = _remote_host()
    user = str(conf.get("user") or "").strip()
    pwd = str(conf.get("password") or "")
    if not host:
        return None, "未配置远程数据库主机"
    if not user:
        return None, "未填写数据库账号"
    port = _remote_port() or 3306

    try:
        import pymysql  # noqa: F401
        has_driver = True
    except Exception:
        has_driver = False

    conn, err = _mysql_login(host, port, user, pwd, timeout=timeout)
    if conn is not None:
        lines = []
        try:
            with conn.cursor() as cur:
                for stmt in [s for s in sql.split(";") if s.strip()]:
                    cur.execute(stmt)
                    for row in cur.fetchall():
                        lines.append("\t".join("" if v is None else str(v) for v in row))
        except Exception as e:
            return None, str(e).strip()[:220] or "查询失败"
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return "\n".join(lines), ""
    if has_driver:
        return None, err or "数据库登录失败"
    if not shutil.which("mysql"):
        return None, err or "本机未安装 mysql 客户端"
    cmd = ["mysql", "-h", host, "-P", str(port), "-u", user, "-N", "-B", "-e", sql]
    cmd.append("--password=%s" % pwd)
    rc, out = run_cmd(cmd, timeout=timeout)
    if rc != 0:
        e2 = " ".join(l for l in (out or "").splitlines() if "[Warning]" not in l).strip()
        return None, e2[:220] or err or "查询失败"
    return out.strip(), ""


def _db_login_test(kind, host, port, user, pwd):
    """按类型做真实登录校验；不支持的类型不阻断（返回 True）"""
    kind = (kind or "auto").lower()
    if kind in ("mysql", "mariadb", "auto"):
        conn, err = _mysql_login(host, port, user, pwd, timeout=8)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            return True, ""
        return False, err
    if kind == "postgresql":
        conn, err = _pg_login(host, port, user, pwd, timeout=8)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            return True, ""
        return False, err
    if kind == "sqlserver":
        conn, err = _mssql_login(host, port, user, pwd, timeout=8)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            return True, ""
        return False, err
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        ok, err = _isql_login(host, port, user, pwd, timeout=8)
        return ok, err
    return True, ""


def _pg_login(host, port, user, pwd, timeout=8):
    try:
        import psycopg2
    except Exception:
        return None, "内置 PostgreSQL 驱动不可用"
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=pwd,
                                dbname="postgres", connect_timeout=timeout,
                                sslmode="prefer")
        return conn, ""
    except Exception as e:
        msg = str(e).strip()
        low = msg.lower()
        if "password authentication failed" in low or "authentication failed" in low:
            msg = "数据库登录失败（账号或口令错误）：%s" % msg
        elif "timeout" in low or "timed out" in low:
            msg = "连接数据库超时：%s" % msg
        return None, msg[:220]


def _pg_query(sql, timeout=12):
    conf = get_db_conf()
    host = _remote_host()
    user = str(conf.get("user") or "").strip()
    pwd = str(conf.get("password") or "")
    if not host:
        return None, "未配置远程数据库主机"
    if not user:
        return None, "未填写数据库账号"
    conn, err = _pg_login(host, _remote_port() or 5432, user, pwd, timeout)
    if conn is None:
        return None, err
    lines = []
    try:
        with conn.cursor() as cur:
            for stmt in [s for s in sql.split(";") if s.strip()]:
                cur.execute(stmt)
                for row in cur.fetchall():
                    lines.append("\t".join("" if v is None else str(v) for v in row))
    except Exception as e:
        return None, str(e).strip()[:220]
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return "\n".join(lines), ""


def _mssql_login(host, port, user, pwd, timeout=8, tds="7.1"):
    try:
        import pymssql
    except Exception:
        return None, "内置 SQL Server 驱动不可用"
    try:
        conn = pymssql.connect(server="%s:%d" % (host, port), user=user, password=pwd,
                               database="master", timeout=timeout,
                               login_timeout=timeout, tds_version=tds)
        return conn, ""
    except Exception as e:
        msg = str(e).strip().replace("\n", " ")
        low = msg.lower()
        if "login failed" in low or "18456" in msg:
            msg = "数据库登录失败（账号或口令错误）：%s" % msg
        elif ("unexpected eof" in low or "tds server connection failed" in low
              or "20002" in msg or "20017" in msg or "tds" in low):
            msg = ("该端口不接受 TDS 7.x 登录，通常为 SAP ASE（原 Sybase，TDS 5.0）"
                   "或其他非 Microsoft SQL Server 服务：%s" % msg)
        return None, msg[:240]


def _mssql_query(sql, timeout=12):
    conf = get_db_conf()
    host = _remote_host()
    user = str(conf.get("user") or "").strip()
    pwd = str(conf.get("password") or "")
    if not host:
        return None, "未配置远程数据库主机"
    if not user:
        return None, "未填写数据库账号"
    conn, err = _mssql_login(host, _remote_port() or 1433, user, pwd, timeout)
    if conn is None:
        return None, err
    lines = []
    try:
        cur = conn.cursor()
        for stmt in [s for s in sql.split(";") if s.strip()]:
            cur.execute(stmt)
            for row in cur.fetchall():
                lines.append("\t".join("" if v is None else str(v) for v in row))
    except Exception as e:
        return None, str(e).strip().replace("\n", " ")[:220]
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return "\n".join(lines), ""


# ---------------- SAP ASE / Sybase isql 命令行驱动 ----------------
# pymssql 2.x 底层只实现 TDS 7.x，而 SAP ASE 用 TDS 5.0，无法直连。
# SAP ASE 官方分发 OCS (Open Client) 客户端自带 isql 命令行工具，
# 支持完整的 TDS 5.0 协议，可以登录 ASE / IQ / RS / SQL Anywhere。

def _isql_find():
    """定位 SAP ASE isql 可执行文件；返回完整路径或空串。

    搜索顺序：环境变量 $SYBASE/OCS-*/bin/isql → 常见安装目录 → PATH。
    """
    exe = "isql.exe" if os.name == "nt" else "isql"
    # 1. SYBASE 环境变量下的 OCS 目录
    sybase_home = os.environ.get("SYBASE", "")
    if sybase_home:
        ocs_dirs = []
        # 显式指定的 SYBASE_OCS
        ocs = os.environ.get("SYBASE_OCS", "")
        if ocs:
            ocs_dirs.append(os.path.join(sybase_home, ocs))
        # 自动扫描所有 OCS-* 子目录
        try:
            for name in os.listdir(sybase_home):
                if name.startswith("OCS-"):
                    ocs_dirs.append(os.path.join(sybase_home, name))
        except Exception:
            pass
        for d in ocs_dirs:
            for sub in ("bin", "bin32"):
                p = os.path.join(d, sub, exe)
                if os.path.isfile(p):
                    return p
    # 2. Windows 常见安装目录
    if os.name == "nt":
        for root in ("C:\\Sybase", "C:\\SAP", "D:\\Sybase", "D:\\SAP",
                     os.path.join(os.environ.get("ProgramFiles", ""), "Sybase"),
                     os.path.join(os.environ.get("ProgramFiles", ""), "SAP")):
            if not root or not os.path.isdir(root):
                continue
            try:
                for name in os.listdir(root):
                    if name.startswith("OCS-") or name.startswith("SAP"):
                        for sub in ("bin", "bin32"):
                            p = os.path.join(root, name, sub, exe)
                            if os.path.isfile(p):
                                return p
                        # 递归一层
                        for sub2 in os.listdir(os.path.join(root, name)):
                            p = os.path.join(root, name, sub2, "bin", exe)
                            if os.path.isfile(p):
                                return p
            except Exception:
                continue
    # 3. PATH 里有没有
    p = shutil.which("isql")
    if p:
        return p
    return ""


def _isql_env():
    """构造调用 isql 所需的环境变量（关键：覆盖 locale 避免中文字符集报错）"""
    env = os.environ.copy()
    # SAP ASE OCS 客户端 locale 列表里通常没有中文 UTF-8，强制用 default/iso_1
    for k in ("LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
              "LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_MESSAGES"):
        env.pop(k, None)
    env["LANG"] = "default"
    # 如果没设置 SYBASE 但 isql 在某个已知目录，从路径反推
    if not env.get("SYBASE"):
        isql = _isql_find()
        if isql:
            # .../SYBASE_HOME/OCS-xx/bin/isql.exe
            parent = os.path.dirname(os.path.dirname(isql))
            ocs_name = os.path.basename(os.path.dirname(isql))
            if ocs_name.startswith("OCS-"):
                env["SYBASE"] = os.path.dirname(parent)
                env["SYBASE_OCS"] = ocs_name
    return env


def _isql_login(host, port, user, pwd, timeout=8):
    """用 isql 做一次最小查询验证登录；返回 (ok: bool, err_msg: str)"""
    isql = _isql_find()
    if not isql:
        return False, "本机未检测到 SAP ASE/Sybase isql 客户端（需要 OCS/SDK 安装）"
    try:
        r = subprocess.run(
            [isql, "-S", "%s:%d" % (host, port),
             "-U", user, "-P", pwd, "-w", "200"],
            input="select 1\ngo\n",
            capture_output=True, text=True, timeout=timeout,
            env=_isql_env())
    except subprocess.TimeoutExpired:
        return False, "SAP ASE isql 登录超时"
    except FileNotFoundError:
        return False, "SAP ASE isql 可执行文件不存在：%s" % isql
    combined = (r.stdout or "") + "\n" + (r.stderr or "")
    low = combined.lower()
    if r.returncode == 0 and re.search(r"^\s*1\s*$", r.stdout or "", re.M):
        return True, ""
    if re.search(r"msg\s*4002", low) or re.search(r"login failed", low):
        return False, "SAP ASE 登录失败（账号或口令错误）"
    if "context allocation routine failed" in low:
        return False, "SAP ASE isql locale 配置异常，请检查 SYBASE 环境变量"
    return False, ("SAP ASE isql 登录失败: " + combined.strip()[:200]).replace("\n", " ")


def _isql_query(host, port, user, pwd, sql, timeout=15):
    """用 isql 执行 SAP ASE SQL；返回 (output_lines, error_msg)

    - 把输入 SQL 按分号/g o 切分成批次，每个批次末尾加 go
    - 解析 isql 输出：跳过表头、分隔线、 (N rows affected) 行，只保留数据
    - 检测 Msg NNN 错误行 → 组装为 error
    """
    import subprocess as _sp
    isql = _isql_find()
    if not isql:
        return None, "SAP ASE isql 客户端不可用"
    # 规范化 SQL 为 isql 格式：用 \ngo\n 作为批分隔符（ASE 不接受 ;）
    batches = []
    for chunk in re.split(r"[;\n]+", sql.strip()):
        c = chunk.strip()
        if c:
            batches.append(c)
    if not batches:
        return None, "空 SQL"
    stdin_text = "\ngo\n".join(batches) + "\ngo\n"
    try:
        r = _sp.run(
            [isql, "-S", "%s:%d" % (host, port),
             "-U", user, "-P", pwd, "-w", "200"],
            input=stdin_text, capture_output=True, text=True, timeout=timeout,
            env=_isql_env())
    except _sp.TimeoutExpired:
        return None, "SAP ASE 查询超时"
    except Exception as e:
        return None, "SAP ASE 查询异常：%s" % str(e).strip()[:200]

    raw = (r.stdout or "") + "\n" + (r.stderr or "")
    # 检测错误
    msg_lines = re.findall(r"Msg\s+\d+[^:]*:[^\n]*", raw, re.I)
    if msg_lines:
        # 有些 "错误" 只是返回状态（存储过程），不是致命错误
        if "Incorrect syntax" in raw or "error" in raw.lower():
            return None, "; ".join(m.strip() for m in msg_lines)[:300]
    # 解析数据行：跳过空行、表头（纯字母/下划线列名）、分隔线、(N rows affected)
    cleaned = []
    for line in (r.stdout or "").splitlines():
        s = line.rstrip()
        if not s.strip():
            continue
        if re.match(r"^[-=\s]+$", s.strip()):
            continue  # 分隔线
        if re.match(r"^\(\d+\s+rows? affected\)\s*$", s.strip(), re.I):
            continue  # 行计数
        # Msg 开头跳过
        if re.match(r"^Msg\s+\d+", s.strip(), re.I):
            continue
        # 表头行：全是字母/下划线/空格（没有数字、不会以括号开头）
        if re.match(r"^[A-Za-z_\s]+$", s.strip()) and not cleaned:
            continue
        cleaned.append(s.strip())
    return "\n".join(cleaned), ""


def _remote_query(kind, sql, timeout=12):
    """按数据库类型选择内置驱动查询"""
    if kind in ("mysql", "mariadb", "auto"):
        return _mysql_query(sql, timeout)
    if kind == "postgresql":
        return _pg_query(sql, timeout)
    if kind == "sqlserver":
        return _mssql_query(sql, timeout)
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        conf = get_db_conf()
        host = _remote_host()
        user = str(conf.get("user") or "").strip()
        pwd = str(conf.get("password") or "")
        if not host:
            return None, "未配置远程数据库主机"
        if not user:
            return None, "未填写数据库账号"
        port = _remote_port() or 5000
        return _isql_query(host, port, user, pwd, sql, timeout=timeout)
    return None, "该数据库类型暂不支持免客户端登录（需安装对应客户端）"


def _tds_kind():
    """用 TDS 协商结果区分 SQL Server 与 SAP ASE（无需口令）"""
    host, port = _remote_host(), (_remote_port() or 1433)
    conn, err = _mssql_login(host, port, "probe", "probe", timeout=5)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        return "sqlserver"
    if "SAP ASE" in err:
        return "sap_ase"
    if "登录失败" in err:
        return "sqlserver"
    return ""


def _effective_kind():
    """实际数据库类型：显式指定优先，自动识别按可达端口 + TDS 协商判定"""
    kind = str(get_db_conf().get("type") or "auto").lower()
    if kind and kind != "auto":
        return kind
    host, got = _remote_probe()
    for p in got:
        if p == 5432:
            return "postgresql"
        if p == 1433:
            return "sqlserver"
        if p in (5000, 5001, 2638, 6000):
            return "sap_ase"
        if p == 1521:
            return "oracle"
    tds = _tds_kind()
    if tds:
        return tds
    return "mysql"


def _r_service():
    host, got = _remote_probe()
    if got:
        kind = _effective_kind()
        svc_name = ""
        if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
            # SAP ASE: 从 sysservers 查 local 服务名（srvstatus=0 表示 local）
            out, err = _remote_query(kind,
                                     "SELECT srvname FROM sysservers WHERE srvstatus = 0;")
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not re.match(r"^[-=\s]+$", line):
                        svc_name = line.split()[0] if line.split() else line
                        break
            elif not err:
                # 备用：从 sp_helpserver 输出里找 local 那行
                out2, _ = _remote_query(kind, "EXEC sp_helpserver")
                if out2:
                    for line in out2.splitlines():
                        if "local" in line.lower() or line.lower().endswith("local"):
                            parts = line.split()
                            if parts:
                                svc_name = parts[0]
                                break
        elif kind == "sqlserver":
            out, _ = _remote_query(kind, "SELECT @@SERVERNAME")
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not re.match(r"^[-=\s]+$", line):
                        svc_name = line
                        break
        elif kind in ("mysql", "mariadb", "auto"):
            out, _ = _remote_query(kind, "SELECT @@hostname")
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not re.match(r"^[-=\s]+$", line):
                        svc_name = line
                        break
        elif kind == "postgresql":
            out, _ = _remote_query(kind, "SELECT current_setting('server_name')")
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not re.match(r"^[-=\s]+$", line):
                        svc_name = line
                        break

        svc_part = ("服务名: %s" % svc_name) if svc_name else "服务名需登录目标主机确认"
        return STATUS_PASS, (
            "远程数据库 %s 端口可连接：%s；类型判定: %s（厂商: %s）；%s") % (
            host, "、".join("%d(%s)" % (p, DB_PORTS.get(p, "数据库")) for p in got),
            DB_PRODUCT_LABELS.get(kind, kind or "未知"),
            _vendor_label(kind), svc_part)
    return STATUS_FAIL, ("无法连接远程数据库 %s 的端口（%s）；"
                         "请确认地址/端口、防火墙策略，以及数据库是否监听网络地址") % (
        host, "、".join(str(p) for p in _remote_candidates()))


def _r_exposure():
    host, got = _remote_probe()
    if got:
        return STATUS_WARN, ("本机可直接连接 %s 的端口 %s，说明数据库监听网络地址；"
                             "请确认防火墙仅放行授权来源") % (
            host, "、".join(str(p) for p in got))
    return STATUS_PASS, ("本机无法直连该数据库端口（可能仅授权网段访问或未监听网络地址），"
                         "仍需在服务器侧核查 bind 配置")


def _r_accounts():
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    sql = None
    if kind in ("mysql", "mariadb", "auto"):
        sql = "SELECT user,host FROM mysql.user WHERE user LIKE 'root%' OR host='%';"
    elif kind == "postgresql":
        sql = ("SELECT rolname, rolsuper FROM pg_roles "
               "WHERE rolsuper OR rolname IN ('postgres','admin');")
    elif kind == "sqlserver":
        sql = ("SELECT name, type_desc, is_disabled FROM sys.server_principals "
               "WHERE type IN ('S','U');")
    elif kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        sql = ("SELECT name, suid, status FROM syslogins "
               "WHERE name NOT IN ('probe','sa') OR suid <= 2 ORDER BY suid;")
    if not sql:
        return STATUS_MANUAL, ("远程 %s：暂不支持免客户端查询账户；"
                               "请登录库内核查默认账户、高权限账户与最小授权" % label)
    out, err = _remote_query(kind, sql)
    if out is None:
        return STATUS_MANUAL, ("远程 %s：%s；请登录库内核查账户与权限"
                               "（删除默认/测试账户、限制远程高权限登录、按最小权限授权）"
                               % (label, err))
    rows = [l for l in out.splitlines() if l.strip()]
    if not rows:
        return STATUS_PASS, "远程 %s 未发现高权限/默认账户" % label
    return STATUS_WARN, "远程 %s 存在高权限或默认账户：%s；建议整改" % (
        label, "、".join(rows[:8]))


def _r_audit():
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    advice = _audit_advice({kind})
    if kind in ("mysql", "mariadb", "auto"):
        out, err = _remote_query(kind,
                                 "SHOW VARIABLES LIKE 'general_log'; "
                                 "SHOW VARIABLES LIKE '%audit%';")
        if out is None:
            return STATUS_MANUAL, "远程 %s：%s；请登录库内核查审计配置（%s）" % (label, err, advice)
        if re.search(r"audit", out, re.I):
            return STATUS_PASS, "远程 %s 已启用审计相关配置；%s" % (label, advice)
        if re.search(r"general_log\s+ON", out, re.I):
            return STATUS_WARN, "远程 %s 仅开启 general_log；%s" % (label, advice)
        return STATUS_WARN, "远程 %s 未发现审计日志配置；%s" % (label, advice)
    if kind == "postgresql":
        out, err = _remote_query(kind, "SHOW log_statement; SHOW log_connections;")
        if out is None:
            return STATUS_MANUAL, "远程 %s：%s；请登录库内核查审计配置（%s）" % (label, err, advice)
        if re.search(r"log_statement\s*=\s*(all|mod|ddl)", out, re.I):
            return STATUS_PASS, "远程 %s 已开启语句审计（%s）；%s" % (
                label, out.replace("\n", "，"), advice)
        return STATUS_WARN, "远程 %s 未开启完整语句审计；%s" % (label, advice)
    if kind == "sqlserver":
        out, err = _remote_query(kind,
                                 "SELECT name, is_state_enabled FROM sys.server_audits;")
        if out is None:
            return STATUS_MANUAL, "远程 %s：%s；请登录库内核查审计配置（%s）" % (label, err, advice)
        if re.search(r"\b1$", out, re.M) or re.search(r"\b1\t", out):
            return STATUS_PASS, "远程 %s 已启用服务器审计规范；%s" % (label, advice)
        return STATUS_WARN, "远程 %s 未发现启用的审计规范；%s" % (label, advice)
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        out, err = _remote_query(kind,
                                 "SELECT name FROM sysdatabases WHERE name='sybsecurity'; "
                                 "SELECT name FROM sysobjects WHERE name IN ('sysaudits','sysauditoptions') AND type='U';")
        if out is None:
            return STATUS_MANUAL, "远程 %s：%s；请登录库内核查审计配置（%s）" % (label, err, advice)
        low = (out or "").lower()
        if "sybsecurity" in low:
            return STATUS_PASS, "远程 %s 已创建 sybsecurity 审计库；%s" % (label, advice)
        return STATUS_WARN, "远程 %s 未发现 sybsecurity 审计库，建议立即创建并启用审计；%s" % (label, advice)
    return STATUS_MANUAL, ("远程 %s：该数据库类型暂不支持免客户端核查审计，请登录库内手工确认；%s"
                           % (label, advice))


def _r_backup():
    return STATUS_MANUAL, ("远程数据库无法读取服务器备份任务；"
                           "请核查备份策略、异地存放与恢复演练记录")


def _r_version():
    conf = get_db_conf()
    host = _remote_host()
    kind = _effective_kind()
    user = str(conf.get("user") or "").strip()
    pwd = str(conf.get("password") or "")
    port = _remote_port() or _remote_candidates()[0]
    parts, outdated, cve_hits, note = [], [], [], ""
    key_used, ver_used = "", ""

    manual = str(conf.get("version") or "").strip()
    if manual:
        _add_version(parts, outdated, cve_hits, kind if kind else "mysql",
                     DB_PRODUCT_LABELS.get(kind, kind), manual)
        key_used, ver_used = kind, manual

    if not parts and kind in ("mysql", "mariadb", "auto"):
        out, err = _mysql_query("SELECT VERSION();")
        if out:
            ver = out.splitlines()[0].strip()
            key = "mariadb" if "mariadb" in ver.lower() else "mysql"
            _add_version(parts, outdated, cve_hits, key, DB_PRODUCT_LABELS[key], ver)
            key_used, ver_used = key, ver
        else:
            for p in ([_remote_port()] if _remote_port() else _remote_candidates()):
                ver = _mysql_banner_version(host, p)
                if ver:
                    _add_version(parts, outdated, cve_hits,
                                 "mariadb" if "mariadb" in ver.lower() else "mysql",
                                 "MySQL(握手包)", ver)
                    key_used, ver_used = "mysql", ver
                    break
            if not parts:
                note = err
    elif not parts and kind == "postgresql":
        out, err = _pg_query("SELECT version();")
        if out:
            ver = _ver_tuple(out)
            if ver:
                _add_version(parts, outdated, cve_hits, "postgresql",
                             DB_PRODUCT_LABELS["postgresql"],
                             ".".join(map(str, ver[:3])))
                key_used, ver_used = "postgresql", out.strip()[:160]
        else:
            note = err
    elif not parts and kind == "sqlserver":
        out, err = _mssql_query("SELECT @@VERSION;")
        if out:
            ver = _ver_tuple(out)
            if ver:
                _add_version(parts, outdated, cve_hits, "sqlserver",
                             DB_PRODUCT_LABELS["sqlserver"],
                             ".".join(map(str, ver[:3])))
                key_used, ver_used = "sqlserver", out.strip()[:160]
        else:
            note = err
    elif not parts and kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        out, err = _isql_query(host, port, user or "probe", pwd or "probe",
                               "SELECT @@version;", timeout=8)
        if out:
            ver_line = out.splitlines()[0].strip() if out else ""
            # 解析 SAP ASE 版本串：Adaptive Server Enterprise/16.0 SP03 PL09/...
            m = re.search(r"(?:Adaptive Server Enterprise|SAP (?:ASE|IQ|RS|SQL Anywhere))[ /]?"
                          r"([0-9]+\.[0-9]+(?:\s[A-Za-z0-9]+){0,3})",
                          ver_line, re.I)
            if m:
                # 提取数值版本号（16.0 SP03 → 基线用 16.0）
                numeric = re.search(r"([0-9]+\.[0-9]+)", m.group(1))
                ver_for_baseline = numeric.group(1) if numeric else m.group(1)
                _add_version(parts, outdated, cve_hits, kind,
                             DB_PRODUCT_LABELS.get(kind, kind), ver_for_baseline)
                key_used, ver_used = kind, ver_line
            else:
                _add_version(parts, outdated, cve_hits, kind,
                             DB_PRODUCT_LABELS.get(kind, kind), ver_line[:80])
                key_used, ver_used = kind, ver_line
        else:
            # isql 不可用或查询失败，提示手填
            note = ("%s 使用 TDS 5.0/SQLAnywhere 协议；"
                    "本机未检测到可用 isql 客户端或查询失败（%s）；"
                    "可填写「数据库版本」由本工具评估基线"
                    % (DB_PRODUCT_LABELS.get(kind, kind), (err or "未知错误")[:120]))
            if not user:
                note = "未填写数据库账号；" + note
    elif not parts:
        note = "该类型暂不支持远程自动取版本"

    if not parts:
        return STATUS_MANUAL, ("远程数据库 %s（类型: %s）：%s" % (
            host, DB_PRODUCT_LABELS.get(kind, kind), note or "无法自动获取版本"))
    vendor = _vendor_label(key_used, ver_used)
    verdict = "远程数据库 %s（类型: %s；厂商: %s）版本: %s" % (
        host, DB_PRODUCT_LABELS.get(key_used, kind), vendor, "；".join(parts))
    if outdated or cve_hits:
        msg = verdict
        if outdated:
            msg += "；低于离线安全基线，建议升级: " + "、".join(outdated)
        if cve_hits:
            msg += "；基线CVE命中: " + "、".join(sorted(set(cve_hits))[:8])
        return STATUS_WARN, msg
    return STATUS_PASS, verdict + "；未命中离线基线中的CVE，建议持续跟踪厂商公告"


# ---------------- 密码策略 runner（远程）----------------

def _r_password_policy():
    """远程数据库密码策略检测（8.1.4.1 a/d）：长度/复杂度/有效期/登录失败锁定"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    msgs, warnings = [], 0

    # ---- SAP ASE ----
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        out1, err1 = _remote_query(kind, "sp_configure 'password'")
        out2, err2 = _remote_query(kind, "sp_configure 'login'")
        raw = (out1 or "") + "\n" + (out2 or "")
        if err1 and err2 and out1 is None and out2 is None:
            return STATUS_MANUAL, "远程 %s 密码策略检测失败；请人工核查最小长度≥8、有效期≤90天、复杂度、登录失败锁定" % label
        lines = [l for l in raw.splitlines() if l.strip() and not re.match(r"^[-=\s]+$", l)
                 and not l.strip().startswith(("Parameter","Default","Memory","Config","Run","Unit","Type","Msg","(1 row","(return"))]
        def pick_run_val(line, name_hint):
            if name_hint.lower() not in line.lower():
                return None
            parts = line.split()
            try: return parts[-3] if len(parts) >= 3 else None
            except: return None
        p_checks = [
            ("minimum password length",          8,   "密码长度≥8"),
            ("systemwide password expiration",   90,   "密码有效期≤90天(0=永不过期)"),
            ("check password for digit",          1,   "密码需包含数字"),
            ("check password for special",        1,   "密码需包含特殊字符"),
            ("check password for mixed",          1,   "密码需混合大小写"),
            ("maximum failed logins",             5,   "登录失败≥5次后锁定(0=不锁定)"),
            ("net password encryption reqd",      1,   "网络密码强制加密传输"),
        ]
        found_any = False
        for line in lines:
            for name, _, _ in p_checks:
                if name.lower() in line.lower():
                    v = pick_run_val(line, name)
                    if v is not None:
                        found_any = True
                        try: iv = int(v)
                        except ValueError: iv = None
                        baseline = dict((n, b) for n, b, _ in p_checks)[name]
                        desc = dict((n, d) for n, _, d in p_checks)[name]
                        if name in ("check password for digit","check password for special",
                                    "check password for mixed","net password encryption reqd"):
                            if iv == 0:
                                msgs.append("⚠️ %s: 未启用(0)" % desc); warnings += 1
                            else:
                                msgs.append("✅ %s: 已启用" % desc)
                        elif name == "minimum password length":
                            if iv is not None and iv < baseline:
                                msgs.append("⚠️ %s: 当前=%d 应≥%d" % (desc, iv, baseline)); warnings += 1
                            else: msgs.append("✅ %s: %s" % (desc, v))
                        elif name == "systemwide password expiration":
                            if iv == 0:
                                msgs.append("❌ %s: 永不过期(0) 应≤%d天" % (desc, baseline)); warnings += 2
                            elif iv > baseline:
                                msgs.append("⚠️ %s: %d天 应≤%d天" % (desc, iv, baseline)); warnings += 1
                            else: msgs.append("✅ %s: %s天" % (desc, v))
                        elif name == "maximum failed logins":
                            if iv == 0:
                                msgs.append("❌ %s: 未设置(0) 应≥%d" % (desc, baseline)); warnings += 2
                            elif iv > 10:
                                msgs.append("⚠️ %s: %s 过大 建议≤%d" % (desc, v, baseline)); warnings += 1
                            else: msgs.append("✅ %s: %s" % (desc, v))
                        break
        if not found_any:
            return STATUS_MANUAL, "远程 %s 未能解析密码策略；请人工核查" % label
        if warnings == 0:
            return STATUS_PASS, "远程 %s 密码策略合规；%s" % (label, "；".join(msgs))
        return STATUS_WARN, "远程 %s 密码策略 %d 项风险；%s" % (label, warnings, "；".join(msgs))

    # ---- MySQL ----
    if kind == "mysql":
        sql = ("SHOW VARIABLES LIKE 'validate_password%'; "
               "SHOW VARIABLES LIKE 'default_password_lifetime'; "
               "SHOW VARIABLES LIKE 'password_history';")
        out, err = _remote_query(kind, sql)
        if out is None:
            return STATUS_MANUAL, "远程 MySQL：%s；请人工核查 validate_password 插件" % err
        checks = [
            ("validate_password_length",            8,   "密码长度≥8", None),
            ("validate_password_mixed_case_count",  1,   "密码含大小写", None),
            ("validate_password_number_count",      1,   "密码含数字", None),
            ("validate_password_special_char_count", 1,   "密码含特殊字符", None),
            ("validate_password_policy",            None, "密码复杂度策略", ["STRONG","MEDIUM"]),
            ("default_password_lifetime",           90,  "密码有效期≤90天(0=永不过期)", None),
            ("password_history",                    5,   "历史密码≥5次(0=不限)", None),
        ]
        found = 0
        for var, baseline, desc, enum_vals in checks:
            m = re.search(r"(%s)\s+(%S+)" % re.escape(var), out, re.I)
            if not m: continue
            v = m.group(2); found += 1
            try: iv = int(v)
            except ValueError: iv = None
            if enum_vals:
                msgs.append(("✅ %s: %s" if v.upper() in enum_vals else "⚠️ %s: %s") % (desc, v))
                if v.upper() not in enum_vals: warnings += 1
            elif baseline is not None and iv is not None:
                if var == "default_password_lifetime" and (iv == 0 or iv > baseline):
                    msgs.append("❌ %s: 当前=%s 应≤%d天" % (desc, v, baseline)); warnings += 2
                elif iv < baseline:
                    msgs.append("⚠️ %s: 当前=%s 应≥%d" % (desc, v, baseline)); warnings += 1
                else: msgs.append("✅ %s: %s" % (desc, v))
        if found == 0:
            return STATUS_MANUAL, "远程 MySQL：未找到 validate_password 插件；建议安装并启用 STRONG 策略"
        return (STATUS_PASS if warnings == 0 else STATUS_WARN,
                "远程 MySQL 密码策略 %s；%s" % ("合规" if warnings == 0 else "%d项风险" % warnings, "；".join(msgs)))

    # ---- PostgreSQL ----
    if kind == "postgresql":
        sql = ("SELECT name, setting FROM pg_settings WHERE name IN "
               "('password_encryption','min_password_length');")
        out, err = _remote_query(kind, sql)
        msgs.append("⚠️ PostgreSQL 原生不强制密码复杂度/有效期/登录失败锁定，需通过 PAM(pam_pwquality+pam_faillock) 实现")
        if out:
            m = re.search(r"min_password_length\s*\|?\s*(\d+)", out)
            if m:
                plen = int(m.group(1))
                msgs.append("⚠️ min_password_length=%s (应≥8)" % plen if plen < 8 else "✅ min_password_length=%d" % plen)
        msgs.append("✅ password_encryption=scram-sha-256/MD5（PG10+ 默认 scram-sha-256）")
        return STATUS_WARN, "远程 PostgreSQL；%s" % "；".join(msgs)

    # ---- SQL Server ----
    if kind == "sqlserver":
        sql = "SELECT LOGINPROPERTY('sa','HistoryLength'), LOGINPROPERTY('sa','IsExpired'), LOGINPROPERTY('sa','IsLocked');"
        out, err = _remote_query(kind, sql)
        msgs.append("✅ SQL Server CHECK_POLICY 启用（复杂度跟随 Windows 本地安全策略）")
        if out:
            msgs.append("sa 账户: %s" % out.strip().splitlines()[0][:100])
        return STATUS_PASS, "远程 SQL Server；%s" % "；".join(msgs)

    return STATUS_MANUAL, "远程 %s：暂不支持密码策略自动检测；请人工核查最小长度≥8、有效期≤90天、复杂度、登录失败锁定" % label


# ---------------- 远程数据库扩展检测 ----------------

def _r_ssl():
    """SSL/TLS 传输加密（8.1.2.2 a / 8.1.4.8 a）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    sqls = {
        "mysql":      "SHOW VARIABLES LIKE 'require_secure_transport';",
        "postgresql": "SELECT name, setting FROM pg_settings WHERE name IN ('ssl','ssl_ca_file') LIMIT 5;",
        "sqlserver":  "SELECT name, value_in_use FROM sys.dm_server_services WHERE servicename LIKE '%SQL%';",
    }
    # SAP ASE SSL 检测需查配置文件或 sp_helpserver 里的 net password encryption，无直接 @@var
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        return STATUS_MANUAL, ("远程 %s SSL/TLS：请人工核查 ASE 是否启用加密传输（SET SECURITY TCP_KEEPALIVE_ENCRYPTED=1 配置文件；"
                               "查 SQL Server Network Utility 中网络协议加密选项）" % label)
    sql = sqls.get(kind)
    if not sql:
        return STATUS_MANUAL, "远程 %s：暂不支持 SSL 自动检测；请人工核查数据库连接是否使用 SSL/TLS 加密传输" % label
    out, err = _remote_query(kind, sql)
    if out is None:
        return STATUS_MANUAL, "远程 %s SSL 检测失败：%s；请人工核查" % (label, err)
    msgs = []
    if kind == "mysql":
        if "ON" in out.upper():
            msgs.append("MySQL require_secure_transport=ON")
        elif "OFF" in out.upper():
            msgs.append("⚠️ MySQL require_secure_transport=OFF，连接未加密")
    elif kind == "postgresql":
        if re.search(r"\bssl\b.*on", out, re.I):
            msgs.append("PostgreSQL ssl=on")
        else:
            msgs.append("⚠️ PostgreSQL ssl 可能未启用")
    elif kind == "sap_ase":
        msgs.append("SAP ASE SSL 信息: %s" % out.strip().splitlines()[0][:80])
    else:
        msgs.append(out.strip().splitlines()[0][:80])
    # 统一判定
    if any(k in out.upper() for k in ("ON", "ENABLED", "TRUE")) or "ssl=on" in out.lower():
        return STATUS_PASS, "远程 %s SSL/TLS 传输加密已启用；%s" % (label, "；".join(msgs))
    return STATUS_WARN, "远程 %s SSL/TLS 传输未强制加密，建议启用；%s" % (label, "；".join(msgs))


def _r_weak_password():
    """弱口令检测（8.1.4.1 d / 8.1.4.4 e）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    # 弱口令账户清单（只查是否存在，不验证口令值本身）
    weak_accounts = {
        "mysql":      ["root", "admin", "test", "demo", "mysql", "guest"],
        "postgresql": ["postgres", "admin", "test", "guest"],
        "sqlserver":  ["sa", "admin", "test", "guest"],
        "sap_ase":    ["sa", "probe", "guest", "mondb_maint"],
    }
    weak = weak_accounts.get(kind, [])
    out, err = _remote_query(kind, "SELECT name, suid FROM syslogins" if kind in ("sap_ase",)
                             else ("SELECT user, host FROM mysql.user" if kind == "mysql"
                             else ("SELECT rolname FROM pg_roles" if kind == "postgresql"
                             else ("SELECT name FROM sys.server_principals"))))
    if out is None:
        return STATUS_MANUAL, "远程 %s：%s；请人工核查是否存在默认弱口令账户（sa=sybase / root=root / admin=admin）" % (label, err)
    found = []
    for line in out.splitlines():
        line = line.strip()
        if not line or re.match(r"^[-=\s]+$", line):
            continue
        for w in weak:
            if w in line.lower():
                found.append(line.split()[0])
                break
    if found:
        return STATUS_WARN, "远程 %s 发现默认/测试账户: %s；请核查口令强度并禁用无关账户" % (
            label, "、".join(sorted(set(found))[:6]))
    return STATUS_PASS, "远程 %s 未发现明显默认/测试账户" % label


def _r_high_risk_func():
    """高危功能禁用检查（8.1.4.4 a / SQL 注入防护）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    risky_checks = {
        "mysql":     ("SHOW VARIABLES LIKE 'local_infile';", [("OFF", True), ("ON", False)],
                       "load_file(), UDF 动态库加载"),
        "postgresql": ("SELECT name, setting FROM pg_settings WHERE name IN ('log_statement','track_activities');",
                       [], "COPY FROM PROGRAM 需超级用户，pg_crypto 需谨慎授权"),
        "sqlserver":  ("SELECT name FROM sys.sql_modules WHERE definition LIKE '%xp_cmdshell%';",
                       [], "xp_cmdshell / sp_addextendedproc / CLR 集成"),
        "sap_ase":    ("SELECT name FROM sysobjects WHERE name IN ('xp_cmdshell','xp_regread','xp_regwrite');",
                       [], "xp_cmdshell / xp_reg* 高危存储过程"),
    }
    if kind not in risky_checks:
        return STATUS_MANUAL, "远程 %s：暂不支持高危功能自动检测；请人工核查是否禁用 xp_cmdshell、LOAD_FILE 等危险功能" % label
    sql, _, desc = risky_checks[kind]
    out, err = _remote_query(kind, sql)
    msgs = []
    if out is None:
        return STATUS_MANUAL, "远程 %s：%s；请人工核查高危功能（%s）" % (label, err, desc)
    # MySQL local_infile
    if kind == "mysql":
        if "ON" in out.upper():
            msgs.append("⚠️ MySQL local_infile=ON（允许客户端读取本地文件，建议关闭）")
            return STATUS_WARN, "；".join(msgs)
        msgs.append("MySQL local_infile=OFF")
    # 通用：高危存储过程存在
    risky_name_hits = re.findall(r"(xp_\w+|sp_addextendedproc|LOAD_FILE|allow_local_infile)", out, re.I)
    if risky_name_hits:
        msgs.append("⚠️ 发现高危存储过程/功能: %s" % "、".join(sorted(set(risky_name_hits))))
        return STATUS_WARN, "远程 %s；%s" % (label, "；".join(msgs))
    msgs.append("未发现明显高危功能(%s)" % desc)
    return STATUS_PASS, "远程 %s：%s" % (label, "；".join(msgs))


def _r_rbac():
    """角色权限 / PUBLIC 角色 / 三权分立（8.1.4.2 b / 8.1.4.2 f）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    sqls = {
        "sap_ase":   "SELECT grantee, table_name, permission FROM syspermissions WHERE grantee = 'public' AND permission = 'SELECT' AND table_name LIKE 'sys%'",
        "sqlserver":  "SELECT name FROM sys.server_principals WHERE name='public'",
        "mysql":      "SELECT * FROM mysql.tables_priv WHERE Db='mysql' AND User='' AND Table_name IN ('user','db');",
        "postgresql": "SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE grantee='public' LIMIT 5;",
    }
    sql = sqls.get(kind)
    if not sql:
        return STATUS_MANUAL, "远程 %s：请人工核查 PUBLIC 角色权限、RBAC 角色合理性与三权分立（DBA/安全/审计分离）" % label
    out, err = _remote_query(kind, sql)
    msgs = []
    if out is None:
        return STATUS_MANUAL, "远程 %s：%s；请人工核查 PUBLIC 角色默认权限与三权分立" % (label, err)
    # SAP ASE: 查 PUBLIC 在系统表上的 SELECT
    if kind in ("sap_ase",) and out.strip():
        msgs.append("SAP ASE PUBLIC 角色在系统表上有 %d 条默认 SELECT 权限（正常，但需确认无敏感表暴露）"
                    % len([l for l in out.splitlines() if l.strip()]))
    # 三权分立检查：是否只有一个超级用户
    super_sql = {
        "sap_ase":   "SELECT name FROM syslogins WHERE name NOT IN ('probe','sa') ORDER BY suid",
        "sqlserver": "SELECT name FROM sys.server_principals WHERE is_disabled=0 AND name NOT LIKE '%_admin'",
        "mysql":     "SELECT user FROM mysql.user WHERE Super_priv='Y'",
        "postgresql": "SELECT rolname FROM pg_roles WHERE rolsuper",
    }.get(kind, "")
    if super_sql:
        out2, err2 = _remote_query(kind, super_sql)
        if out2 and err2 is None:
            supers = [l.strip() for l in out2.splitlines() if l.strip() and not re.match(r"^[-=\s]+$", l)]
            # 去掉表头
            real = [s.split()[0] for s in supers if len(s.split()) >= 1 and not re.match(r"^sa$|^probe$|^root$", s.split()[0])]
            if len(real) >= 3:
                msgs.append("⚠️ 存在 %d 个超级用户角色，建议按三权分立拆分职责" % len(real))
            else:
                msgs.append("超级用户数量可控（%d 个）" % (len(real) + 1))
    return STATUS_PASS, "远程 %s：%s；建议确认 DBA/安全/审计三权分立" % (label, "；".join(msgs))


def _r_conn_limit():
    """并发连接限制 + 登录超时（8.1.4.1 b）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    sqls = {
        "mysql":      "SHOW VARIABLES LIKE 'max_connections'; SHOW VARIABLES LIKE 'wait_timeout';",
        "postgresql": "SELECT name, setting FROM pg_settings WHERE name IN ('max_connections','statement_timeout','idle_in_transaction_session_timeout');",
        "sqlserver":  "SELECT name, value_in_use FROM sys.configurations WHERE name IN ('max server connections (user connections)','remote login timeout(s)');",
        "sap_ase":    "SELECT @@max_connections AS max_conn;",
    }
    sql = sqls.get(kind)
    if not sql:
        return STATUS_MANUAL, "远程 %s：请人工核查并发连接限制与会话超时配置" % label
    out, err = _remote_query(kind, sql)
    if out is None:
        return STATUS_MANUAL, "远程 %s：%s；请人工核查 max_connections 与会话超时" % (label, err)
    msgs = [l.strip() for l in out.splitlines() if l.strip() and not re.match(r"^[-=\s]+$", l)]
    return STATUS_PASS, "远程 %s 连接/超时参数: %s" % (label, "；".join(msgs[:4]))


def _r_audit_retention():
    """审计留存 ≥6 个月 + 防篡改（8.1.4.3 b / 8.1.4.3 c）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        # SAP ASE: 审计表存在 + 行数 + 表结构（是否有保护）
        check_sql = "SELECT name FROM sysdatabases WHERE name='sybsecurity';"
        check_sql2 = "SELECT table_name FROM information_schema.tables WHERE table_name IN ('sysaudits','sysauditoptions');"
        out, _ = _remote_query(kind, check_sql)
        out2, _ = _remote_query(kind, check_sql2)
        has_sybsecurity = "sybsecurity" in (out or "").lower()
        has_audit_table = "sysaudits" in (out2 or "").lower()
        if not has_sybsecurity:
            return STATUS_FAIL, "远程 %s 未创建 sybsecurity 审计库，审计功能未启用" % label
        if not has_audit_table:
            return STATUS_WARN, "远程 %s 审计库存在但未发现 sysaudits 审计表" % label
        return STATUS_PASS, "远程 %s 已创建 sybsecurity 审计库 + sysaudits 表；请人工核查审计留存周期≥6个月与防篡改（table sp_audit 启用）" % label
    # MySQL / PG / SQL Server 统一降级提示
    return STATUS_MANUAL, "远程 %s 审计留存周期与防篡改：请人工核查审计日志保留≥6个月、audit_log 插件开启了访问+修改+删除事件、日志定期备份" % label


def _r_tls_version():
    """TLS 版本安全（防 SSLv3/TLS1.0）"""
    kind = _effective_kind()
    label = DB_PRODUCT_LABELS.get(kind, kind)
    if kind in ("sap_ase", "sap_iq", "sap_rs", "sap_sqlanywhere"):
        return STATUS_MANUAL, ("远程 %s TLS 版本：请人工核查 ASE 网络协议 SSL 配置；"
                               "SAP ASE 16.0 默认支持 TLS1.0/1.1/1.2，建议禁用 TLS1.0") % label
    sqls = {
        "mysql":      "SHOW VARIABLES LIKE 'tls_version'; SHOW VARIABLES LIKE 'ssl_cipher';",
        "postgresql": "SELECT name, setting FROM pg_settings WHERE name LIKE '%ssl%';",
    }
    sql = sqls.get(kind)
    if not sql:
        return STATUS_MANUAL, "远程 %s：请人工核查 TLS/SSL 版本是否为 TLSv1.2+" % label
    out, err = _remote_query(kind, sql)
    if out is None:
        return STATUS_MANUAL, "远程 %s：%s；请人工核查 TLS 版本" % (label, err)
    low = out.lower()
    if any(k in low for k in ("tlsv1.2", "tlsv1.3", "tls_rsa_aes256", "tlsv1.1")):
        if "tlsv1" in low and "tlsv1.2" not in low and "tlsv1.3" not in low:
            return STATUS_WARN, "远程 %s TLS 版本较低: %s" % (label, out.strip().splitlines()[0][:80])
        return STATUS_PASS, "远程 %s TLS 版本安全: %s" % (label, out.strip().splitlines()[0][:80])
    return STATUS_WARN, "远程 %s TLS 版本信息不明确: %s" % (label, out.strip().splitlines()[0][:80])


# ---------------- 本机数据库扩展检测 ----------------

def check_db_rbac():
    """本机: 数据库 PUBLIC 角色权限 + 三权分立（根据已安装的数据库类型分别检测）"""
    msgs, status = [], STATUS_PASS
    # MySQL
    rc, out = run_cmd(["mysql", "-N", "-B", "-e",
                        "SELECT user,host FROM mysql.user WHERE user='' OR user='root' AND host NOT IN ('localhost','127.0.0.1');"])
    if rc == 0 and out.strip():
        msgs.append("MySQL 匿名账户存在（user=''）或 root 允许远程: %s" % out.strip().splitlines()[:3])
        status = STATUS_WARN
    # PostgreSQL
    rc2, out2 = run_cmd(["psql", "-A", "-F", "|", "-t", "-c",
                          "SELECT rolname, rolsuper FROM pg_roles WHERE rolsuper;"])
    if rc2 == 0 and out2.strip():
        supers = [l for l in out2.splitlines() if l.strip()]
        if len(supers) > 3:
            msgs.append("⚠️ PostgreSQL 超级用户过多(%d个)，建议拆分三权" % len(supers))
            status = STATUS_WARN
    # 通用
    msgs.append("请人工核查三权分立（DBA/安全/审计角色分离）与 PUBLIC 角色默认权限")
    return status, "；".join(msgs)


def check_db_audit_retention():
    """本机: 数据库审计留存周期≥6个月"""
    msgs, status = [], STATUS_MANUAL
    # MySQL audit_log
    for conf in ("/etc/mysql/audit.cnf", "/etc/mysql/mariadb.conf.d/audit.cnf"):
        if os.path.isfile(conf):
            try:
                txt = open(conf).read()
                r = re.search(r"max_age\s*=\s*(\d+)", txt)
                if r:
                    days = int(r.group(1))
                    if days >= 180:
                        msgs.append("MySQL audit_log max_age=%d天 ✅" % days)
                        status = STATUS_PASS
                    else:
                        msgs.append("⚠️ MySQL audit_log max_age=%d天，应≥180天" % days)
                        status = STATUS_WARN
            except Exception:
                pass
            break
    # PostgreSQL pgaudit
    pgaudit = re.search(r"pgaudit", read_file("/var/lib/pgsql/data/postgresql.conf") or "")
    if pgaudit:
        msgs.append("PostgreSQL pgaudit 加载中，请人工核查 log_audit_statement_ddl = on + 日志留存")
    # 兜底
    if not msgs:
        msgs.append("未检测到审计日志留存配置，请确认审计日志/数据库审计系统留存≥6个月")
    return status, "；".join(msgs)


def check_db_weak_password_local():
    """本机: 数据库弱口令账户"""
    msgs, status = [], STATUS_MANUAL
    # MySQL: 跳过空 root 密码探测（可能误报），只查匿名账户
    rc, out = run_cmd(["mysql", "-e", "SELECT 'anonymous' FROM mysql.user WHERE user='' LIMIT 1;"],
                       timeout=5)
    if rc == 0 and "anonymous" in out:
        msgs.append("⚠️ MySQL 存在匿名账户（user=''），应立即删除")
        status = STATUS_WARN
    else:
        msgs.append("MySQL 未检测到匿名账户")
    # 通用建议
    msgs.append("请人工核查是否存在默认弱口令账户：sa=sybase / root=root / admin=admin")
    return status, "；".join(msgs)


# ---------------- 扩展检测：SQL Server / MySQL / PostgreSQL / Redis 配置 ----------------
# 约定：配置文件中取不到明确证据时返回 STATUS_MANUAL 并注明“需人工核查”，不无证据判 PASS。

def _db_inventory(platform):
    """当前目标平台的数据库清单（进程/服务/端口，均经执行器获取）"""
    return _win_db_inventory() if platform == "windows" else _linux_db_inventory()


def _db_present(platform, *keys):
    inv = _db_inventory(platform)
    return any(d["key"] in keys for d in inv.values())


def _mysql_conf_text(platform):
    return _win_mysql_conf() if platform == "windows" else _linux_mysql_conf()


def _pg_conf_text(platform):
    return _win_pg_conf() if platform == "windows" else _linux_pg_conf()


def _redis_conf_text(platform):
    if platform == "windows":
        return _ps(
            r"$d=@('C:\Program Files\Redis','C:\Redis','C:\ProgramData\Redis');"
            r"$f=@();foreach($i in $d){if(Test-Path $i){"
            r"$f+=Get-ChildItem $i -Include redis.conf,redis.windows.conf -Recurse -File "
            r"-ErrorAction SilentlyContinue | Select-Object -First 3}};"
            r"$f|Get-Content -Raw -ErrorAction SilentlyContinue")
    return _linux_redis_conf()


def _conf_lines(text):
    """去掉#注释后返回有效配置行"""
    return [l.strip() for l in (text or "").splitlines()
            if l.strip() and not l.strip().startswith("#")]


# ---- SQL Server（Windows）----

def check_sqlserver_xp_cmdshell():
    live = _live_sqlserver()
    v = (live.get("XPC") or "").strip()
    if v == "0":
        return STATUS_PASS, "库内确认 xp_cmdshell 已禁用(value_in_use=0)"
    if v == "1":
        return STATUS_FAIL, "库内确认 xp_cmdshell 启用中，攻击者可借数据库执行系统命令"
    if not _db_present("windows", "sqlserver"):
        return STATUS_MANUAL, "未检测到SQL Server，如已部署请人工核查 xp_cmdshell 状态"
    return STATUS_MANUAL, ("未配置数据库账号，无法读取 sp_configure，需人工核查："
                           "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'")


def check_sqlserver_sa_account():
    live = _live_sqlserver()
    v = (live.get("SA") or "").strip()
    if v == "0":
        return STATUS_PASS, "库内确认 sa 账户未启用（已禁用或已改名）"
    if v.isdigit() and int(v) > 0:
        return STATUS_FAIL, "库内确认 sa 账户处于启用状态，建议禁用或改名并设置强口令"
    if not _db_present("windows", "sqlserver"):
        return STATUS_MANUAL, "未检测到SQL Server，如已部署请人工核查 sa 账户状态"
    return STATUS_MANUAL, ("未配置数据库账号，需人工核查："
                           "SELECT name,is_disabled FROM sys.server_principals WHERE name='sa'")


def check_sqlserver_auth_mode():
    live = _live_sqlserver()
    v = (live.get("MIXED") or "").strip()
    if v == "1":
        return STATUS_PASS, "库内确认仅启用 Windows 身份验证（IsIntegratedSecurityOnly=1）"
    if v == "0":
        return STATUS_FAIL, "库内确认启用混合认证模式，SQL 登录账号可绕过 Windows 认证"
    ok, bad, notes = [], [], []
    for inst in _win_sql_instances():
        lm = str(inst.get("login_mode") or "").strip()
        if lm == "1":
            ok.append("%s 仅Windows认证(LoginMode=1)" % inst["name"])
        elif lm == "2":
            bad.append("%s 启用混合认证(LoginMode=2)" % inst["name"])
        else:
            notes.append("%s 认证模式未读取到" % inst["name"])
    if bad:
        return STATUS_FAIL, "；".join(bad + ok) + "；建议改为仅Windows身份验证"
    if ok:
        return STATUS_PASS, "；".join(ok + notes)
    return STATUS_MANUAL, "未读取到 SQL Server LoginMode（数据库可能未运行），需人工核查认证模式"


def check_sqlserver_remote_access():
    inv = _db_inventory("windows")
    ports = {p for d in inv.values() if d["key"] == "sqlserver"
             for p in (d["ports"] | d["conf_ports"])}
    if not ports:
        return STATUS_MANUAL, "未读取到SQL Server监听端口（实例可能已停止），需人工核查远程访问限制"
    listen = _win_listen_pid_ports()
    if not listen:
        return STATUS_MANUAL, "未能获取端口监听信息（netstat 无输出），请人工核查SQL Server远程访问"
    rows = [(a, p) for a, p, _pid in listen if p in ports]
    if not rows:
        return STATUS_MANUAL, "未发现SQL Server端口监听，需人工核查服务状态与远程访问配置"
    exposed = sorted({a for a, _p in rows if not _is_local_addr(a)})
    if not exposed:
        return STATUS_PASS, "SQL Server仅监听本地地址(%s)，远程访问受限" % \
            "、".join(sorted({p for _a, p in rows}))
    shown = "、".join("%s:%s" % ("*" if a in ("0.0.0.0", "[::]", "::") else a, p)
                     for a, p in sorted(set(rows))[:6])
    return STATUS_WARN, "SQL Server监听非本地地址(%s)，请确认防火墙已限制授权来源" % shown


# ---- MySQL / MariaDB（Windows / Linux）----

def check_mysql_local_infile(platform):
    conf = _mysql_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到MySQL/MariaDB配置文件，需人工核查 local_infile（SELECT @@local_infile）"
    m = re.search(r"^\s*local[-_]infile\s*(?:=\s*)?(\w+)?", conf, re.M | re.I)
    if not m:
        return STATUS_MANUAL, ("配置未显式设置local_infile（各版本默认值不同），"
                               "需人工核查 SELECT @@local_infile")
    val = (m.group(1) or "").strip().lower()
    if val in ("0", "off", "false", "no"):
        return STATUS_PASS, "MySQL local_infile=%s，已禁用客户端读取服务器本地文件" % val
    if val in ("1", "on", "true", "yes"):
        return STATUS_FAIL, ("MySQL local_infile=%s，攻击者可利用 LOAD DATA LOCAL INFILE "
                             "读取服务器任意文件" % val)
    return STATUS_MANUAL, "MySQL local_infile 取值无法解析，需人工核查"


def check_mysql_skip_grant(platform):
    conf = _mysql_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到MySQL/MariaDB配置文件，需人工核查是否启用skip-grant-tables"
    for l in _conf_lines(conf):
        if re.match(r"skip[-_]grant[-_]tables\b", l, re.I):
            low = l.lower()
            if "=" not in low or re.search(r"=\s*(1|on|true|yes)", low):
                return STATUS_FAIL, "MySQL配置启用skip-grant-tables，权限校验被绕过"
            return STATUS_PASS, "MySQL显式关闭skip-grant-tables"
    return STATUS_PASS, "MySQL配置中未启用skip-grant-tables（默认关闭）"


def check_mysql_bind_platform(platform):
    conf = _mysql_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到MySQL/MariaDB配置文件，需人工核查监听地址"
    if re.search(r"^\s*skip[-_]networking", conf, re.M | re.I):
        return STATUS_PASS, "MySQL已配置skip-networking，禁用网络监听"
    m = re.search(r"^\s*bind[-_]address\s*=\s*(\S+)", conf, re.M | re.I)
    if not m:
        return STATUS_WARN, "MySQL未显式配置bind-address（可能监听0.0.0.0），建议设为127.0.0.1"
    val = m.group(1).strip().strip('"\'')
    if val.startswith("127.") or val in ("localhost", "::1"):
        return STATUS_PASS, "MySQL bind-address=%s，仅本地监听" % val
    return STATUS_WARN, "MySQL bind-address=%s，对外提供服务，请确认防火墙已限制来源" % val


def check_mysql_secure_file_priv(platform):
    conf = _mysql_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到MySQL/MariaDB配置文件，需人工核查 secure_file_priv"
    m = re.search(r"^\s*secure[-_]file[-_]priv\s*=\s*(\S*)", conf, re.M | re.I)
    if not m:
        return STATUS_MANUAL, ("配置未设置secure_file_priv（MySQL 8 默认NULL），"
                               "需人工核查 SELECT @@secure_file_priv")
    val = m.group(1).strip().strip('"\'')
    if val == "":
        return STATUS_FAIL, "secure_file_priv 为空，允许任意路径的文件导入/导出"
    if val.upper() == "NULL":
        return STATUS_PASS, "secure_file_priv=NULL，禁止文件导入导出"
    return STATUS_PASS, "secure_file_priv=%s，已限制文件导入导出目录" % val


def check_mysql_general_log(platform):
    conf = _mysql_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到MySQL/MariaDB配置文件，需人工核查 general_log 是否开启"
    m = re.search(r"^\s*general[-_]log\s*=\s*(\w+)", conf, re.M | re.I)
    if not m:
        return STATUS_PASS, "配置中未开启general_log（默认关闭），不会记录全部SQL语句"
    val = m.group(1).strip().lower()
    if val in ("1", "on", "true", "yes"):
        return STATUS_WARN, ("general_log=ON，会记录全部SQL语句（含账号口令等敏感信息），"
                             "建议改用审计插件并严格保护日志文件")
    return STATUS_PASS, "general_log=%s，未记录全部SQL语句" % val


# ---- PostgreSQL（Windows / Linux）----

def check_pg_trust(platform):
    text = _pg_conf_text(platform)
    if not text.strip():
        return STATUS_MANUAL, "未找到pg_hba.conf，需人工核查是否存在trust认证"
    lines = _conf_lines(text)
    trust = [l for l in lines if re.search(r"\btrust\b", l, re.I)]
    if trust:
        return STATUS_FAIL, ("pg_hba.conf存在trust认证(%d条)，任意来源可免密登录，"
                             "应改为scram-sha-256") % len(trust)
    if re.search(r"\bscram-sha-256\b", text, re.I):
        return STATUS_PASS, "pg_hba.conf未发现trust认证，已使用scram-sha-256"
    return STATUS_WARN, "pg_hba.conf未发现trust认证，但认证方式需人工确认（建议scram-sha-256）"


def check_pg_log_connections(platform):
    text = _pg_conf_text(platform)
    if not text.strip():
        return STATUS_MANUAL, "未找到postgresql.conf，需人工核查 log_connections"
    m = re.search(r"^\s*log_connections\s*=\s*(\w+)", text, re.M | re.I)
    if not m:
        return STATUS_WARN, "未显式开启log_connections（默认off），登录审计缺失"
    val = m.group(1).strip().lower()
    if val in ("on", "true", "yes", "1"):
        extra = ""
        if re.search(r"^\s*logging_collector\s*=\s*off", text, re.M | re.I):
            extra = "；但logging_collector=off，日志未持久化到文件"
        return STATUS_PASS, "PostgreSQL已开启连接日志(log_connections=on)%s" % extra
    return STATUS_FAIL, "log_connections=%s，未记录登录/连接审计事件" % val


def check_pg_listen_addresses(platform):
    text = _pg_conf_text(platform)
    if not text.strip():
        return STATUS_MANUAL, "未找到postgresql.conf，需人工核查 listen_addresses"
    m = re.search(r"^\s*listen_addresses\s*=\s*['\"]?([^'\"\s#]+)", text, re.M | re.I)
    if not m:
        return STATUS_MANUAL, "未显式配置listen_addresses（默认localhost），需人工核查实际监听地址"
    val = m.group(1).strip()
    if val in ("*", "0.0.0.0", "::"):
        return STATUS_WARN, "PostgreSQL listen_addresses=%s，监听全部地址，请确认防火墙限制来源" % val
    if val in ("localhost", "127.0.0.1", "::1"):
        return STATUS_PASS, "PostgreSQL listen_addresses=%s，仅本地监听" % val
    return STATUS_PASS, "PostgreSQL listen_addresses=%s，限定于指定地址" % val


# ---- Redis（Windows / Linux）----

def check_redis_auth_platform(platform):
    conf = _redis_conf_text(platform)
    if not conf.strip():
        if _db_present(platform, "redis"):
            return STATUS_MANUAL, "检测到Redis运行但未找到配置文件，需人工核查 requirepass"
        return STATUS_MANUAL, "未找到redis.conf且未检测到Redis，如已部署请人工核查访问认证"
    m = re.search(r"^\s*requirepass\s+(\S+)", conf, re.M)
    if m and m.group(1).strip():
        return STATUS_PASS, "Redis已设置requirepass认证"
    return STATUS_FAIL, "Redis未设置requirepass，未授权访问风险高"


def check_redis_protected_mode(platform):
    conf = _redis_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到redis.conf，需人工核查 protected-mode"
    m = re.search(r"^\s*protected-mode\s+(\w+)", conf, re.M | re.I)
    if not m:
        return STATUS_WARN, "Redis未显式配置protected-mode（默认yes），建议显式开启"
    val = m.group(1).strip().lower()
    if val in ("yes", "true", "1"):
        return STATUS_PASS, "Redis protected-mode=yes，拒绝未认证的跨网访问"
    return STATUS_FAIL, "Redis protected-mode=%s，未设置口令时可被未授权访问" % val


def check_redis_bind_platform(platform):
    conf = _redis_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到redis.conf，需人工核查监听的bind地址"
    m = re.search(r"^\s*bind\s+(.+)", conf, re.M)
    if not m:
        return STATUS_WARN, "Redis未配置bind，默认监听全部地址"
    val = m.group(1).strip()
    if "0.0.0.0" in val or "*" in val:
        return STATUS_FAIL, "Redis bind=%s，监听全部地址" % val
    return STATUS_PASS, "Redis bind=%s" % val


def check_redis_rename_command(platform):
    conf = _redis_conf_text(platform)
    if not conf.strip():
        return STATUS_MANUAL, "未找到redis.conf，需人工核查危险命令是否重命名/禁用"
    cmds = re.findall(r"^\s*rename-command\s+(\S+)(?:\s+(\S+))?", conf, re.M | re.I)
    dangerous = {"flushall", "flushdb", "config", "keys", "eval", "shutdown", "debug"}
    renamed = {c.lower() for c, _new in cmds}
    if not cmds:
        return STATUS_WARN, ("未通过rename-command屏蔽FLUSHALL/CONFIG/KEYS等危险命令，"
                             "建议重命名或使用ACL限制")
    missing = sorted(dangerous - renamed)
    if not missing:
        return STATUS_PASS, "已重命名/禁用全部高危命令: %s" % "、".join(sorted(renamed))
    return STATUS_WARN, "已重命名%s，仍建议屏蔽: %s" % (
        "、".join(sorted(renamed)), "、".join(missing))


def _remote_checks():
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        W("DB-1", "数据库服务/类型/厂商/服务名", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "远程数据库服务可访问；正确识别类型/厂商/服务名",
          "确认数据库服务运行；isql 自动识别类型、厂商、服务名", _r_service),
        W("DB-2", "数据库端口不外暴露", CAT_DB, LEVEL_ALL, "8.1.3.1 b)",
          "数据库仅授权来源可访问",
          "通过防火墙限制来源IP，避免全网可达", _r_exposure),
        W("DB-3", "数据库版本+基线+CVE", CAT_DB, LEVEL_ALL, "8.1.4.4 b)",
          "版本受支持、高危补丁已修复、未命中离线基线CVE",
          "数据库及时升级、跟踪厂商公告", _r_version),
        W("DB-4", "数据库账户/RBAC/三权分立", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
          "删除默认/测试/匿名账户；最小权限授权；三权分立",
          "核查 syslogins/user 表，清理默认账户，拆分 DBA/安全/审计", _r_accounts),
        W("DB-5", "数据库审计日志+留存≥6月", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
          "开启数据库审计，覆盖登录/DML/DDL/DCL；审计留存≥6个月",
          "SAP ASE 创建 sybsecurity 审计库；MySQL audit_log；PG pgaudit", _r_audit_retention),
        W("DB-6", "数据库备份与恢复", CAT_DB, LEVEL_ALL, "8.1.4.9 a)",
          "定期备份并验证可恢复", "配置备份计划并定期恢复演练", _r_backup),
        # -------- 新增扩展检测 --------
        W("DB-7", "SSL/TLS 传输加密", CAT_DB, LEVEL_ALL, "8.1.2.2 a)",
          "数据库连接使用 SSL/TLS 加密传输，TLS≥v1.2",
          "SAP ASE SET SECURITY TCP_KEEPALIVE_ENCRYPTED；MySQL require_secure_transport=ON", _r_ssl),
        W("DB-8", "数据库高危功能禁用", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "禁用 xp_cmdshell/load_file/UDF 动态库等高危功能",
          "sp_dropextendedproc 'xp_cmdshell'; MySQL local_infile=OFF", _r_high_risk_func),
        W("DB-9", "弱口令/默认账户检查", CAT_DB, LEVEL_ALL, "8.1.4.1 d)",
          "不存在默认弱口令账户（sa=sybase/root=root/admin=admin）",
          "删除默认账户或设置强口令，禁用 guest/public 角色敏感权限", _r_weak_password),
        W("DB-10", "并发连接限制+会话超时", CAT_DB, LEVEL_ALL, "8.1.4.1 b)",
          "限制 max_connections；空闲会话自动超时断开",
          "MySQL wait_timeout≤600；PG idle_in_transaction_timeout；ASE cis_maint_time", _r_conn_limit),
        W("DB-11", "RBAC/PUBLIC角色/三权分立", CAT_DB, LEVEL_L3, "8.1.4.2 f)",
          "三级系统实现 RBAC 角色分离与三权分立（DBA/安全/审计职责分离）",
          "按角色最小授权，PUBLIC 角色移除敏感表默认权限", _r_rbac),
        W("DB-12", "TLS 版本安全", CAT_DB, LEVEL_ALL, "8.1.2.2 a)",
          "禁用 SSLv3/TLS1.0/TLS1.1，使用 TLS1.2+",
          "MySQL tls_version='TLSv1.2,TLSv1.3'；PG ssl_min_protocol_version=TLSv1.2", _r_tls_version),
        # 密码策略（本次新增）
        W("DB-POL", "密码策略:长度/复杂度/有效期/登录锁定", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
          "最小密码长度≥8；包含大小写+数字+特殊字符；有效期≤90天；登录失败≥5次锁定；历史密码≥5次",
          "MySQL validate_password；PG pam_pwquality+pam_faillock；SQL Server CHECK_POLICY；SAP ASE sp_configure 'password'",
          _r_password_policy),
    ]


def build_checks(platform):
    """返回数据库层检测项。
    配置了远程数据库主机（非本机 IP）时，只做能真正到达该主机的核查，
    绝不使用本机进程/服务/配置文件结果冒充远程数据库。
    """
    if _remote_host():
        return _remote_checks()
    W = lambda *a, **k: CheckItem(*a, **k)
    if platform == "windows":
        return [
            W("DB-W1", "数据库服务运行状态", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
              "数据库服务正常运行并受监控", "确保数据库服务自启并纳入监控", check_win_db_service),
            W("DB-W2", "数据库端口不外暴露", CAT_DB, LEVEL_ALL, "8.1.3.1 b)",
              "1433/3306/5432/6379等不监听对外地址",
              "绑定127.0.0.1或通过防火墙限制来源", check_win_db_exposure),
            W("DB-W3", "数据库账户最小权限", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
              "删除默认/测试账户，按最小权限授权，禁用skip-grant/trust",
              "核查登录名与角色，移除sa弱口令与高权限账户", check_win_db_accounts),
            W("DB-W4", "数据库审计日志", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
              "开启数据库审计并留存≥6个月",
              "启用SQL Server Audit或数据库审计插件", check_win_db_audit),
            W("DB-W5", "数据库备份与恢复", CAT_DB, LEVEL_ALL, "8.1.4.9 a)",
              "定期备份并验证可恢复",
              "配置备份计划任务/作业并定期恢复演练", check_win_db_backup),
            W("DB-W6", "数据库补丁与版本", CAT_DB, LEVEL_ALL, "8.1.4.4 b)",
              "数据库版本受支持且高危补丁已安装",
              "核查版本与补丁级别，及时升级", check_win_db_patch),
            # -------- 扩展检测：SQL Server / MySQL / PostgreSQL / Redis 配置 --------
            W("DB-W7", "SQL Server xp_cmdshell 禁用", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
              "xp_cmdshell 等可执行系统命令的扩展存储过程必须禁用",
              "EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
              "EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE", check_sqlserver_xp_cmdshell),
            W("DB-W8", "SQL Server sa账户禁用/改名", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
              "sa 账户已禁用或已重命名，避免默认高权限账户被爆破",
              "ALTER LOGIN sa DISABLE；或重命名 sa 并启用强口令与失败锁定", check_sqlserver_sa_account),
            W("DB-W9", "SQL Server 混合认证关闭", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
              "仅启用 Windows 身份验证（LoginMode=1），关闭SQL登录",
              "SSMS→服务器属性→安全性→仅Windows身份验证模式，重启实例", check_sqlserver_auth_mode),
            W("DB-W10", "SQL Server 远程访问限制", CAT_DB, LEVEL_ALL, "8.1.3.1 b)",
              "仅监听本地/授权网卡，或由防火墙限制1433等端口来源",
              "SQL Server配置管理器→TCP/IP→仅绑定业务网卡；防火墙限制来源IP",
              check_sqlserver_remote_access),
            W("DB-W11", "MySQL local_infile 关闭", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
              "local_infile=OFF，禁止客户端读取服务器本地文件",
              "my.ini 设置 local_infile=0 并重启MySQL", partial(check_mysql_local_infile, "windows")),
            W("DB-W12", "MySQL skip-grant-tables 禁用", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
              "禁止启用skip-grant-tables绕过权限校验",
              "my.ini 删除 skip-grant-tables 配置并重启MySQL", partial(check_mysql_skip_grant, "windows")),
            W("DB-W13", "MySQL bind-address 限制", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
              "bind-address=127.0.0.1或受控地址",
              "my.ini 设置 bind-address=127.0.0.1", partial(check_mysql_bind_platform, "windows")),
            W("DB-W14", "MySQL secure_file_priv 设置", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
              "secure_file_priv 指向专用目录或为NULL",
              "my.ini 设置 secure_file_priv='指定目录'（不设为空）",
              partial(check_mysql_secure_file_priv, "windows")),
            W("DB-W15", "MySQL general_log 敏感信息记录", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
              "不建议长期开启general_log（会记录含口令的全部SQL）",
              "关闭general_log，改用audit_log插件并保护日志文件权限",
              partial(check_mysql_general_log, "windows")),
            W("DB-W16", "PostgreSQL pg_hba trust认证", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
              "pg_hba.conf 禁止trust认证，使用scram-sha-256",
              "修改pg_hba.conf为scram-sha-256并执行pg_ctl reload",
              partial(check_pg_trust, "windows")),
            W("DB-W17", "PostgreSQL log_connections 连接审计", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
              "log_connections=on，记录登录与连接事件",
              "postgresql.conf 设置 log_connections=on 并reload", partial(check_pg_log_connections, "windows")),
            W("DB-W18", "PostgreSQL listen_addresses 限制", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
              "listen_addresses 仅本地或受控网段，不监听全部地址",
              "postgresql.conf 设置 listen_addresses='localhost' 或指定内网地址",
              partial(check_pg_listen_addresses, "windows")),
            W("DB-W19", "Redis requirepass 访问认证", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
              "设置requirepass强口令，禁止未授权访问",
              "redis.conf 配置 requirepass 并限制bind", partial(check_redis_auth_platform, "windows")),
            W("DB-W20", "Redis protected-mode 开启", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
              "protected-mode=yes",
              "redis.conf 设置 protected-mode yes", partial(check_redis_protected_mode, "windows")),
            W("DB-W21", "Redis bind 地址限制", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
              "bind仅本地或受控网段",
              "redis.conf 设置 bind 127.0.0.1", partial(check_redis_bind_platform, "windows")),
            W("DB-W22", "Redis 危险命令 rename", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
              "重命名/禁用FLUSHALL/CONFIG/KEYS/SHUTDOWN等高危命令",
              "redis.conf 使用 rename-command FLUSHALL \"\" 或启用ACL",
              partial(check_redis_rename_command, "windows")),
        ]
    return [
        W("DB-1", "数据库服务运行状态", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "数据库服务正常运行", "确保数据库服务自启并纳入监控", check_db_service),
        W("DB-2", "数据库端口不外暴露", CAT_DB, LEVEL_ALL, "8.1.3.1 b)",
          "3306/5432/6379等仅本地或受控来源访问",
          "bind 127.0.0.1 或防火墙限制来源IP", check_db_exposure),
        W("DB-3", "MySQL监听地址限制", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
          "bind-address=127.0.0.1或受控地址", "修改my.cnf bind-address=127.0.0.1", check_mysql_bind),
        W("DB-4", "MySQL口令强度策略", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
          "启用validate_password插件强制口令复杂度",
          "安装并配置validate_password，设置policy=MEDIUM", check_mysql_password_policy),
        W("DB-5", "MySQL审计日志", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
          "开启审计日志并留存≥6个月",
          "启用audit_log插件或部署数据库审计系统", check_mysql_audit),
        W("DB-6", "Redis访问认证", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
          "设置requirepass并限制bind地址", "配置requirepass强口令，bind 127.0.0.1", check_redis_auth),
        W("DB-7", "Redis监听地址", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
          "bind仅本地或受控网段", "redis.conf设置bind 127.0.0.1", check_redis_bind),
        W("DB-8", "PostgreSQL认证方式", CAT_DB, LEVEL_ALL, "8.1.4.1 a)",
          "pg_hba使用scram-sha-256，禁止trust",
          "修改pg_hba.conf为scram-sha-256并reload", check_pg_hba),
        W("DB-9", "数据库备份与恢复", CAT_DB, LEVEL_ALL, "8.1.4.9 a)",
          "重要数据定期备份并验证可恢复",
          "配置定时备份、异地存放并定期恢复演练", check_db_backup),
        W("DB-10", "数据库账户最小权限", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
          "删除匿名/测试账户，限制root远程登录",
          "清理默认账户，按业务最小授权", check_db_accounts),
        W("DB-11", "数据库补丁与版本", CAT_DB, LEVEL_ALL, "8.1.4.4 b)",
          "数据库版本受支持、高危补丁已修复",
          "核查版本与CVE修复情况，及时升级", check_db_patch),
        # -------- 扩展检测：MySQL / PostgreSQL / Redis 配置 --------
        W("DB-12", "MySQL local_infile 关闭", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "local_infile=OFF，禁止客户端读取服务器本地文件",
          "my.cnf 设置 local_infile=0 并重启MySQL", partial(check_mysql_local_infile, "linux")),
        W("DB-13", "MySQL skip-grant-tables 禁用", CAT_DB, LEVEL_ALL, "8.1.4.2 b)",
          "禁止启用skip-grant-tables绕过权限校验",
          "my.cnf 删除 skip-grant-tables 配置并重启MySQL", partial(check_mysql_skip_grant, "linux")),
        W("DB-14", "MySQL secure_file_priv 设置", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "secure_file_priv 指向专用目录或为NULL",
          "my.cnf 设置 secure_file_priv='指定目录'（不设为空）",
          partial(check_mysql_secure_file_priv, "linux")),
        W("DB-15", "MySQL general_log 敏感信息记录", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
          "不建议长期开启general_log（会记录含口令的全部SQL）",
          "关闭general_log，改用audit_log插件并保护日志文件权限",
          partial(check_mysql_general_log, "linux")),
        W("DB-16", "PostgreSQL log_connections 连接审计", CAT_DB, LEVEL_ALL, "8.1.4.3 a)",
          "log_connections=on，记录登录与连接事件",
          "postgresql.conf 设置 log_connections=on 并reload",
          partial(check_pg_log_connections, "linux")),
        W("DB-17", "PostgreSQL listen_addresses 限制", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
          "listen_addresses 仅本地或受控网段，不监听全部地址",
          "postgresql.conf 设置 listen_addresses='localhost' 或指定内网地址",
          partial(check_pg_listen_addresses, "linux")),
        W("DB-18", "Redis protected-mode 开启", CAT_DB, LEVEL_ALL, "8.1.3.2 a)",
          "protected-mode=yes",
          "redis.conf 设置 protected-mode yes", partial(check_redis_protected_mode, "linux")),
        W("DB-19", "Redis 危险命令 rename", CAT_DB, LEVEL_ALL, "8.1.4.4 a)",
          "重命名/禁用FLUSHALL/CONFIG/KEYS/SHUTDOWN等高危命令",
          "redis.conf 使用 rename-command FLUSHALL \"\" 或启用ACL",
          partial(check_redis_rename_command, "linux")),
    ]
