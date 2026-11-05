# -*- coding: utf-8 -*-
"""中间件 / Web 服务安全检测（Nginx、Apache、Tomcat、IIS）"""
import re
import shlex
from functools import partial

from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_MW, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, run_powershell, get_executor
from .db_checks import _listen
from .version_checks import detect_running_software, check_host_cves

_MW_CONF = {}


def set_mw_conf(conf):
    """设置中间件配置（名称/安装路径），由 engine 每轮注入"""
    global _MW_CONF
    _MW_CONF = dict(conf or {})


def get_mw_conf():
    return _MW_CONF


def _read(path):
    """通过当前执行器读取文件（本机或远程）"""
    rc, out = run_cmd("cat %s 2>/dev/null" % shlex.quote(path))
    return out if rc == 0 else ""


def _jenkins_home():
    rc, out = run_cmd("sh -c 'echo ${JENKINS_HOME:-/var/lib/jenkins}'")
    return (out.strip() or "/var/lib/jenkins") if rc == 0 else "/var/lib/jenkins"


def _base():
    """用户指定的中间件安装目录/配置文件路径（可为空）"""
    return (get_mw_conf().get("path") or "").strip().rstrip("/")


_BASE_EXTRA = ("/nginx.conf", "/conf/nginx.conf", "/httpd.conf", "/conf/httpd.conf",
               "/apache2.conf", "/conf/apache2.conf", "/server.xml", "/conf/server.xml",
               "/web.xml", "/conf/web.xml", "/tomcat-users.xml", "/conf/tomcat-users.xml")

_BASE_FIND = ("$(find %s -maxdepth 4 -type f \\( -name 'nginx.conf' "
              "-o -name 'httpd.conf' -o -name 'apache2.conf' -o -name '*.conf' "
              "-o -name 'server.xml' -o -name 'web.xml' -o -name 'tomcat-users.xml' \\) "
              "2>/dev/null | head -40)")


def _cat(pattern):
    """读取配置文件内容并合并返回。

    - pattern: 内置常见配置路径（可含通配符，空格分隔）
    - 用户指定安装目录时：追加目录下的常见配置文件，并递归搜索目录内的
      nginx.conf/*.conf/server.xml/web.xml/tomcat-users.xml
    - 逐个判断文件存在后读取（带 "===== 路径" 分隔头），任一文件缺失不
      影响其余内容 —— 修复此前 cat 任一文件缺失返回非零导致全部内容被
      丢弃、用户给定路径不生效的问题"""
    paths = [pattern]
    base = _base()
    if base:
        paths.append(shlex.quote(base))
        paths.extend(shlex.quote(base + f) for f in _BASE_EXTRA)
        paths.append(_BASE_FIND % shlex.quote(base))
    cmd = ("for p in %s; do if [ -f \"$p\" ]; then echo \"===== $p\"; "
           "cat \"$p\" 2>/dev/null; echo; fi; done 2>/dev/null" % " ".join(paths))
    rc, out = run_cmd(cmd, timeout=30)
    return out if rc == 0 else ""


_PROBE = {}

_NGINX_MARK = re.compile(
    r"(location\s+[~^/]|[^\w-]upstream[^\w]|server_tokens|fastcgi|proxy_pass|"
    r"worker_processes|http\s*\{)", re.I)
_APACHE_MARK = re.compile(r"(ServerRoot|<VirtualHost|LoadModule|ServerAdmin)", re.I)


def _path_hint():
    """用户指定路径的探测说明（不存在/无权限/可读但无匹配配置），结果缓存"""
    base = _base()
    if not base:
        return ""
    st = _PROBE.get(base, "?")
    if st == "?":
        qb = shlex.quote(base)
        # 目录需同时具备读(r)与执行(x)权限才能访问内部文件；文件只需读(r)。
        # 用 ls 实际探测目录可访问性，比单纯 [ -r ] 更准确。
        rc, out = run_cmd(
            "if [ ! -e %s ]; then echo missing; "
            "elif [ -d %s ]; then if ls %s >/dev/null 2>&1; then echo ok; "
            "else echo noperm; fi; "
            "else if [ -r %s ]; then echo ok; else echo noperm; fi; fi"
            % (qb, qb, qb, qb), timeout=10)
        v = (out or "").strip()
        st = v if (rc == 0 and v in ("ok", "noperm", "missing")) else "unknown"
        _PROBE[base] = st
    if st == "missing":
        return "（指定路径 %s：不存在或不可访问）" % base
    if st == "noperm":
        return "（指定路径 %s：当前登录账号无读取/访问权限，请改用 root 或配置 sudo）" % base
    if st == "ok":
        return "（指定路径 %s：路径可访问，但未匹配到该类中间件的配置文件）" % base
    return "（指定路径 %s）" % base


NGINX_CFG = ("/etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf "
             "/etc/nginx/sites-enabled/* /usr/local/nginx/conf/nginx.conf")
APACHE_CFG = ("/etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf "
              "/etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf")
TOMCAT_CFG = ("/etc/tomcat*/server.xml /etc/tomcat*/server.xml "
              "/usr/share/tomcat*/conf/server.xml /opt/tomcat/conf/server.xml "
              "/usr/local/tomcat/conf/server.xml")


# 常见高风险端口（对外暴露时需关注）
_RISKY_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
    "9000": "管理/PHP-FPM",
    "19000": "bileiwaf管理后台",
    "8080": "Tomcat/管理后台",
    "8443": "Tomcat HTTPS",
    "11211": "Memcached",
    "5984": "CouchDB",
    "2181": "ZooKeeper",
    "9090": "Prometheus",
    "15672": "RabbitMQ管理",
    "7001": "WebLogic",
    "7002": "WebLogic HTTPS",
    "9043": "WebSphere",
    "8888": "宝塔/管理面板",
}


def _listening_ports_win():
    """Windows: netstat -ano 取端口+PID，PowerShell 补进程名与路径"""
    rc, out = run_powershell(
        "$n=netstat -ano | Select-String 'LISTENING|UDP'; "
        "$p=Get-Process -ErrorAction SilentlyContinue | "
        "Select-Object Id,ProcessName,Path; "
        "$h=@{};foreach($x in $p){$h[$x.Id]=$x.ProcessName+'|'+($x.Path -replace '\\|','/')}; "
        "foreach($l in $n){-join ($l.ToString()+'|'+$h[[int](($l.ToString() -split '\\s+')[-1])])}",
        timeout=30)
    if rc != 0 or not out.strip():
        return []
    ports = []
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue
        netstat_part = parts[0]
        proc_path = parts[1] if len(parts) > 1 else ""
        proc, _, path = proc_path.partition("|")
        toks = netstat_part.split()
        if len(toks) < 4:
            continue
        proto = toks[0].lower()
        local = toks[1] if ":" in toks[1] else toks[3]
        lm = re.match(r"^(.*?):(\d+)$", local)
        if not lm:
            continue
        addr, port = lm.group(1), lm.group(2)
        key = (proto, addr, port)
        if key in seen:
            continue
        seen.add(key)
        ports.append({"proto": proto, "addr": addr, "port": port,
                      "proc": proc or "(未知)", "pid": "", "path": path or ""})
    return ports


def _listening_ports():
    """枚举所有监听端口及其对应进程，返回 [{proto,addr,port,proc,pid,path}]。
    Linux: 优先 ss -tulnp，回退 netstat -tulnp；再通过 /proc/<pid>/exe 取路径。
    Windows: netstat -ano + PowerShell 取进程名与路径。"""
    plat = getattr(get_executor(), "platform", "linux")
    if plat == "windows":
        return _listening_ports_win()
    rc, out = run_cmd(
        ["bash", "-c", "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"],
        timeout=20)
    if rc != 0 or not out.strip():
        return []
    ports = []
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Netid", "Proto", "Active")):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        # ss: Netid State Recv-Q Send-Q Local:Port Peer ... users:(("proc",pid=X,fd=Y))
        # netstat: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
        local = ""
        proc = ""
        pid = ""
        if "users:((" in line:
            m = re.search(r"users:\(\(\"([^\"]+)\",pid=(\d+)", line)
            if m:
                proc, pid = m.group(1), m.group(2)
            # 找 Local Address:Port（第4列起）
            for p in parts[3:7]:
                if ":" in p and not p.startswith("["):
                    local = p
                    break
                if p.startswith("["):
                    local = p
                    break
        else:
            # netstat 格式
            if "LISTEN" not in line.upper() and proto not in ("udp", "tcp"):
                continue
            local = parts[3] if len(parts) > 3 else ""
            ppp = parts[-1] if parts else ""
            m = re.match(r"(\d+)/(.+)", ppp)
            if m:
                pid, proc = m.group(1), m.group(2)
        if not local:
            continue
        # 解析地址:端口
        lm = re.match(r"^(.*?):(\d+)$", local)
        if not lm:
            continue
        addr, port = lm.group(1), lm.group(2)
        key = (proto, addr, port)
        if key in seen:
            continue
        seen.add(key)
        ports.append({"proto": proto, "addr": addr, "port": port,
                      "proc": proc, "pid": pid, "path": ""})
    # 通过 /proc/<pid>/exe 取可执行文件真实路径（仅 root 可读其他进程）
    for p in ports:
        if p["pid"]:
            rc2, exe = run_cmd(
                ["bash", "-c", "readlink /proc/%s/exe 2>/dev/null" % p["pid"]],
                timeout=5)
            if rc2 == 0 and exe.strip():
                p["path"] = exe.strip()
    return ports


def _running():
    """枚举常见中间件/应用进程（含路径），返回原始 ps 输出。
    排除执行 pgrep 的 bash 进程自身（其命令行含所有关键字导致假阳性）。"""
    rc, out = run_cmd(["bash", "-c",
        "pgrep -a -f 'nginx|httpd|apache2|tomcat|catalina|bileiwaf|bilei-waf|"
        "jenkins|gunicorn|uwsgi|redis-server|memcached' 2>/dev/null "
        "| grep -vE 'pgrep|grep'"], timeout=15)
    return out.strip()


def check_mw_service():
    text = _running()
    name = (get_mw_conf().get("name") or "").strip()
    if not text:
        if name:
            return STATUS_MANUAL, "未检测到运行中的%s，请人工核查其部署位置与运行状态" % name
        return STATUS_MANUAL, "未检测到运行中的Web中间件（如已独立部署请单独核查）"
    kinds = []
    low = text.lower()
    for k, n in (("bileiwaf", "BileiWAF(壁垒WAF)"), ("bilei-waf", "BileiWAF(壁垒WAF)"),
                 ("nginx", "Nginx"), ("httpd", "Apache"), ("apache2", "Apache"),
                 ("tomcat", "Tomcat"), ("catalina", "Tomcat"),
                 ("jenkins", "Jenkins"), ("node", "Node.js"),
                 ("gunicorn", "Gunicorn"), ("uwsgi", "uWSGI"),
                 ("redis-server", "Redis"), ("memcached", "Memcached")):
        if k in low and n not in kinds:
            kinds.append(n)
    msg = "检测到运行中的中间件: %s" % ("、".join(kinds) or "未知")
    if name:
        msg += "（指定核查：%s）" % name
    return STATUS_PASS, msg


def check_open_ports():
    """开放端口与对应应用检测：列出所有监听端口，标注高风险端口对外暴露情况"""
    ports = _listening_ports()
    if not ports:
        return STATUS_MANUAL, "无法获取监听端口列表（ss/netstat 不可用或权限不足）"
    # 区分对外暴露 vs 仅本地
    public = []
    local_only = []
    for p in ports:
        addr = p["addr"]
        is_local = addr in ("127.0.0.1", "::1", "[::1]") or addr.startswith("127.")
        # UDP 也列入但不强制风险
        if p["proto"] == "tcp" and not is_local:
            public.append(p)
        else:
            local_only.append(p)
    # 识别高风险端口
    risky_public = [p for p in public if p["port"] in _RISKY_PORTS]
    lines = []
    for p in sorted(public + local_only, key=lambda x: int(x["port"])):
        addr = p["addr"] if p["addr"] else "*"
        proc = p["proc"] or "(未知进程)"
        path = p["path"] or ""
        tag = ""
        is_local = p["addr"] in ("127.0.0.1", "::1", "[::1]") or p["addr"].startswith("127.")
        if p["proto"] == "tcp" and not is_local and p["port"] in _RISKY_PORTS:
            tag = " ⚠️%s对外" % _RISKY_PORTS[p["port"]]
        elif is_local:
            tag = "（仅本地）"
        path_str = (" → %s" % path) if path else ""
        lines.append("%s/%s %s:%s [%s]%s%s" % (
            p["proto"].upper(), p["port"], addr, p["port"], proc, tag, path_str))
    summary = "共 %d 个监听端口（TCP对外 %d，本地 %d，UDP %d）" % (
        len(ports), len(public),
        len([p for p in local_only if p["proto"] == "tcp"]),
        len([p for p in ports if p["proto"] == "udp"]))
    if risky_public:
        names = "、".join("%s(%s)" % (_RISKY_PORTS[p["port"]], p["port"]) for p in risky_public)
        return STATUS_WARN, summary + "；⚠️ 以下高风险端口对外暴露：%s\n" % names + "\n".join(lines)
    return STATUS_PASS, summary + "\n" + "\n".join(lines)


def check_mw_versions():
    """MW-VER：运行中中间件/应用软件版本 + CVE 漏洞匹配。
    同时列出所有未知软件（进程名+路径），确保报告不会漏掉。"""
    items = detect_running_software()
    if not items:
        return STATUS_MANUAL, "未能枚举到运行中的软件（权限不足或 ss/ps 受限）"
    msgs = []
    any_cve = False
    any_unknown = False
    any_nover = False
    for it in sorted(items, key=lambda x: (not x["is_known"], x["name"].lower())):
        line = "- %s" % it["name"]
        if it.get("proc") and it["proc"] != it["name"]:
            line += " (进程: %s)" % it["proc"]
        if it.get("path"):
            line += " → %s" % it["path"]
        if it["is_known"]:
            if it["version"]:
                line += "，版本=%s" % it["version"]
            else:
                line += "，版本=<未探测到>"
                any_nover = True
        else:
            any_unknown = True
            line += "，版本=<未探测到>（未识别的软件）"
        if it["cves"]:
            any_cve = True
            cve_str = "、".join(
                "%s %s" % (",".join(e.get("cve", [])), e.get("desc", ""))
                for e in it["cves"])
            line += " ⚠️ %s" % cve_str
        msgs.append(line)
    if any_cve:
        status = STATUS_FAIL
        pre = "⚠️ 以下运行中的软件存在已公开 CVE 漏洞（请优先升级到修复版本）：\n"
    else:
        status = STATUS_PASS
        pre = "✅ 所有已识别软件版本未命中内置 CVE 漏洞库：\n"
    post = ""
    if any_unknown:
        post += "\nℹ️ 以上包含 %d 个未识别的软件（进程名不在漏洞库映射内），请人工确认其名称/版本并评估漏洞风险。" % sum(1 for i in items if not i["is_known"])
    if any_nover:
        post += "\nℹ️ 部分软件未能探测到版本号（可能需要 root/管理员权限或版本探测命令路径不同）。"
    return status, pre + "\n".join(msgs) + post


def check_host_versions():
    """MW-PKG（宿主关键软件 CVE）：内核、glibc、OpenSSL、OpenSSH 版本匹配。"""
    plat = getattr(get_executor(), "platform", "linux")
    if plat == "windows":
        return STATUS_PASS, "Windows 平台：宿主关键软件 CVE 请结合系统补丁号另行核查"
    items = check_host_cves()
    if not items:
        return STATUS_MANUAL, "未能获取宿主关键软件版本（权限不足或命令不可用）"
    msgs = []
    any_cve = False
    any_nover = False
    for it in items:
        line = "- %s" % it["name"]
        if it["version"]:
            line += "=%s" % it["version"]
        else:
            line += "=<未探测到>"
            any_nover = True
        if it["cves"]:
            any_cve = True
            cve_str = "、".join(
                "%s %s" % (",".join(e.get("cve", [])), e.get("desc", ""))
                for e in it["cves"])
            line += " ⚠️ %s" % cve_str
        msgs.append(line)
    if any_cve:
        return STATUS_FAIL, "⚠️ 宿主关键软件存在已公开 CVE（请优先升级/打补丁）：\n" + "\n".join(msgs)
    post = ""
    if any_nover:
        post = "\nℹ️ 部分组件版本未探测到，请人工核查补丁状态。"
    return STATUS_PASS, "✅ 宿主关键软件版本未命中内置 CVE 漏洞库：\n" + "\n".join(msgs) + post


def check_nginx_tokens():
    content = _cat(NGINX_CFG)
    if "nginx" not in content.lower() and not _NGINX_MARK.search(content):
        return STATUS_MANUAL, "未找到Nginx配置" + _path_hint()
    if re.search(r"server_tokens\s+off", content, re.I):
        return STATUS_PASS, "Nginx server_tokens=off，已隐藏版本信息"
    return STATUS_FAIL, "Nginx未关闭server_tokens，响应头会泄露版本信息"


def check_nginx_autoindex():
    content = _cat(NGINX_CFG)
    if "nginx" not in content.lower() and not _NGINX_MARK.search(content):
        return STATUS_MANUAL, "未找到Nginx配置" + _path_hint()
    if re.search(r"autoindex\s+on", content, re.I):
        return STATUS_FAIL, "Nginx存在autoindex on，目录可被遍历"
    return STATUS_PASS, "Nginx未开启目录遍历(autoindex off/未配置)"


def check_nginx_tls():
    content = _cat(NGINX_CFG)
    if "nginx" not in content.lower() and not _NGINX_MARK.search(content):
        return STATUS_MANUAL, "未找到Nginx配置" + _path_hint()
    m = re.search(r"ssl_protocols\s+([^;]+)", content, re.I)
    if not m:
        return STATUS_WARN, "未显式配置ssl_protocols，可能仍启用TLSv1.0/1.1"
    protocols = m.group(1)
    if "TLSv1" in protocols and "TLSv1.2" not in protocols:
        return STATUS_FAIL, "ssl_protocols=%s，仅支持旧版TLS" % protocols.strip()
    if "SSLv3" in protocols or "TLSv1.1" in protocols:
        return STATUS_WARN, "ssl_protocols含有过时协议: %s" % protocols.strip()
    return STATUS_PASS, "Nginx ssl_protocols=%s" % protocols.strip()


def check_nginx_log():
    content = _cat(NGINX_CFG)
    if "nginx" not in content.lower() and not _NGINX_MARK.search(content):
        return STATUS_MANUAL, "未找到Nginx配置" + _path_hint()
    if re.search(r"access_log\s+off", content, re.I):
        return STATUS_FAIL, "Nginx已关闭access_log，缺少访问审计"
    if re.search(r"access_log\s+", content, re.I):
        return STATUS_PASS, "Nginx已开启访问日志"
    return STATUS_WARN, "未显式配置access_log（默认开启），建议显式配置并集中留存"


def check_apache_tokens():
    content = _cat(APACHE_CFG)
    if "apache" not in content.lower() and "httpd" not in content.lower() \
            and not _APACHE_MARK.search(content):
        return STATUS_MANUAL, "未找到Apache配置" + _path_hint()
    if re.search(r"ServerTokens\s+Prod", content, re.I) and \
       re.search(r"ServerSignature\s+Off", content, re.I):
        return STATUS_PASS, "Apache已隐藏版本与签名信息"
    return STATUS_WARN, "Apache未同时配置ServerTokens Prod与ServerSignature Off"


def check_apache_autoindex():
    content = _cat(APACHE_CFG)
    if "apache" not in content.lower() and "httpd" not in content.lower() \
            and not _APACHE_MARK.search(content):
        return STATUS_MANUAL, "未找到Apache配置" + _path_hint()
    if re.search(r"Options.*Indexes", content, re.I) and \
       not re.search(r"Options.*-Indexes", content, re.I):
        return STATUS_FAIL, "Apache启用了Indexes，目录可被遍历"
    return STATUS_PASS, "Apache未开启目录遍历(Indexes)"


def check_tomcat_version():
    content = _cat(TOMCAT_CFG)
    if "tomcat" not in content.lower() and "<Connector" not in content:
        return STATUS_MANUAL, "未找到Tomcat配置" + _path_hint()
    hidden = re.search(r"showServerInfo\s*=\s*\"false\"", content, re.I) or \
             re.search(r"ErrorReportValve[^>]*showReport\s*=\s*\"false\"", content, re.I)
    if hidden:
        return STATUS_PASS, "Tomcat已隐藏版本/错误详细信息"
    return STATUS_WARN, "Tomcat未关闭版本与错误信息展示(ErrorReportValve)"


def check_tomcat_ajp():
    content = _cat(TOMCAT_CFG)
    hit = [h for h in _listen() if h[1] == "8009"]
    if hit:
        exposed = [x for x in hit if not x[0].startswith("127.")]
        if exposed:
            return STATUS_FAIL, "Tomcat AJP 8009端口对外监听，存在Ghostcat类风险"
    if re.search(r"<Connector[^>]*protocol\s*=\s*\"AJP", content, re.I) and re.search(
            r"secretRequired\s*=\s*\"false\"", content, re.I):
        return STATUS_WARN, "Tomcat启用AJP且未要求secret，建议关闭或配置secret"
    return STATUS_PASS, "未发现AJP 8009对外暴露"


def check_tls_cert():
    ports = [p for h, p in _listen() if p in ("443", "8443")]
    if not ports:
        return STATUS_MANUAL, "未检测到443/8443监听端口，如使用其他端口请人工核查证书有效期"
    port = "443" if "443" in ports else ports[0]
    cmd = ("echo | openssl s_client -connect 127.0.0.1:%s -servername localhost 2>/dev/null "
           "| openssl x509 -noout -enddate -checkend 2592000 2>/dev/null" % port)
    rc, out = run_cmd(cmd, timeout=20)
    if rc != 0 or "notAfter" not in out:
        return STATUS_MANUAL, "无法通过openssl读取证书（可能未安装openssl）"
    expiry = re.search(r"notAfter=([^\n]+)", out)
    expired_soon = "will expire" in out
    if expired_soon:
        return STATUS_WARN, "HTTPS证书将在30天内过期：%s" % (expiry.group(1) if expiry else "")
    return STATUS_PASS, "HTTPS证书有效且30天内不失效：%s" % (expiry.group(1) if expiry else "")


def check_mw_admin_access():
    return STATUS_MANUAL, "请人工核查中间件管理后台(如Tomcat manager、Nginx状态页)是否限制访问源并设置强口令"


# ---------------- 扩展：Tomcat / IIS / Nginx / Apache 配置核查 ----------------

TOMCAT_WEB_XML = ("/etc/tomcat*/web.xml /usr/share/tomcat*/conf/web.xml "
                  "/opt/tomcat/conf/web.xml /usr/local/tomcat/conf/web.xml")
TOMCAT_USERS = ("/etc/tomcat*/tomcat-users.xml /usr/share/tomcat*/conf/tomcat-users.xml "
                "/opt/tomcat/conf/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml")


def _win_tomcat_conf():
    """读取 Windows 上 Tomcat 的 server.xml/web.xml/tomcat-users.xml（含用户指定目录）"""
    base = _base().replace("/", "\\").replace("'", "''")
    dirs = (r"@('C:\Program Files\Apache Software Foundation','C:\Program Files\Tomcat',"
            r"'C:\Program Files (x86)\Apache Software Foundation','C:\Tomcat','D:\Tomcat'"
            + ((",@('%s')" % base) if base else "") + ")")
    return run_powershell(
        r"$d=" + dirs + r";"
        r"$f=@();foreach($i in $d){if(Test-Path $i){"
        r"$f+=Get-ChildItem $i -Include server.xml,web.xml,tomcat-users.xml -Recurse -File "
        r"-ErrorAction SilentlyContinue | Select-Object -First 8}};"
        r"foreach($x in $f){'===== ' + $x.FullName; "
        r"Get-Content $x.FullName -Raw -ErrorAction SilentlyContinue}")[1]


def _tomcat_text(platform):
    if platform == "windows":
        return _win_tomcat_conf()
    return _cat(TOMCAT_CFG) + _cat(TOMCAT_WEB_XML) + _cat(TOMCAT_USERS)


def _strip_xml_comments(text):
    return re.sub(r"<!--.*?-->", "", text or "", flags=re.S)


def _iis_installed():
    """W3SVC 服务存在视为安装了 IIS"""
    out = run_powershell(
        "$s=Get-Service W3SVC -ErrorAction SilentlyContinue;if($s){'YES'}else{'NO'}")[1]
    return "YES" in out


def _iis_missing_msg(what):
    if _iis_installed():
        return "检测到IIS但无法读取%s配置（需管理员权限/WebAdministration模块），需人工核查" % what
    return "未检测到IIS（W3SVC服务不存在），如未部署IIS可忽略；%s需人工核查" % what


def _tomcat_installed(platform):
    """Tomcat 服务或进程是否存在"""
    if platform == "windows":
        out = run_powershell(
            "$s=Get-Service -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Name -match 'tomcat'} | "
            "Select-Object -First 1 -ExpandProperty Name")[1]
        return bool(out.strip())
    rc, out = run_cmd(["bash", "-c",
                       "pgrep -f 'catalina|org.apache.catalina' 2>/dev/null | head -1"], timeout=15)
    return rc == 0 and bool((out or "").strip())


def _tomcat_missing_msg(platform, what):
    if _tomcat_installed(platform):
        return "检测到Tomcat运行但未找到配置文件，需人工核查%s" % (what + _path_hint())
    return "未检测到Tomcat服务/进程，如未部署Tomcat可忽略；%s需人工核查" % what


def check_iis_webdav():
    rc, out = run_powershell(
        "try{$m=(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "
        "'system.webServer/globalModules' -ErrorAction Stop).Collection;"
        "$n=@($m|ForEach-Object{$_.name}) -join ',';"
        "try{$h=(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "
        "'system.webServer/handlers' -ErrorAction Stop).Collection;"
        "$hn=@($h|ForEach-Object{$_.name}) -join ','}catch{$hn=''};"
        "'MOD:'+$n+';H:'+$hn}catch{'ERR'}")
    if "ERR" in out or not out.strip():
        return STATUS_MANUAL, _iis_missing_msg("WebDAV模块")
    if re.search(r"WebDAV", out, re.I):
        return STATUS_FAIL, "IIS已加载WebDAV模块/处理程序，建议卸载并删除WebDAV创作规则"
    return STATUS_PASS, "IIS未加载WebDAV模块，未启用WebDAV发布"


def check_iis_http_methods():
    rc, out = run_powershell(
        "try{$v=(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "
        "'system.webServer/security/requestFiltering' -Name verbs -ErrorAction Stop).Collection;"
        "if($v){($v|ForEach-Object{$_.verb+'='+$_.allowed}) -join ','}else{'EMPTY'}}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, _iis_missing_msg("HTTP方法限制")
    text = out.strip()
    if text == "EMPTY" or not text:
        return STATUS_WARN, "IIS未显式限制HTTP方法，建议拒绝PUT/DELETE/TRACE"
    pairs = {}
    for part in text.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs[k.strip().lower()] = v.strip().lower()
    denied = {k for k, v in pairs.items() if v in ("false", "deny")}
    trace_on = pairs.get("trace") in ("true", "allow")
    if "*" in denied or "trace" in denied:
        return STATUS_PASS, "IIS已限制HTTP方法: %s" % text
    if trace_on:
        return STATUS_FAIL, "IIS显式允许TRACE方法，可被用于跨站追踪，应拒绝"
    return STATUS_WARN, "IIS请求方法限制不完整: %s，建议拒绝PUT/DELETE/TRACE" % text


def check_iis_request_filtering():
    rc, out = run_powershell(
        "try{$s=Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "
        "'system.webServer/security/requestFiltering' -ErrorAction Stop;"
        "if($s.PSObject.Properties.Name -contains 'enabled'){'E:'+$s.enabled}else{'SEC:OK'}}catch{'ERR'}")
    if "ERR" in out or not out.strip():
        return STATUS_MANUAL, _iis_missing_msg("请求筛选")
    m = re.search(r"E:(True|False)", out, re.I)
    if m:
        if m.group(1).lower() == "false":
            return STATUS_FAIL, "IIS请求筛选(requestFiltering)已禁用，无法拦截异常请求"
        return STATUS_PASS, "IIS请求筛选(requestFiltering)已启用"
    return STATUS_PASS, "IIS存在requestFiltering配置节（默认启用请求筛选）"


def check_iis_apppool_identity():
    rc, out = run_powershell(
        "& $env:windir\\System32\\inetsrv\\appcmd.exe list apppool "
        "/text:processModel.identityType 2>&1")
    ids = sorted({l.strip() for l in (out or "").splitlines() if l.strip()})
    if rc != 0 or not ids or re.search(r"ERROR|错误", " ".join(ids), re.I):
        return STATUS_MANUAL, _iis_missing_msg("应用程序池标识")
    low = {i.lower() for i in ids}
    if "localsystem" in low:
        return STATUS_FAIL, "存在应用程序池以LocalSystem运行，权限过高，应改为ApplicationPoolIdentity"
    known = {"applicationpoolidentity", "localservice", "networkservice", "localsystem"}
    custom = [i for i in ids if i.lower() not in known]
    if custom:
        return STATUS_WARN, "应用程序池使用自定义账户: %s，请核查其最小权限与口令强度" % "、".join(custom)
    return STATUS_PASS, "应用程序池标识为最小权限账户: %s" % "、".join(ids)


def check_tomcat_shutdown(platform):
    text = _strip_xml_comments(_tomcat_text(platform))
    if not text.strip():
        return STATUS_MANUAL, _tomcat_missing_msg(platform, "shutdown端口")
    m = re.search(r"<Server\b[^>]*\bport\s*=\s*[\"'](-?\d+)[\"']", text, re.I)
    if not m:
        return STATUS_MANUAL, "未解析到Server端口配置，需人工核查shutdown端口"
    port = m.group(1)
    if port == "-1":
        return STATUS_PASS, "Tomcat shutdown端口已禁用(port=-1)"
    return STATUS_FAIL, "Tomcat shutdown端口=%s开启，可被本地请求关闭（建议port=-1）" % port


def check_tomcat_ajp_connector(platform):
    text = _strip_xml_comments(_tomcat_text(platform))
    if not text.strip():
        return STATUS_MANUAL, _tomcat_missing_msg(platform, "AJP连接器")
    ajp = re.findall(r"<Connector\b[^>]*AJP[^>]*>", text, re.I)
    if not ajp:
        return STATUS_PASS, "server.xml未配置AJP连接器"
    with_secret = [c for c in ajp if re.search(r"secret(Required)?\s*=\s*[\"'][^\"']+[\"']", c, re.I)]
    if len(with_secret) == len(ajp):
        return STATUS_WARN, "Tomcat启用AJP但已配置secret，建议关闭AJP仅保留HTTP"
    return STATUS_FAIL, "Tomcat启用AJP且未配置secret（Ghostcat风险），建议删除AJP Connector"


def check_tomcat_manager(platform):
    text = _strip_xml_comments(_tomcat_text(platform))
    if not text.strip():
        return STATUS_MANUAL, _tomcat_missing_msg(platform, "manager/host-manager后台")
    granted = set()
    for rs in re.findall(r"<user\b[^>]*\broles\s*=\s*[\"']([^\"']+)[\"']", text, re.I):
        for r in rs.split(","):
            r = r.strip()
            if "manager" in r.lower() or "admin" in r.lower():
                granted.add(r)
    if granted:
        return STATUS_FAIL, "tomcat-users.xml存在manager/admin角色授权: %s，应删除或严格限制" % \
            "、".join(sorted(granted))
    if re.search(r"<tomcat-users\b", text, re.I):
        return STATUS_PASS, "tomcat-users.xml未授予manager/host-manager角色"
    return STATUS_MANUAL, "未读取到tomcat-users.xml，需人工核查manager/host-manager后台"


def check_tomcat_https_constraint(platform):
    text = _strip_xml_comments(_tomcat_text(platform))
    if not text.strip():
        return STATUS_MANUAL, _tomcat_missing_msg(platform, "是否强制HTTPS")
    if re.search(r"<security-constraint\b", text, re.I) and \
       re.search(r"<transport-guarantee>\s*CONFIDENTIAL\s*</transport-guarantee>", text, re.I):
        return STATUS_PASS, "已配置security-constraint强制HTTPS(CONFIDENTIAL)"
    if re.search(r"<security-constraint\b", text, re.I):
        return STATUS_WARN, "存在security-constraint但未设置CONFIDENTIAL，未强制HTTPS"
    return STATUS_WARN, "未配置security-constraint强制HTTPS，HTTP与HTTPS可并存"


def check_nginx_methods():
    content = _cat(NGINX_CFG)
    if "nginx" not in content.lower() and not _NGINX_MARK.search(content):
        return STATUS_MANUAL, "未找到Nginx配置" + _path_hint()
    if re.search(r"\$request_method", content, re.I) or re.search(r"limit_except\b", content, re.I):
        return STATUS_PASS, "Nginx已配置HTTP请求方法限制(limit_except/$request_method)"
    return STATUS_WARN, "Nginx未限制HTTP方法，建议仅允许GET/HEAD/POST并拒绝PUT/DELETE/TRACE"


def check_apache_methods():
    content = _cat(APACHE_CFG)
    if "apache" not in content.lower() and "httpd" not in content.lower() \
            and not _APACHE_MARK.search(content):
        return STATUS_MANUAL, "未找到Apache配置" + _path_hint()
    trace_off = re.search(r"^\s*TraceEnable\s+Off", content, re.I | re.M)
    trace_on = re.search(r"^\s*TraceEnable\s+On", content, re.I | re.M)
    limited = re.search(r"<LimitExcept\b", content, re.I) or re.search(r"<Limit\b", content, re.I)
    if trace_off and limited:
        return STATUS_PASS, "Apache已关闭TRACE并通过Limit/LimitExcept限制HTTP方法"
    if trace_on:
        return STATUS_FAIL, "Apache TraceEnable=On，TRACE方法可被用于跨站追踪，应设为Off"
    if trace_off:
        return STATUS_WARN, "Apache已关闭TRACE，但未通过LimitExcept限制PUT/DELETE等方法"
    return STATUS_WARN, "Apache未关闭TRACE且未限制HTTP方法，建议TraceEnable Off + LimitExcept"


# ---------------- Windows (IIS) ----------------

def check_iis_service():
    rc, out = run_powershell(
        "$s=Get-Service W3SVC -ErrorAction SilentlyContinue;"
        "if($s){$s.Status}else{'NONE'}")
    if "Running" in out:
        return STATUS_PASS, "IIS(W3SVC)运行中"
    return STATUS_MANUAL, "未检测到运行的IIS（如使用Other Web服务请人工核查）"


def check_iis_dirbrowse():
    rc, out = run_powershell(
        "try{$v=(Get-WebConfiguration -PSPath 'IIS:\\' -Filter "
        "'system.webServer/directoryBrowse' -ErrorAction Stop).enabled;$v}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取IIS目录浏览配置"
    if out.strip().lower() == "false":
        return STATUS_PASS, "IIS目录浏览已禁用"
    return STATUS_FAIL, "IIS启用了目录浏览，目录可被遍历"


def check_iis_errors():
    rc, out = run_powershell(
        "try{$v=(Get-WebConfiguration -PSPath 'IIS:\\' -Filter "
        "'system.webServer/httpErrors' -ErrorAction Stop).errorMode;$v}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取IIS错误页配置"
    if "Detailed" in out:
        return STATUS_WARN, "IIS错误页为Detailed，会泄露堆栈与服务器信息"
    return STATUS_PASS, "IIS错误页模式: %s" % out.strip()


# ---------------------------------------------------------------------------
# depends: 前置条件函数，返回 False 表示当前目标不适用该检测项
# ---------------------------------------------------------------------------

def _proc_running(*patterns):
    """pgrep -f 任一个 pattern 命中即视为运行中。
    排除 pgrep 自身、grep 自身、python/ssh wrapper 等，避免假阳性。"""
    try:
        plat = getattr(get_executor(), "platform", "linux")
        if plat == "windows":
            return False
        for p in patterns:
            rc, out = run_cmd(["bash", "-c",
                "pgrep -af %s 2>/dev/null | grep -vE 'pgrep|grep' | head -1"
                % shlex.quote(p)], timeout=10)
            if rc == 0 and out.strip():
                return True
        return False
    except Exception:
        return False


def _file_exists_any(*paths):
    try:
        plat = getattr(get_executor(), "platform", "linux")
        for p in paths:
            if plat == "windows":
                continue
            # 用 compgen -G 正确处理通配符路径（不匹配时返回空，不报错）
            rc, out = run_cmd(["bash", "-c",
                "f=$(compgen -G %s | head -1); [ -n \"$f\" ] && echo 1"
                % shlex.quote(p)], timeout=5)
            if rc == 0 and out.strip():
                return True
        return False
    except Exception:
        return False


def _depends_nginx():
    return _proc_running("nginx") or _file_exists_any(
        "/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf")


def _depends_apache():
    return _proc_running("httpd", "apache2") or _file_exists_any(
        "/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf")


def _depends_tomcat():
    return _proc_running("catalina", "tomcat") or _file_exists_any(
        "/etc/tomcat*/server.xml", "/usr/share/tomcat*/conf/server.xml",
        "/opt/tomcat/conf/server.xml", "/usr/local/tomcat/conf/server.xml")


def _depends_jenkins():
    return _proc_running("jenkins") or _file_exists_any(
        "/etc/jenkins/config.xml", "/var/lib/jenkins/config.xml")


def _depends_iis():
    try:
        plat = getattr(get_executor(), "platform", "linux")
        if plat != "windows":
            return False
        rc, out = run_powershell(
            "Get-Service W3SVC -ErrorAction SilentlyContinue | Select -ExpandProperty Status",
            timeout=10)
        return rc == 0 and "running" in (out or "").lower()
    except Exception:
        return False


def _depends_iis_worker():
    return _depends_iis()


def _depends_tomcat_win():
    return _proc_running("catalina", "tomcat", "bootstrap")


def _depends_jenkins_win():
    return _proc_running("jenkins")


# ---------------------------------------------------------------------------
# WAF/IPS 通用检测（不特定厂商）
# ---------------------------------------------------------------------------

def check_waf_status():
    """WAF/IPS 运行检测：识别 nginx-waf / modsecurity / openresty / bileiwaf / f5 / netscaler 等。
    未运行任何 WAF 时返回 WARN（等保 8.1.4.4 要求 Web 应用层防护）。"""
    waf_procs = ("bileiwaf", "bilei-waf", "modsecurity", "openresty",
                 "nginx-waf", "asm", "wafnode", "stringray", "appshield")
    hits = []
    for name in waf_procs:
        if _proc_running(name):
            hits.append(name)
    # nginx + modsecurity 组合
    if "nginx" in _running().lower() and _file_exists_any(
            "/etc/nginx/modsec.conf", "/etc/nginx/conf.d/modsec*.conf",
            "/etc/modsecurity/", "/etc/nginx/modules/ngx_http_modsecurity_module.so"):
        hits.append("nginx+modsecurity")
    if hits:
        return STATUS_PASS, "检测到 WAF/IPS 组件运行: %s（需进一步核查防护规则配置）" % "、".join(hits)
    return STATUS_WARN, "未检测到 Web 应用防火墙(WAF)/IPS 组件运行（等保三级要求 8.1.4.4 应用层防护；若已部署但进程名不匹配，请在资产登记中注明）"


def build_checks(platform):
    W = lambda *a, **k: CheckItem(*a, **k)
    if platform == "windows":
        return [
            W("MW-W1", "Web服务运行状态", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "Web中间件正常运行并受监控", "确保IIS/中间件自启并纳入监控", check_iis_service),
            W("MW-W17", "开放端口与对应应用", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "列出所有监听端口及其进程，高风险端口不得对外暴露",
              "关闭不必要端口，管理/数据库端口限制访问源", check_open_ports),
            W("MW-WVER", "中间件/应用软件版本与已知CVE", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "运行中的中间件不得命中已公开高危CVE；所有软件名称+版本应在报告中体现",
              "定期升级中间件到修复版本；漏洞库同步更新", check_mw_versions),
            W("MW-WPKG", "宿主关键软件版本与已知CVE", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "Windows关键中间件不得命中已公开高危CVE",
              "Windows Update定期打补丁", check_host_versions),
            W("MW-WAF", "Web应用防火墙(WAF/IPS)", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "部署 Web 应用防火墙或主机防护组件",
              "按等保三级要求部署 WAF，拦截 SQLi/XSS/命令注入等攻击", check_waf_status),
            W("MW-W2", "IIS目录浏览禁用", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
              "禁止目录浏览", "IIS管理器→目录浏览→禁用", check_iis_dirbrowse,
              depends=_depends_iis_worker),
            W("MW-W3", "错误信息不泄露", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "错误页为Custom，避免泄露堆栈与版本",
              "配置httpErrors errorMode=Custom", check_iis_errors,
              depends=_depends_iis_worker),
            W("MW-W4", "HTTPS证书有效期", CAT_MW, LEVEL_ALL, "8.1.2.2 a)",
              "证书有效且未临近过期", "检查证书链与有效期，及时续期", check_tls_cert),
            W("MW-W5", "Web管理后台访问控制", CAT_MW, LEVEL_ALL, "8.1.4.2 b)",
              "管理后台限制访问源并强口令", "限制管理入口IP并启用MFA", None),
            # ========== 密码策略（本次新增）==========
            W("MW-WP1", "中间件默认账户/弱口令", CAT_MW, LEVEL_ALL, "8.1.4.1 a)",
              "删除或禁用中间件默认账户（IIS/IUSRS/DefaultAppPool/ASP.NET）；Jenkins首次启动密码已改",
              "Tomcat: 删除 tomcat 默认用户或改强口令；IIS: 确认 IUSR/IIS_IUSRS 口令强；Jenkins: 改默认密码",
              check_mw_default_accounts_win),
            W("MW-WP2", "IIS 本地账户/应用池密码策略", CAT_MW, LEVEL_ALL, "8.1.4.1 a)",
              "IIS 应用池/IUSR 账户使用强口令，禁止空/弱口令",
              "IIS Manager → Application Pools → 设置 Identity 为域账户或强口令本地账户",
              check_iis_apppool_pwd),
            # ========== 扩展：IIS / Tomcat 配置核查 ==========
            W("MW-W6", "IIS WebDAV 禁用", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "卸载/禁用WebDAV模块与处理程序，避免PUT文件上传与目录遍历",
              "服务器管理器→删除WebDAV发布角色；或移除WebDAVModule与WebDAVHandler",
              check_iis_webdav, depends=_depends_iis_worker),
            W("MW-W7", "IIS HTTP方法限制(PUT/DELETE/TRACE)", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
              "请求筛选拒绝PUT/DELETE/TRACE等非业务方法",
              "IIS管理器→请求筛选→HTTP谓词→拒绝PUT/DELETE/TRACE（或拒绝*)",
              check_iis_http_methods, depends=_depends_iis_worker),
            W("MW-W8", "IIS 请求筛选启用", CAT_MW, LEVEL_ALL, "8.1.4.4 c)",
              "启用requestFiltering，过滤异常URL与请求头",
              "安装「请求筛选」功能并确保 requestFiltering enabled=true",
              check_iis_request_filtering, depends=_depends_iis_worker),
            W("MW-W9", "IIS 应用程序池最小权限", CAT_MW, LEVEL_ALL, "8.1.4.2 b)",
              "应用程序池使用ApplicationPoolIdentity等最小权限标识，禁止LocalSystem",
              "IIS管理器→应用程序池→高级设置→标识→ApplicationPoolIdentity",
              check_iis_apppool_identity, depends=_depends_iis_worker),
            W("MW-W10", "Tomcat shutdown端口禁用", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
              "server.xml 中 <Server port=\"-1\">，关闭shutdown端口",
              "修改conf/server.xml Server port=-1并重启Tomcat",
              partial(check_tomcat_shutdown, "windows"), depends=_depends_tomcat_win),
            W("MW-W11", "Tomcat AJP连接器关闭", CAT_MW, LEVEL_ALL, "8.1.3.1 b)",
              "未使用的AJP Connector应删除，避免Ghostcat文件读取",
              "注释或删除server.xml中的AJP Connector；如需保留须配置secretRequired",
              partial(check_tomcat_ajp_connector, "windows"), depends=_depends_tomcat_win),
            W("MW-W12", "Tomcat manager后台管控", CAT_MW, LEVEL_ALL, "8.1.4.2 b)",
              "删除manager/host-manager应用及manager-gui/admin-gui角色授权",
              "删除webapps/manager与webapps/host-manager，清理tomcat-users.xml角色",
              partial(check_tomcat_manager, "windows"), depends=_depends_tomcat_win),
            W("MW-W13", "Tomcat 强制HTTPS", CAT_MW, LEVEL_ALL, "8.1.2.2 a)",
              "web.xml 配置security-constraint + transport-guarantee=CONFIDENTIAL",
              "在web.xml增加security-constraint强制CONFIDENTIAL传输",
              partial(check_tomcat_https_constraint, "windows"), depends=_depends_tomcat_win),
        ]
    return [
        W("MW-1", "中间件服务运行状态", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "Web中间件正常运行并受监控", "确保中间件自启并纳入监控", check_mw_service),
        W("MW-17", "开放端口与对应应用", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "列出所有监听端口及其进程，高风险端口不得对外暴露",
          "关闭不必要端口，管理/数据库端口限制访问源", check_open_ports),
        W("MW-VER", "中间件/应用软件版本与已知CVE", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "运行中的中间件不得命中已公开高危CVE；所有软件名称+版本应在报告中体现",
          "定期升级中间件到修复版本；漏洞库同步更新；对未知软件补充资产登记", check_mw_versions),
        W("MW-PKG", "宿主关键软件版本与已知CVE", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "内核、glibc、OpenSSL、OpenSSH不得命中已公开高危CVE",
          "操作系统定期打补丁；关注安全公告及时升级", check_host_versions),
        W("MW-WAF", "Web应用防火墙(WAF/IPS)", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "部署 Web 应用防火墙或主机防护组件",
          "按等保三级要求部署 WAF，拦截 SQLi/XSS/命令注入等攻击", check_waf_status),
        W("MW-2", "Nginx版本信息隐藏", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "server_tokens off", "nginx.conf 设置 server_tokens off", check_nginx_tokens,
          depends=_depends_nginx),
        W("MW-3", "Nginx目录遍历防护", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
          "autoindex off，禁止目录列举", "nginx.conf 设置 autoindex off", check_nginx_autoindex,
          depends=_depends_nginx),
        W("MW-4", "Nginx TLS协议配置", CAT_MW, LEVEL_ALL, "8.1.2.2 a)",
          "仅启用TLSv1.2/1.3，禁用SSLv3/TLSv1.0/1.1",
          "ssl_protocols TLSv1.2 TLSv1.3;", check_nginx_tls,
          depends=_depends_nginx),
        W("MW-5", "Nginx访问日志", CAT_MW, LEVEL_ALL, "8.1.4.3 a)",
          "开启access_log并集中留存", "配置access_log并接入日志平台", check_nginx_log,
          depends=_depends_nginx),
        W("MW-6", "Apache版本隐藏", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "ServerTokens Prod、ServerSignature Off",
          "httpd.conf 设置 ServerTokens Prod、ServerSignature Off", check_apache_tokens,
          depends=_depends_apache),
        W("MW-7", "Apache目录遍历防护", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
          "Options不含Indexes", "配置 Options -Indexes", check_apache_autoindex,
          depends=_depends_apache),
        W("MW-8", "Tomcat版本信息隐藏", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "关闭ErrorReportValve与server信息",
          "server.xml 配置 ErrorReportValve showReport=false", check_tomcat_version,
          depends=_depends_tomcat),
        W("MW-9", "Tomcat AJP端口管控", CAT_MW, LEVEL_ALL, "8.1.3.1 b)",
          "AJP 8009不对内网以外暴露，或配置secret",
          "关闭AJP Connector或设置 secretRequired=true", check_tomcat_ajp,
          depends=_depends_tomcat),
        W("MW-10", "HTTPS证书有效期", CAT_MW, LEVEL_ALL, "8.1.2.2 a)",
          "证书有效且30天内不失效", "检查证书链与有效期，及时续期", check_tls_cert),
        W("MW-11", "Web管理后台访问控制", CAT_MW, LEVEL_ALL, "8.1.4.2 b)",
          "管理后台限制访问源并强口令", "限制管理入口IP并启用MFA", check_mw_admin_access),
        # ========== 密码策略（本次新增）==========
        W("MW-P1", "中间件默认账户/弱口令", CAT_MW, LEVEL_ALL, "8.1.4.1 a)",
          "删除或禁用中间件默认账户：Tomcat tomcat/manager/admin；Jenkins 默认密码；Nginx/Apache htpasswd 空/弱",
          "Tomcat 改 tomcat-users.xml；Jenkins 改 config.xml；htpasswd 确认非空弱",
          check_mw_default_accounts),
        W("MW-P2", "Jenkins 默认密码/首次启动安全", CAT_MW, LEVEL_ALL, "8.1.4.1 a)",
          "Jenkins 首次启动生成的初始密码已改；禁用匿名访问；启用安全矩阵",
          "安装后立即使用 unlock.key 解锁并修改管理员密码，启用全局安全→安全矩阵",
          check_jenkins_pwd, depends=_depends_jenkins),
        # ========== 扩展：Tomcat / Nginx / Apache 配置核查 ==========
        W("MW-12", "Tomcat shutdown端口禁用", CAT_MW, LEVEL_ALL, "8.1.4.4 a)",
          "server.xml 中 <Server port=\"-1\">，关闭shutdown端口",
          "修改conf/server.xml Server port=-1并重启Tomcat",
          partial(check_tomcat_shutdown, "linux"), depends=_depends_tomcat),
        W("MW-13", "Tomcat manager后台管控", CAT_MW, LEVEL_ALL, "8.1.4.2 b)",
          "删除manager/host-manager应用及manager-gui/admin-gui角色授权",
          "删除webapps/manager与webapps/host-manager，清理tomcat-users.xml角色",
          partial(check_tomcat_manager, "linux"), depends=_depends_tomcat),
        W("MW-14", "Tomcat 强制HTTPS", CAT_MW, LEVEL_ALL, "8.1.2.2 a)",
          "web.xml 配置security-constraint + transport-guarantee=CONFIDENTIAL",
          "在web.xml增加security-constraint强制CONFIDENTIAL传输",
          partial(check_tomcat_https_constraint, "linux"), depends=_depends_tomcat),
        W("MW-15", "Nginx HTTP方法限制", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
          "仅允许GET/HEAD/POST，拒绝PUT/DELETE/TRACE",
          "配置 if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }",
          check_nginx_methods, depends=_depends_nginx),
        W("MW-16", "Apache HTTP方法限制(TRACE)", CAT_MW, LEVEL_ALL, "8.1.4.2 c)",
          "TraceEnable Off 并通过LimitExcept限制PUT/DELETE",
          "httpd.conf 设置 TraceEnable Off 与 <LimitExcept GET POST>",
          check_apache_methods, depends=_depends_apache),
    ]


# ---------------- 密码策略 runner（中间件）----------------

def check_mw_default_accounts():
    """Linux: 中间件默认账户/弱口令（读取经执行器，支持远程服务器）"""
    msgs, status = [], STATUS_PASS
    found_mw = False
    # Tomcat: tomcat-users.xml
    for path in ("/etc/tomcat8/tomcat-users.xml", "/etc/tomcat9/tomcat-users.xml",
                 "/usr/share/tomcat/conf/tomcat-users.xml", "/opt/tomcat/conf/tomcat-users.xml",
                 "/usr/local/tomcat/conf/tomcat-users.xml"):
        txt = _read(path)
        if not txt.strip():
            continue
        found_mw = True
        try:
            # 找 <user username="xxx" password="yyy"/>
            users = re.findall(r'<user\s+username="([^"]+)"\s+password="([^"]*)"', txt, re.I)
            weak_defaults = {"tomcat", "admin", "manager", "roles"}
            for u, p in users:
                if not p or p.strip() == "":
                    msgs.append("⚠️ Tomcat 用户 '%s' 密码为空" % u); status = STATUS_WARN
                elif p.lower() in ("tomcat", "admin", "manager", "password", "123456", "changeme"):
                    msgs.append("⚠️ Tomcat 用户 '%s' 使用弱口令 '%s'" % (u, p)); status = STATUS_WARN
                if u.lower() in weak_defaults:
                    msgs.append("⚠️ Tomcat 存在默认账户 '%s'" % u); status = STATUS_WARN
        except Exception as e:
            msgs.append("⚠️ 读取 %s 失败: %s" % (path, e))
        break
    # Jenkins: secrets/initialAdminPassword + config.xml
    j_home = _jenkins_home()
    init_pw = j_home + '/secrets/initialAdminPassword'
    init_val = _read(init_pw).strip()
    if init_val:
        msgs.append("⚠️ Jenkins 初始密码文件仍存在: %s（应立即删除并改密码）" % init_pw); status = STATUS_WARN
        msgs.append("   初始密码值: %s..." % init_val[:12])
    txt = _read(j_home + '/config.xml')
    if txt.strip():
        low = txt.lower()
        if '<disablerememberme>false</disablerememberme>' in low:
            msgs.append("⚠️ Jenkins RememberMe 未禁用")
        if re.search(r'<authorizationStrategy>.*?any.*?</authorizationStrategy>', txt, re.I | re.S):
            msgs.append("⚠️ Jenkins 使用 Anybody 授权策略（任何人可读）"); status = STATUS_WARN
        if '<securityRealm class="hudson.security.HudsonPrivateSecurityRealm">' in txt:
            msgs.append("✅ Jenkins 使用私有安全域（非匿名）")
    # Nginx htpasswd / Apache .htpasswd
    rc, out = run_cmd(
        "bash -c \"ls -1 /etc/nginx/.htpasswd* /etc/nginx/htpasswd* "
        "/etc/httpd/.htpasswd* /etc/apache2/.htpasswd* 2>/dev/null\"")
    files = [l.strip() for l in out.splitlines() if l.strip().startswith("/")]
    for fp in files:
        try:
            perms = run_cmd("stat -c '%%a' %s 2>/dev/null" % shlex.quote(fp))[1].strip()
            if perms:
                try:
                    if int(perms, 8) & 0o004:
                        msgs.append("⚠️ htpasswd 文件 %s 全局可读(%s)，应改 600" % (fp, perms))
                        status = STATUS_WARN
                except ValueError:
                    pass
            lines = [l.strip() for l in _read(fp).splitlines() if l.strip() and not l.startswith('#')]
            empty = [l for l in lines if ':' not in l or l.split(':', 1)[1] in ('', '!', '*')]
            if empty:
                msgs.append("⚠️ htpasswd 文件 %s 存在 %d 条空/禁用口令行" % (fp, len(empty))); status = STATUS_WARN
            else:
                msgs.append("✅ htpasswd 文件 %s 权限安全" % fp)
        except Exception as e:
            msgs.append("⚠️ htpasswd 检查 %s 失败: %s" % (fp, e))
    if not found_mw and not msgs:
        return STATUS_MANUAL, "未检测到 Tomcat/Jenkins/Nginx/Apache 配置文件，请人工核查中间件默认账户与弱口令"
    return status, "；".join(msgs) if msgs else "未发现明显中间件默认账户/弱口令"


def check_jenkins_pwd():
    """Jenkins 密码专项（Linux，读取经执行器）"""
    msgs, status = [], STATUS_PASS
    j_home = _jenkins_home()
    if _read(j_home + '/secrets/initialAdminPassword').strip():
        msgs.append("❌ Jenkins 初始密码文件仍存在（应立即删除并改密码）"); status = STATUS_WARN
    # 匿名访问
    txt = _read(j_home + '/config.xml')
    if txt.strip():
        if '<useSecurity>false</useSecurity>' in txt.lower():
            msgs.append("❌ Jenkins 未启用安全机制(useSecurity=false)"); status = STATUS_FAIL
        elif '<securityRealm class="hudson.security.HudsonPrivateSecurityRealm">' in txt:
            msgs.append("✅ Jenkins 使用私有安全域")
        if '<authorizationStrategy>hudson.security.FullControlOnceLoggedInAuthorizationStrategy</authorizationStrategy>' in txt:
            msgs.append("✅ Jenkins 授权策略: FullControlOnceLoggedIn（仅登录用户可读）")
        elif re.search(r'anybody|AnonymousAuthorizationStrategy', txt, re.I):
            msgs.append("⚠️ Jenkins 存在匿名访问风险"); status = STATUS_WARN
    if not msgs:
        return STATUS_MANUAL, "未检测到 Jenkins，请人工核查其密码策略与安全配置"
    return status, "；".join(msgs)


def check_mw_default_accounts_win():
    """Windows: 中间件默认账户"""
    msgs, status = [], STATUS_PASS
    # IIS 相关本地用户
    rc, out = run_powershell(
        "Get-WmiObject Win32_UserAccount -Filter \"LocalAccount=True\" | "
        "Where-Object { $_.Name -match 'IUSR|IIS|DefaultAppPool|ASP|Tomcat|Jenkins' } | "
        "Select-Object Name, Disabled, Lockout")
    if rc == 0 and out.strip():
        for line in out.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('Name') or line.startswith('--'): continue
            if 'Disabled=False' in line and 'Lockout=False' in line:
                msgs.append("⚠️ 本地中间件账户活跃: %s" % line[:120]); status = STATUS_WARN
    # Jenkins
    rc2, out2 = run_cmd(["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                         "/f", "Jenkins", "/s", "/d"])
    if "Jenkins" in (out2 or ""):
        rc3, out3 = run_powershell(
            "Get-ChildItem 'C:\\Program Files\\Jenkins\\secrets\\initialAdminPassword' -ErrorAction SilentlyContinue")
        if rc3 == 0 and out3.strip():
            msgs.append("⚠️ Jenkins 初始密码文件仍存在，请立即删除并改密码"); status = STATUS_WARN
    if not msgs:
        return STATUS_MANUAL, "未检测到明显中间件默认账户，请人工核查 Tomcat/IIS/Jenkins 等的默认口令"
    return status, "；".join(msgs)


def check_iis_apppool_pwd():
    """Windows: IIS 应用池 + IUSR 账户密码"""
    msgs, status = [], STATUS_PASS
    rc, out = run_powershell(
        "& $env:windir\\System32\\inetsrv\\appcmd.exe list apppool /text:userName")
    if rc == 0 and out.strip():
        users = [l.strip() for l in out.splitlines() if l.strip()]
        msgs.append("IIS 应用池账户: %s" % (", ".join(users[:5]) or "(默认ApplicationPoolIdentity)"))
    # IUSR / IUSRS
    rc2, out2 = run_powershell(
        "net user IUSR 2>&1; net user IUS_IIS* 2>&1 | Select-Object -First 5")
    if rc2 == 0 and "active" in out2.lower() or "账户启用" in out2:
        msgs.append("⚠️ IUSR 账户为启用状态（通常建议保持启用，但需确认口令强度）"); status = STATUS_WARN
    return status, "；".join(msgs)
