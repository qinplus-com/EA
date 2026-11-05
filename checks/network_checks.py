# -*- coding: utf-8 -*-
"""网络与边界安全检测（等保2.0 安全通信网络 / 安全区域边界）"""
import re

from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_NET, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, run_powershell

# ---------------- 网络设备直连配置 ----------------
_NET_CONF = {}
_DEVCACHE = {}


def set_net_conf(conf):
    """由 engine 注入网络设备访问配置（SSH/SNMP）。"""
    global _NET_CONF
    _NET_CONF = dict(conf or {})
    _DEVCACHE.clear()


def get_net_conf():
    return _NET_CONF


def _device_configured():
    """是否已指定网络设备（填写设备 IP 或 SNMP 地址）"""
    conf = _NET_CONF or {}
    return bool((conf.get("host") or "").strip() or (conf.get("snmp_host") or "").strip())


def _snmp_only_facts():
    """仅配置 SNMP 时，用 sysDescr 识别厂商与型号"""
    conf = _NET_CONF or {}
    host = (conf.get("snmp_host") or "").strip()
    if not host:
        return None, "未配置网络设备"
    try:
        from core.netdev import (snmp_walk_device, parse_model,
                                 vendor_display_from_descr)
        info = snmp_walk_device(host, conf.get("snmp_community") or "public",
                                timeout=3)
    except Exception as e:
        return None, "SNMP 探测失败：%s" % e
    descr = info.get("sysDescr") or ""
    vendor, vkey = vendor_display_from_descr(descr)
    facts = {
        "vendor": vendor, "host": host,
        "hostname": info.get("sysName") or "",
        "model": (conf.get("model") or "").strip() or parse_model(descr),
        "os_version": descr.splitlines()[0][:160] if descr else "",
        "config": "", "acl": "", "logging": "", "snmp": "", "aaa": "",
        "ha": "", "mgmt": "", "_vendor_key": vkey,
    }
    return facts, ""


def _dev_label(facts):
    """设备展示名：厂商 + 型号；型号缺失时明确标注"""
    vendor = (facts.get("vendor") or "未知厂商").strip()
    model = (facts.get("model") or "").strip()
    return "%s %s" % (vendor, model) if model else "%s（型号未识别）" % vendor


def device_summary():
    """供报告/界面展示的设备型号摘要（未配置或识别失败时返回空串）。"""
    if not _device_configured():
        return ""
    facts, _err = _device_facts()
    if not facts:
        return ""
    label = _dev_label(facts)
    host = (facts.get("host") or "").strip()
    return "%s（%s）" % (label, host) if host else label


def _device_facts():
    """连接网络设备并返回事实字典；未配置或失败时返回 (None, 原因)。"""
    conf = _NET_CONF or {}
    host = (conf.get("host") or "").strip()
    if not host:
        if (conf.get("snmp_host") or "").strip():
            if "facts" in _DEVCACHE:
                return _DEVCACHE["facts"], ""
            if "error" in _DEVCACHE:
                return None, _DEVCACHE["error"]
            facts, err = _snmp_only_facts()
            if facts:
                _DEVCACHE["facts"] = facts
            else:
                _DEVCACHE["error"] = err
            return facts, err
        return None, "未配置网络设备"
    if "facts" in _DEVCACHE:
        return _DEVCACHE["facts"], ""
    if "error" in _DEVCACHE:
        return None, _DEVCACHE["error"]
    from core.netdev import build_connector, NetdevError
    conn = build_connector(conf)
    if conn is None:
        return None, "未配置网络设备"
    try:
        conn.connect()
        facts = conn.facts()
        facts["_vendor_key"] = conn.vendor
        # SSH 版本行未给出型号时：用 SNMP sysDescr 或用户手填型号兜底
        if not (facts.get("model") or "").strip():
            facts["model"] = (conf.get("model") or "").strip()
        if not facts.get("model") and (conf.get("snmp_host") or "").strip():
            snmp_facts, _err = _snmp_only_facts()
            if snmp_facts:
                facts["model"] = snmp_facts.get("model") or ""
                if facts.get("vendor") in ("", "未知厂商", "Cisco IOS"):
                    facts["vendor"] = snmp_facts.get("vendor") or facts.get("vendor")
        _DEVCACHE["facts"] = facts
        return facts, ""
    except NetdevError as e:
        _DEVCACHE["error"] = str(e)
        return None, str(e)
    except Exception as e:
        _DEVCACHE["error"] = "网络设备检测异常：%s" % e
        return None, _DEVCACHE["error"]
    finally:
        try:
            conn.close()
        except Exception:
            pass



def _sysctl_value(key):
    rc, out = run_cmd(["sysctl", "-n", key])
    return out.strip() if rc == 0 else None


def _listen_ports():
    """返回 [(host, port)] 监听列表"""
    rc, out = run_cmd(["ss", "-tln"])
    if rc != 0:
        rc, out = run_cmd(["netstat", "-tln"])
    rows = []
    for line in out.splitlines():
        m = re.search(r"(\S+):(\d+)\s+\S+\s+LISTEN", line, re.I)
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows


def _exposed(rows, ports):
    """非回环地址上开放的指定端口"""
    hit = []
    for host, port in rows:
        if port in ports and not (host.startswith("127.") or host in ("::1", "[::1]")):
            hit.append("%s:%s" % (host, port))
    return sorted(set(hit))


# ---------------- Linux ----------------

def check_ip_forward():
    v = _sysctl_value("net.ipv4.ip_forward")
    if v is None:
        return STATUS_MANUAL, "无法读取 ip_forward"
    return (STATUS_PASS, "ip_forward=0，未开启路由转发") if v == "0" else \
           (STATUS_FAIL, "ip_forward=%s，主机充当路由器，存在流量旁路风险" % v)


def check_syncookies():
    v = _sysctl_value("net.ipv4.tcp_syncookies")
    if v is None:
        return STATUS_MANUAL, "无法读取 tcp_syncookies"
    return (STATUS_PASS, "tcp_syncookies=1，已开启SYN Flood防护") if v == "1" else \
           (STATUS_WARN, "tcp_syncookies=%s，建议开启防SYN Flood" % v)


def check_redirects():
    bad = []
    for key in ("net.ipv4.conf.all.accept_redirects",
                "net.ipv4.conf.all.accept_source_route",
                "net.ipv4.conf.default.accept_redirects",
                "net.ipv4.conf.default.accept_source_route"):
        v = _sysctl_value(key)
        if v is not None and v != "0":
            bad.append("%s=%s" % (key.split(".")[-1], v))
    if bad:
        return STATUS_WARN, "以下网络参数未加固: %s" % "、".join(bad)
    return STATUS_PASS, "已禁用ICMP重定向与源路由"


def check_firewall_default():
    rc, out = run_cmd(["firewall-cmd", "--get-default-zone"])
    if rc == 0:
        zone = out.strip().splitlines()[0] if out.strip() else ""
        rc2, out2 = run_cmd(["firewall-cmd", "--zone=%s" % zone, "--list-all"])
        if rc2 == 0:
            return STATUS_PASS, "firewalld运行中，默认区域 %s 已启用访问控制" % zone
    rc, out = run_cmd(["iptables", "-S"], timeout=15)
    if rc == 0:
        policies = re.findall(r"-P\s+\w+\s+(ACCEPT|DROP|REJECT)", out)
        if policies and "ACCEPT" not in policies:
            return STATUS_PASS, "iptables默认策略均为拒绝"
        if policies:
            accept = [p for p in policies if p == "ACCEPT"]
            return STATUS_WARN, "iptables存在%s条链默认ACCEPT，建议改为DROP" % len(accept)
    return STATUS_FAIL, "未检测到有效的主机防火墙访问控制策略(firewalld/iptables)"


def check_exposed_ports():
    rows = _listen_ports()
    if not rows:
        return STATUS_ERROR, "无法读取监听端口列表"
    exposed = [(h, p) for h, p in rows
               if not (h.startswith("127.") or h in ("::1", "[::1]"))]
    risky = _exposed(rows, {"21", "23", "135", "139", "445", "1433", "3306",
                            "5432", "6379", "27017"})
    if risky:
        return STATUS_FAIL, "数据库/高危服务监听在对外地址: %s" % "、".join(risky)
    if len(exposed) > 20:
        return STATUS_WARN, "对外监听端口较多(%d个)，建议按最小必要原则收敛" % len(exposed)
    return STATUS_PASS, "对外监听端口 %d 个，未发现数据库/高危服务直接暴露" % len(exposed)


def check_telnet_ftp():
    rc, out = run_cmd(["ss", "-tln"])
    if rc != 0:
        return STATUS_MANUAL, "无法读取端口"
    hit = _exposed(_listen_ports(), {"21", "23"})
    if hit:
        return STATUS_FAIL, "检测到明文管理/传输服务开放: %s，应禁用Telnet/FTP并改用SSH/SFTP" % "、".join(hit)
    return STATUS_PASS, "未开放Telnet(23)/FTP(21)明文服务"


def check_network_device_config():
    return STATUS_MANUAL, "请人工核查交换机/路由器/防火墙：安全区域划分、访问控制策略、管理口隔离与默认口令"


def check_boundary_redundancy():
    return STATUS_MANUAL, "请人工核查边界设备与链路是否冗余部署（三级要求），并提供拓扑与冗余说明"


# ---------------- 防火墙 egress / ACL 自动检测（Linux） ----------------

def check_firewall_egress():
    """Linux: 检查主机侧出口防火墙 egress 策略 + 尝试探测网络设备"""
    msgs, status = [], STATUS_PASS
    # 1. iptables egress 默认策略
    rc, out = run_cmd(["iptables", "-L", "OUTPUT", "-n"], timeout=10)
    if rc == 0:
        # 找默认策略行
        m = re.search(r"Chain OUTPUT.*policy\s+(\w+)", out)
        if m:
            policy = m.group(1).upper()
            if policy in ("DROP", "REJECT"):
                msgs.append("iptables OUTPUT 默认策略: %s ✅" % policy)
            else:
                msgs.append("iptables OUTPUT 默认策略: %s（建议改为DROP）" % policy)
                status = STATUS_WARN
        # 检查是否允许任意外网访问
        any_any = len(re.findall(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0", out))
        if any_any:
            msgs.append("存在 %d 条 OUTPUT ACCEPT ANY→ANY 规则，建议收敛出口规则" % any_any)
    # 2. firewalld egress
    rc2, out2 = run_cmd(["firewall-cmd", "--list-all"])
    if rc2 == 0:
        egress = re.search(r"egress-services:\s*(\S+.*)", out2)
        if egress and "all" not in egress.group(1).lower():
            msgs.append("firewalld 已配置 egress-services")
    # 3. nftables
    rc3, out3 = run_cmd(["nft", "list", "ruleset"])
    if rc3 == 0 and re.search(r"type\s+filter\s+hook\s+egress", out3):
        msgs.append("nftables egress hook 存在")
    return status, "；".join(msgs) if msgs else "无法检测到有效的主机侧出口防火墙策略"


def check_firewall_egress_win():
    """Windows: 检查防火墙 egress 默认策略"""
    rc, out = run_powershell(
        "try{$c=Get-NetFirewallProfile | ForEach-Object {$_.Name+':In='+$_.DefaultInboundAction+':Out='+$_.DefaultOutboundAction}}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取防火墙 egress 策略"
    msgs, status = [], STATUS_PASS
    for line in out.strip().splitlines():
        low = line.lower()
        if ":out=allow" in low:
            msgs.append("%s 出口策略为Allow（建议改为Block）" % line)
            status = STATUS_WARN
        elif ":out=block" in low:
            msgs.append("%s ✅" % line)
    return status, "；".join(msgs) if msgs else out.strip()[:200]


# ---------------- 网络设备 ACL / 边界防护（SSH 直连 + SNMP） ----------------

def _no_device_hint(err="", extra=None):
    """未配置或连接失败时的统一降级文案。"""
    conf = _NET_CONF or {}
    if not (conf.get("host") or "").strip():
        tip = ("未配置网络设备。可在「网络与边界」页填写防火墙/交换机 IP、SSH 账号与厂商，"
               "工具将自动登录执行 show/display 取配置。")
    else:
        tip = "网络设备连接失败（%s），已降级为主机侧证据 + 人工核查。" % (err or "未知原因")
    if extra:
        tip += " " + extra
    return tip


def check_network_acl():
    """8.1.3.2 b) 网络设备 ACL：默认拒绝、删除冗余规则"""
    from core.netdev import parse_acl, external_inbound_acls
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err)
    cfg = facts.get("config") or ""
    ext = external_inbound_acls(cfg)
    acl = parse_acl(facts.get("acl") or cfg, ext or None)
    scope = ("外部接口入方向 ACL %s" % "、".join(sorted(ext))) if ext else "全部 ACL"
    if acl["count"] == 0:
        if cfg.strip():
            return STATUS_FAIL, ("已读取设备 %s(%s) 完整运行配置（%d 字符），%s 中未发现任何规则，"
                                 "边界未配置访问控制策略"
                                 % (_dev_label(facts), facts["host"], len(cfg), scope))
        return STATUS_MANUAL, ("设备 %s(%s) 未返回可解析的配置；请人工核查边界 ACL（默认拒绝、删除冗余规则）"
                               % (_dev_label(facts), facts["host"]))
    deny_all = any(r["action"] == "deny" and r["any_any"] and r["proto"] in ("ip", "any", "")
                   for r in acl["rules"])
    msgs = ["设备 %s(%s) %s 共 %d 条：permit %d / deny %d"
            % (_dev_label(facts), facts["host"], scope, acl["count"],
               acl["permit"], acl["deny"])]
    status = STATUS_PASS
    if acl["deny"] == 0:
        msgs.append("⚠️ 未发现任何 deny 规则，可能缺少默认拒绝")
        status = STATUS_WARN
    if acl["any_any"] > 0:
        msgs.append("⚠️ 存在 %d 条 permit any→any 规则，建议收敛源/目的地址" % acl["any_any"])
        status = STATUS_WARN
    if status == STATUS_PASS:
        msgs.append("✅ 存在默认拒绝（deny ip any any）且无 any→any 放通" if deny_all
                    else "✅ 存在 deny 规则且无 any→any 放通")
    return status, "；".join(msgs)


def check_network_acl_win():
    """Windows 版同名检测"""
    return check_network_acl()


def check_netdev_acl_5tuple():
    """8.1.3.2 c) 源/目的地址+端口+协议 五元组检查"""
    from core.netdev import parse_acl, external_inbound_acls
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err)
    cfg = facts.get("config") or ""
    ext = external_inbound_acls(cfg)
    acl = parse_acl(facts.get("acl") or cfg, ext or None)
    scope = ("外部接口入方向 ACL %s" % "、".join(sorted(ext))) if ext else "ACL"
    if acl["count"] == 0:
        if cfg.strip():
            return STATUS_FAIL, ("已读取设备 %s(%s) 完整运行配置，%s 中未发现任何访问控制规则，"
                                 "不存在源/目的IP+端口+协议的五元组控制"
                                 % (_dev_label(facts), facts["host"], scope))
        return STATUS_MANUAL, "设备未返回可解析的配置，请人工核查五元组（源/目的IP+端口+协议）"
    with_addr = acl["with_addr_pair"]
    with_port = acl["with_port"]
    total = acl["count"]
    msgs = ["%s 共 %d 条：含源/目的地址对 %d 条，含端口/范围条件 %d 条"
            % (scope, total, with_addr, with_port)]
    if with_addr == 0 and with_port == 0:
        msgs.append("⚠️ 规则未体现地址/端口/协议维度的细化控制")
        return STATUS_WARN, "；".join(msgs)
    if with_addr == 0:
        msgs.append("⚠️ 规则源/目的地址均为 any，缺少地址维度控制，仅按端口/协议过滤")
        return STATUS_WARN, "；".join(msgs)
    if with_port == 0:
        msgs.append("⚠️ 未见端口级控制，建议对关键服务限定 dport")
        return STATUS_WARN, "；".join(msgs)
    msgs.append("✅ 规则包含源/目的地址与端口/协议约束")
    return STATUS_PASS, "；".join(msgs)


def check_netdev_app_filter():
    """8.1.3.2 d) 三级：应用层协议过滤（WAF/应用识别/ALG）"""
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查是否具备应用层过滤能力（WAF、应用识别、ALG）。")
    cfg = (facts.get("config") or "").lower()
    hits = []
    for kw, label in (("waf", "WAF/Web 防护"), ("application-inspection", "应用识别"),
                      ("appfw", "应用防火墙"), ("alg", "ALG 应用层网关"),
                      ("inspect ", "深度包检测(ALG/inspect)"),
                      ("http-proxy", "HTTP 代理"), ("url-filter", "URL 过滤"),
                      ("ips", "IPS 入侵防御")):
        if kw in cfg:
            hits.append(label)
    if hits:
        return STATUS_PASS, "设备 %s 配置中检测到应用层过滤特征：%s" % (_dev_label(facts), "、".join(hits))
    return STATUS_WARN, ("设备 %s 配置中未见应用层协议过滤特征；三级系统建议启用 WAF/应用识别/ALG 或前置 WAF"
                         % _dev_label(facts))


def check_netdev_intrusion_alarm():
    """8.1.3.3 b) 边界攻击记录与报警"""
    from core.netdev import parse_logging
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查 IPS/IDS 是否记录攻击并实时告警。")
    log = parse_logging(facts.get("logging") or "")
    cfg = (facts.get("config") or "").lower()
    ips_kw = [k for k in ("ips", "ids", "attack-defense", "anti-ddos", "入侵防御") if k in cfg]
    msgs, status = [], STATUS_PASS
    if log["buffer"] or log["enabled"]:
        msgs.append("✅ 设备日志已开启（%s）" % ("含 syslog 服务器 %s" % "、".join(log["syslog_hosts"])
                                             if log["syslog_hosts"] else "本地缓冲"))
    else:
        msgs.append("⚠️ 未见设备日志开启，攻击事件无法记录")
        status = STATUS_WARN
    if ips_kw:
        msgs.append("✅ 检测到攻击防护特征：%s" % "、".join(ips_kw))
    else:
        msgs.append("⚠️ 未见 IPS/IDS/抗 DDoS 特征，建议启用攻击检测与告警")
        if status == STATUS_PASS:
            status = STATUS_WARN
    if log["syslog_hosts"] and ips_kw and log["buffer"]:
        status = STATUS_PASS
    return status, "；".join(msgs)


def check_netdev_border_av():
    """8.1.3.3 c) 三级：主要节点恶意代码/钓鱼防御"""
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查边界是否部署防病毒/反钓鱼/沙箱。")
    cfg = (facts.get("config") or "").lower()
    label_by_kw = [
        ("anti-virus", "防病毒"), ("antivirus", "防病毒"), ("av-engine", "防病毒引擎"),
        ("content-security", "内容安全"), ("web-reputation", "Web 信誉"),
        ("anti-phishing", "反钓鱼"), ("phishing", "反钓鱼"),
        ("sandbox", "沙箱"), ("threat-intelligence", "威胁情报"), ("url-reputation", "URL 信誉"),
    ]
    hits = sorted({label for kw, label in label_by_kw if kw in cfg})
    if hits:
        return STATUS_PASS, "设备 %s 配置中检测到边界恶意代码/钓鱼防护：%s" % (_dev_label(facts), "、".join(hits))
    return STATUS_WARN, ("设备 %s 未见防病毒/反钓鱼/沙箱特征；三级系统应在边界部署恶意代码与钓鱼防御"
                         % _dev_label(facts))


def check_netdev_audit_retention():
    """8.1.3.4 a) 边界审计留存≥6个月"""
    from core.netdev import parse_logging
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查边界设备日志留存≥6个月。")
    log = parse_logging(facts.get("logging") or "")
    cfg = (facts.get("config") or "").lower()
    msgs = []
    if log["syslog_hosts"]:
        msgs.append("✅ 已配置远程 syslog 服务器 %s（可实现集中长留存）" % "、".join(log["syslog_hosts"]))
        return STATUS_PASS, "设备 %s(%s) 日志外送至 syslog，满足集中留存前提；请确认日志服务器留存≥6个月" % (
            _dev_label(facts), facts["host"])
    if log["buffer"]:
        size = log.get("buffer_size")
        msgs.append("⚠️ 仅本地缓冲日志%s，设备本地留存通常不足 6 个月"
                    % ("（%d 条）" % size if size else ""))
    else:
        msgs.append("❌ 未见日志开启")
        if (facts.get("config") or "").strip():
            return STATUS_FAIL, "；".join(msgs) + "；设备运行配置中无任何日志/审计配置，不满足日志留存要求"
    if "logging file" in cfg or "logfile" in cfg or "info-center logfile" in cfg:
        msgs.append("检测到本地日志文件配置，需确认文件轮转与保留周期≥6个月")
    return STATUS_WARN, "；".join(msgs)


def check_netdev_mgmt_isolation():
    """8.1.3.4 b) 仅通过本地管理口/管理网段管理网络设备"""
    from core.netdev import parse_mgmt
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查管理口仅允许管理网段访问、禁用公网管理。")
    mg = parse_mgmt(facts.get("mgmt") or facts.get("config") or "")
    msgs, status = [], STATUS_PASS
    if mg["vty_acl"]:
        msgs.append("✅ VTY/管理接口已配置 ACL 限制来源")
    else:
        msgs.append("⚠️ 未见 VTY/管理接口 access-class 限制，管理面可能对外开放")
        status = STATUS_WARN
    if mg["ssh_only"]:
        msgs.append("✅ 管理通道仅允许 SSH")
    else:
        msgs.append("⚠️ 未见强制 SSH，可能存在 Telnet 明文管理")
        if status == STATUS_PASS:
            status = STATUS_WARN
    if mg["mgmt_vrf"]:
        msgs.append("✅ 检测到管理 VRF/独立管理接口")
    else:
        msgs.append("提示：建议使用独立管理口/管理 VRF 与业务流量隔离")
    return status, "；".join(msgs)


def check_netdev_audit_central():
    """8.1.3.4 c) 三级：网络设备审计集中管理"""
    from core.netdev import parse_logging
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查设备日志是否统一送 syslog/日志审计平台。")
    log = parse_logging(facts.get("logging") or "")
    if log["syslog_hosts"]:
        return STATUS_PASS, ("设备 %s 日志已集中外送至 %s，满足审计集中管理要求"
                             % (_dev_label(facts), "、".join(log["syslog_hosts"])))
    return STATUS_WARN, ("设备 %s 未见远程 syslog 配置，审计日志未集中，三级系统建议统一送日志审计平台"
                         % _dev_label(facts))


def check_netdev_malware_clean():
    """8.1.3.5 a) 边界处检测并清除恶意代码"""
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查边界是否具备恶意代码检测清除能力。")
    cfg = (facts.get("config") or "").lower()
    kw = [("anti-virus", "防病毒"), ("content-filter", "内容过滤"), ("file-block", "文件拦截"),
          ("malware", "恶意软件检测"), ("attachment-filter", "附件过滤")]
    hits = sorted({lab for k, lab in kw if k in cfg})
    if hits:
        return STATUS_PASS, "设备 %s 具备边界恶意代码检测/清除特征：%s" % (_dev_label(facts), "、".join(hits))
    return STATUS_WARN, "设备 %s 未见恶意代码检测清除配置，建议在边界部署防病毒网关/内容过滤" % _dev_label(facts)


def check_netdev_trusted_boot():
    """8.1.3.6 a) 三级：边界设备可信验证"""
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请核查设备固件签名/可信启动/镜像校验。")
    cfg = (facts.get("config") or "").lower() + (facts.get("os_version") or "").lower()
    kw = [("secure boot", "安全启动"), ("trusted boot", "可信启动"), ("image signature", "镜像签名"),
          ("verified boot", "验证启动"), ("secure-boot", "安全启动"), ("ima", "完整性度量")]
    hits = sorted({lab for k, lab in kw if k in cfg})
    if hits:
        return STATUS_PASS, "设备 %s 检测到可信验证特征：%s" % (_dev_label(facts), "、".join(hits))
    return STATUS_MANUAL, ("设备 %s 未能从 show 输出判定可信启动；请人工核查固件签名校验、"
                           "Secure Boot、镜像完整性校验（三级要求）" % _dev_label(facts))


def check_netdev_redundancy():
    """8.1.2.1 a)/b) 边界设备与链路冗余"""
    from core.netdev import parse_ha
    facts, err = _device_facts()
    if facts is None:
        return STATUS_MANUAL, _no_device_hint(err, "请提供边界设备/链路冗余拓扑与主备切换记录。")
    ha = parse_ha(facts.get("ha") or facts.get("config") or "")
    msgs = []
    if ha["hsrp"]:
        msgs.append("HSRP")
    if ha["vrrp"]:
        msgs.append("VRRP")
    if ha["stack"]:
        msgs.append("堆叠/VSS/CSS/IRF/M-LAG")
    if ha["dual_sup"]:
        msgs.append("双主控冗余")
    if msgs:
        return STATUS_PASS, "设备 %s 检测到冗余机制：%s（仍需人工确认链路双线/机房双路）" % (
            _dev_label(facts), "、".join(msgs))
    return STATUS_MANUAL, ("设备 %s 未检测到 HSRP/VRRP/堆叠冗余；请人工核查设备与链路冗余部署"
                           % _dev_label(facts))


def _snmp_probe():
    """SNMP 只读探测（可选），返回 (信息 dict 或 None, 说明)。"""
    conf = _NET_CONF or {}
    if not conf.get("snmp_host"):
        return None, "未配置 SNMP"
    try:
        from core.netdev import snmp_walk_device
    except Exception as e:
        return None, "无法加载 SNMP 模块：%s" % e
    try:
        info = snmp_walk_device(conf["snmp_host"], conf.get("snmp_community") or "public",
                                timeout=int(conf.get("snmp_timeout") or 3),
                                port=int(conf.get("snmp_port") or 161))
        return info, ""
    except Exception as e:
        return None, str(e)


# ---------------- 网络设备出站外联管控（8.1.3.1 c）----------------

def check_internal_outbound():
    """内部用户非授权外联限制：主机侧 iptables OUTPUT + 尝试探测网关 egress"""
    msgs, status = [], STATUS_MANUAL
    # 1. 主机侧 DNS 出口限制
    rc, out = run_cmd(["iptables", "-L", "OUTPUT", "-n"])
    if rc == 0:
        dns_rules = len(re.findall(r"dport\s+53\s+ACCEPT", out))
        any_any = len(re.findall(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0", out))
        msgs.append("主机侧: iptables OUTPUT → DNS ACCEPT规则%d条，ANY→ANY ACCEPT规则%d条" % (dns_rules, any_any))
        if any_any > 0:
            status = STATUS_WARN
            msgs.append("⚠️ 主机出口规则过于宽松，应仅放行业务必需出站流量")
    # 2. nftables
    rc2, out2 = run_cmd(["nft", "list", "ruleset"])
    if rc2 == 0:
        msgs.append("nftables ruleset 存在")
    # 3. 网络设备网关 egress 核查（需 SSH/SNMP）
    msgs.append("建议在边界网关/防火墙核查 egress 策略：应禁止内网用户私自建立 VPN/SSH/SOCKS 代理绕过管控")
    return status if status != STATUS_MANUAL else STATUS_MANUAL, "；".join(msgs)


def check_internal_outbound_win():
    """Windows 内部用户非授权外联限制"""
    rc, out = run_powershell(
        "try{$r=Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue; $n=$r.Count; 'AllowRules='+$n}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取出口规则"
    msgs = ["Windows 出口允许规则数: %s" % out.strip()]
    msgs.append("建议核查是否存在允许 ANY→ANY 出站的默认规则，以及是否限制了 VPN/TOR/SOCKS 代理出站")
    return STATUS_MANUAL, "；".join(msgs)


# ---------------- Windows ----------------

def check_win_ip_forward():
    rc, out = run_powershell(
        "$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' "
        "-ErrorAction SilentlyContinue).IPEnableRouter;if($null -eq $v){'NONE'}else{$v}")
    if "NONE" in out:
        return STATUS_PASS, "未启用IP路由转发(IPEnableRouter未设置)"
    return (STATUS_PASS, "IPEnableRouter=0") if out.strip() == "0" else \
           (STATUS_FAIL, "IPEnableRouter=%s，主机充当路由器" % out.strip())


def check_win_firewall_default():
    rc, out = run_powershell(
        "try{(Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+$_.DefaultInboundAction}) -join ','}"
        "catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取防火墙默认入站策略"
    if "Block" not in out:
        return STATUS_FAIL, "防火墙默认入站策略未设为Block: %s" % out.strip()
    return STATUS_PASS, "防火墙默认入站策略均为Block(%s)" % out.strip()


def check_win_exposed_ports():
    rc, out = run_powershell(
        "try{$c=Get-NetTCPConnection -State Listen -ErrorAction Stop | "
        "Where-Object {$_.LocalAddress -notin @('127.0.0.1','::1')};"
        "$c | ForEach-Object {$_.LocalAddress+':'+$_.LocalPort}}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取监听端口"
    rows = [l.strip() for l in out.splitlines() if l.strip()]
    risky = [r for r in rows if r.split(":")[-1] in ("21", "23", "1433", "3306",
                                                     "5432", "6379", "27017")]
    if risky:
        return STATUS_FAIL, "数据库/高危服务监听在对外地址: %s" % "、".join(sorted(set(risky))[:8])
    if len(rows) > 20:
        return STATUS_WARN, "对外监听端口较多(%d个)，建议收敛" % len(rows)
    return STATUS_PASS, "对外监听端口 %d 个，未发现数据库/高危服务直接暴露" % len(rows)


def check_win_rdp_security():
    rc, out = run_cmd(["reg", "query",
                       r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                       "/v", "SecurityLayer"])
    m = re.search(r"SecurityLayer\s+REG_DWORD\s+0x(\d)", out)
    if not m:
        return STATUS_MANUAL, "未找到RDP安全层配置或未启用远程桌面"
    if m.group(1) in ("1", "2"):
        return STATUS_PASS, "RDP安全层已启用(SSL/TLS)"
    return STATUS_WARN, "RDP安全层为Native RDP加密，建议要求NLA+SSL"




# ---------------- 网络设备密码策略 runner ----------------

def check_net_device_pwd():
    """网络设备（防火墙/路由器/交换机）密码策略自动核查"""
    if _device_configured():
        host = (_NET_CONF.get("host") or _NET_CONF.get("snmp_host") or "").strip()
        return STATUS_MANUAL, (
            "目标为网络设备 %s。请在设备上核查：AAA/TACACS+/RADIUS 集中认证、"
            "密码长度≥8+复杂度≥3类+有效期≤90天、登录失败≥5次锁定、"
            "禁用默认口令、SSH v2 only、SNMP v3 authPriv。" % host)
    msgs, status = [], STATUS_MANUAL
    # 1. SSH 弱 KEX/算法探测（服务端如果开了 diffie-hellman-group1-sha1 这种就是不安全）
    rc, out = run_cmd(["bash", "-c",
        "ssh -o BatchMode=yes -o ConnectTimeout=3 -o KexAlgorithms=+diffie-hellman-group1-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o PreferredAuthentications=none localhost 2>&1 | head -5"])
    if rc == 255 and ("Protocol mismatch" in out or "refused" in out or "Connection closed" in out):
        msgs.append("✅ SSH 服务端拒绝 weak KEX（如 group1-sha1）")
    elif "Connection refused" in out:
        msgs.append("SSH 端口未监听本机（正常，网络设备另有入口）")
    else:
        msgs.append("⚠️ 本机 SSH 可能允许 weak KEX（请核查 sshd_config KexAlgorithms）")
        status = STATUS_WARN
    # 2. Telnet 明文检测
    rc2, _ = run_cmd(["bash", "-c", "timeout 2 bash -c 'echo quit | nc -w1 localhost 23' 2>/dev/null"])
    rc2b, _ = run_cmd(["ss", "-tlnp"])
    if rc2b == 0 and ":23 " in (rc2b or ""):
        msgs.append("❌ Telnet(23) 明文协议仍在监听！"); status = STATUS_FAIL
    # 3. SNMP v1/v2c 弱 community（主机侧监听）
    if rc2b == 0 and ":161 " in (rc2b or ""):
        rc3, out3 = run_cmd(["snmpwalk", "-v2c", "-c", "public", "-t", "1", "localhost", "1.3.6.1.2.1.1.1.0"],
                             timeout=5)
        if rc3 == 0 and "sysDescr" in (out3 or ""):
            msgs.append("❌ SNMP v2c 暴露，public community 可读系统信息"); status = STATUS_FAIL
        else:
            msgs.append("SNMP v2c 未用默认 public community")
    # 4. 主机侧 sshd 配置检查（作为网络设备 SSH 配置的参考基线）
    rc4, sshd = run_cmd(["cat", "/etc/ssh/sshd_config"])
    if rc4 == 0:
        if re.search(r"KexAlgorithms.*diffie-hellman-group1\b", sshd, re.I):
            msgs.append("⚠️ sshd 启用 weak KEX diffie-hellman-group1"); status = STATUS_WARN
        if re.search(r"Ciphers.*3des|Ciphers.*aes128-cbc", sshd, re.I):
            msgs.append("⚠️ sshd 启用 3DES/CBC 弱加密"); status = STATUS_WARN
        if re.search(r"PasswordAuthentication\s+yes", sshd, re.I):
            msgs.append("⚠️ sshd 允许密码认证（建议改用密钥+禁用密码或仅二次因素）")
    # 5. 核心提示
    msgs.append("【网络设备必查项】请在防火墙/路由/交换机上人工核查以下密码策略：")
    msgs.append("  ① AAA/TACACS+/RADIUS 认证服务器已配置（非本地账户）")
    msgs.append("  ② 密码长度≥8、复杂度≥3 类字符、有效期≤90 天、历史≥5 次")
    msgs.append("  ③ 登录失败≥5 次后账户锁定（Cisco: aaa authentication login default lockout 5）")
    msgs.append("  ④ enable/vty/console 各层独立强口令，禁用默认 cisco/admin/sysadmin")
    msgs.append("  ⑤ VTY/console 登录超时≤10 分钟；SSH v2 only，禁用 Telnet")
    msgs.append("  ⑥ SNMP v3 仅用 authPriv（SHA+AES），禁用 v1/v2c public community")
    return status, "；".join(msgs)


def check_net_device_pwd_win():
    """Windows: 网络设备密码策略"""
    if _device_configured():
        host = (_NET_CONF.get("host") or _NET_CONF.get("snmp_host") or "").strip()
        return STATUS_MANUAL, (
            "目标为网络设备 %s。请在设备上核查：AAA/TACACS+/RADIUS 集中认证、"
            "密码长度≥8+复杂度≥3类+有效期≤90天、登录失败≥5次锁定、"
            "禁用默认口令、SSH v2 only、SNMP v3 authPriv。" % host)
    msgs, status = [], STATUS_MANUAL
    # Windows 作为网络设备的辅助检查：RDP NLA / SSH / WinRM
    rc, out = run_powershell(
        "try{$c=Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | "
        "Where-Object {$_.DisplayName -match 'Telnet|SNMP|TFTP|TACACS'} | Select-Object DisplayName}catch{'ERR'}")
    if rc == 0 and out.strip() and "ERR" not in out:
        msgs.append("⚠️ 防火墙出站允许明文协议: %s" % out.strip().splitlines()[0][:100])
        status = STATUS_WARN
    # RDP 密码策略（本地安全账户策略已覆盖，这里只补充网络设备提示）
    msgs.append("【网络设备必查项】请在防火墙/路由/交换机上人工核查：")
    msgs.append("  ① AAA/TACACS+/RADIUS 集中认证")
    msgs.append("  ② 密码长度≥8、复杂度≥3 类、有效期≤90 天、历史≥5 次")
    msgs.append("  ③ 登录失败≥5 次锁定（Cisco lockout；H3C password-control；Huawei lockout）")
    msgs.append("  ④ 各管理口独立强口令，禁用默认 cisco/admin")
    msgs.append("  ⑤ SSH v2 only，禁用 Telnet；SNMP v3 authPriv")
    return status, "；".join(msgs)


# ---------------- 应用层密码策略 runner ----------------

def check_app_pwd_policy():
    """应用层密码策略（业务应用自身的登录密码策略） — 人工核查 + 辅助证据"""
    msgs = []
    # 辅助证据：看看有没有常见应用的配置文件泄露密码策略
    import glob, os
    for pattern, hint in [
        ("/etc/*-server/conf.d/*users*", "应用配置文件中的用户/密码策略"),
        ("/var/www/**/*config*.php", "PHP 应用 config.php 中的加密方式"),
        ("/opt/**/*.yml", "YAML 应用配置文件"),
    ]:
        files = glob.glob(pattern, recursive=True)[:3]
        for fp in files:
            try:
                txt = open(fp, encoding='utf-8', errors='ignore').read(2000)
                if re.search(r"password.*\$\d+\$|bcrypt|argon2|PBKDF2", txt, re.I):
                    msgs.append("✅ %s 检测到安全哈希密码存储" % os.path.basename(fp))
                elif re.search(r"password\s*=\s*['\"][^'\"]{4,16}['\"]", txt, re.I):
                    msgs.append("⚠️ %s 可能存在明文/弱加密密码" % os.path.basename(fp))
            except Exception: pass
    msgs.append("【应用层必查项】请人工核查业务应用登录密码策略：")
    msgs.append("  ① 注册/改密页面强制：长度≥8 + 大小写+数字+特殊字符中至少3类")
    msgs.append("  ② 密码有效期≤90 天，历史密码不能复用最近 5 次")
    msgs.append("  ③ 登录失败≥5 次锁定账户≥30 分钟（或验证码）")
    msgs.append("  ④ 密码存储用 bcrypt/argon2/PBKDF2 加盐哈希（禁止明文/MD5/SHA1）")
    msgs.append("  ⑤ 登录会话超时≤30 分钟；敏感操作需二次验证（短信/邮箱/MFA）")
    msgs.append("  ⑥ 提供『忘记密码』安全重置流程（邮件/验证码+身份验证）")
    return STATUS_MANUAL, "；".join(msgs)


def check_app_pwd_policy_win():
    """Windows 应用层密码策略"""
    msgs = ["【应用层必查项】请人工核查业务应用登录密码策略：",
            "  ① 注册/改密页面强制复杂度（≥8位+3类字符）",
            "  ② 密码有效期≤90天，历史≥5次不能复用",
            "  ③ 登录失败≥5次锁定≥30分钟",
            "  ④ 密码存储用 bcrypt/argon2/PBKDF2（禁止明文/MD5）",
            "  ⑤ 会话超时≤30分钟；敏感操作二次验证(MFA)",
            "  ⑥ 提供安全的密码重置流程"]
    return STATUS_MANUAL, "；".join(msgs)


def _device_checks_win():
    """已指定网络设备时：只做设备直连核查，不混入本机 Windows 主机项"""
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        W("N-D1", "网络设备访问控制", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "交换机/防火墙安全区域划分与访问控制策略",
          "核查网络设备ACL、区域划分与管理口隔离", None),
        W("N-D2", "网络设备ACL策略", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "边界设备 ACL 应默认拒绝、删除冗余规则、限制源/目的/端口/协议",
          "登录设备执行 show access-lists 解析 ACL", check_network_acl_win),
        W("N-D3", "ACL 五元组细化控制", CAT_NET, LEVEL_ALL, "8.1.3.2 c)",
          "边界 ACL 按源/目的地址+端口+协议做细化控制",
          "登录设备核查 ACL 是否含 address pair 与 dport 条件", check_netdev_acl_5tuple),
        W("N-D4", "应用层协议过滤(三级)", CAT_NET, LEVEL_L3, "8.1.3.2 d)",
          "三级系统边界应具备应用层协议过滤能力（WAF/应用识别/ALG）",
          "在边界启用 WAF/应用识别/ALG 或前置 WAF", check_netdev_app_filter),
        W("N-D5", "边界攻击记录与报警", CAT_NET, LEVEL_ALL, "8.1.3.3 b)",
          "边界设备记录攻击事件并可实时告警",
          "启用 IPS/IDS/抗DDoS 与日志 syslog 外送告警", check_netdev_intrusion_alarm),
        W("N-D6", "边界恶意代码/钓鱼防御(三级)", CAT_NET, LEVEL_L3, "8.1.3.3 c)",
          "三级系统主要节点具备恶意代码与钓鱼防御",
          "边界部署防病毒网关/内容安全/沙箱/威胁情报", check_netdev_border_av),
        W("N-D7", "边界审计留存≥6个月", CAT_NET, LEVEL_ALL, "8.1.3.4 a)",
          "边界设备审计日志留存≥6个月",
          "配置远程 syslog 集中留存，日志服务器保留≥180天", check_netdev_audit_retention),
        W("N-D8", "仅通过管理口/管理网段管理设备", CAT_NET, LEVEL_ALL, "8.1.3.4 b)",
          "网络设备管理面仅允许管理网段访问，禁用公网管理",
          "VTY/管理接口配置 access-class 限制来源，仅允许 SSH", check_netdev_mgmt_isolation),
        W("N-D9", "网络设备审计集中管理(三级)", CAT_NET, LEVEL_L3, "8.1.3.4 c)",
          "三级系统网络设备审计日志集中收集分析",
          "统一送 syslog/日志审计平台", check_netdev_audit_central),
        W("N-D10", "边界恶意代码检测清除", CAT_NET, LEVEL_ALL, "8.1.3.5 a)",
          "边界处检测并清除恶意代码",
          "部署防病毒网关/内容过滤/附件过滤", check_netdev_malware_clean),
        W("N-D11", "边界设备可信验证(三级)", CAT_NET, LEVEL_L3, "8.1.3.6 a)",
          "三级系统边界设备固件/镜像可信验证",
          "启用 Secure Boot/镜像签名校验/可信启动", check_netdev_trusted_boot),
        W("N-D12", "边界设备与链路冗余", CAT_NET, LEVEL_ALL, "8.1.2.1 a)",
          "边界关键设备与链路冗余（双机/双线/堆叠）",
          "部署 HSRP/VRRP/堆叠或双链路", check_netdev_redundancy),
        W("N-D13", "网络设备密码策略", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
          "AAA 集中认证；密码长度≥8+复杂度≥3类+有效期≤90天+登录失败≥5次锁定；禁用默认口令；SSH v2 only；SNMP v3 authPriv",
          "登录设备核查 AAA、密码策略、登录锁定与管理协议",
          check_net_device_pwd_win),
    ]


def _device_checks_linux():
    """Linux 扫描端 + 已指定网络设备时：只做设备直连核查"""
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        W("N-D1", "网络设备访问控制", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "交换机/防火墙安全区域划分与访问控制策略",
          "核查网络设备ACL、区域划分与管理口隔离", None),
        W("N-D2", "网络设备ACL策略", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "边界设备 ACL 应默认拒绝、删除冗余规则、限制源/目的/端口/协议",
          "登录设备执行 show access-lists 解析 ACL", check_network_acl),
        W("N-D3", "ACL 五元组细化控制", CAT_NET, LEVEL_ALL, "8.1.3.2 c)",
          "边界 ACL 按源/目的地址+端口+协议做细化控制",
          "登录设备核查 ACL 是否含 address pair 与 dport 条件", check_netdev_acl_5tuple),
        W("N-D4", "应用层协议过滤(三级)", CAT_NET, LEVEL_L3, "8.1.3.2 d)",
          "三级系统边界应具备应用层协议过滤能力（WAF/应用识别/ALG）",
          "在边界启用 WAF/应用识别/ALG 或前置 WAF", check_netdev_app_filter),
        W("N-D5", "边界攻击记录与报警", CAT_NET, LEVEL_ALL, "8.1.3.3 b)",
          "边界设备记录攻击事件并可实时告警",
          "启用 IPS/IDS/抗DDoS 与日志 syslog 外送告警", check_netdev_intrusion_alarm),
        W("N-D6", "边界恶意代码/钓鱼防御(三级)", CAT_NET, LEVEL_L3, "8.1.3.3 c)",
          "三级系统主要节点具备恶意代码与钓鱼防御",
          "边界部署防病毒网关/内容安全/沙箱/威胁情报", check_netdev_border_av),
        W("N-D7", "边界审计留存≥6个月", CAT_NET, LEVEL_ALL, "8.1.3.4 a)",
          "边界设备审计日志留存≥6个月",
          "配置远程 syslog 集中留存，日志服务器保留≥180天", check_netdev_audit_retention),
        W("N-D8", "仅通过管理口/管理网段管理设备", CAT_NET, LEVEL_ALL, "8.1.3.4 b)",
          "网络设备管理面仅允许管理网段访问，禁用公网管理",
          "VTY/管理接口配置 access-class 限制来源，仅允许 SSH", check_netdev_mgmt_isolation),
        W("N-D9", "网络设备审计集中管理(三级)", CAT_NET, LEVEL_L3, "8.1.3.4 c)",
          "三级系统网络设备审计日志集中收集分析",
          "统一送 syslog/日志审计平台", check_netdev_audit_central),
        W("N-D10", "边界恶意代码检测清除", CAT_NET, LEVEL_ALL, "8.1.3.5 a)",
          "边界处检测并清除恶意代码",
          "部署防病毒网关/内容过滤/附件过滤", check_netdev_malware_clean),
        W("N-D11", "边界设备可信验证(三级)", CAT_NET, LEVEL_L3, "8.1.3.6 a)",
          "三级系统边界设备固件/镜像可信验证",
          "启用 Secure Boot/镜像签名校验/可信启动", check_netdev_trusted_boot),
        W("N-D12", "边界设备与链路冗余", CAT_NET, LEVEL_ALL, "8.1.2.1 a)",
          "边界关键设备与链路冗余（双机/双线/堆叠）",
          "部署 HSRP/VRRP/堆叠或双链路", check_netdev_redundancy),
        W("N-D13", "网络设备密码策略", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
          "AAA 集中认证；密码长度≥8+复杂度≥3类+有效期≤90天+登录失败≥5次锁定；禁用默认口令；SSH v2 only；SNMP v3 authPriv",
          "登录设备核查 AAA、密码策略、登录锁定与管理协议",
          check_net_device_pwd),
    ]


def build_checks(platform):
    W = lambda *a, **k: CheckItem(*a, **k)
    if _device_configured():
        return _device_checks_win() if platform == "windows" else _device_checks_linux()
    if platform == "windows":
        return [
            W("N-W1", "IP路由转发关闭", CAT_NET, LEVEL_ALL, "8.1.3.1 a)",
              "非路由器主机应关闭IP转发", "设置IPEnableRouter=0", check_win_ip_forward),
            W("N-W2", "防火墙默认入站拒绝", CAT_NET, LEVEL_ALL, "8.1.3.2 a)",
              "默认入站策略为Block，仅放行必要端口",
              "组策略/防火墙策略配置默认入站=阻止", check_win_firewall_default),
            W("N-W3", "对外监听端口最小化", CAT_NET, LEVEL_ALL, "8.1.3.1 b)",
              "数据库与高危服务不直接对外暴露",
              "绑定127.0.0.1或通过防火墙限制访问源", check_win_exposed_ports),
            W("N-W4", "远程管理通道加密", CAT_NET, LEVEL_ALL, "8.1.2.2 a)",
              "RDP/WinRM采用SSL/TLS等加密传输",
              "启用RDP的SSL安全层与NLA，WinRM使用HTTPS(5986)", check_win_rdp_security),
            W("N-W5", "网络设备访问控制", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
              "交换机/防火墙安全区域划分与访问控制策略",
              "核查网络设备ACL、区域划分与管理口隔离", None),
            W("N-W6", "边界与链路冗余", CAT_NET, LEVEL_L3, "8.1.2.1 b)",
              "三级系统边界设备与链路冗余", "关键设备/链路双机或双线部署", None),

            # 防火墙 egress/ACL (新增)
            W("N-W7", "防火墙出口(e-gress)策略", CAT_NET, LEVEL_ALL, "8.1.3.1 c)",
              "限制内部用户非授权外联（VPN/TOR/SOCKS代理等）",
              "Windows Defender 防火墙 egress 策略非 ALLOW；网关/边界设备 egress ACL 限制",
              check_firewall_egress_win),
            W("N-W8", "网络设备ACL策略", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
              "边界设备 ACL 应默认拒绝、删除冗余规则、限制源/目的/端口/协议",
              "在界面填写设备 IP/SSH 账号/厂商，工具自动登录执行 show access-lists 解析 ACL",
              check_network_acl_win),
            W("N-W9", "内部用户非授权外联管控", CAT_NET, LEVEL_L3, "8.1.3.1 d)",
              "三级系统应检测内网用户非法外联（绕过边界防火墙访问外网）",
              "在网关设备上配置检测规则或流量监控，阻止 VPN/代理工具出站",
              check_internal_outbound_win),
            # 网络设备密码策略 + 应用层密码策略
            W("N-WP1", "网络设备(防火墙/路由/交换)密码策略", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
              "AAA 集中认证；密码长度≥8+复杂度≥3类+有效期≤90天+登录失败≥5次锁定；禁用默认口令；SSH v2 only；SNMP v3 authPriv",
              "在防火墙/路由/交换机上配置 AAA/TACACS+、密码策略、登录锁定、禁用 Telnet/SNMP v1/v2c",
              check_net_device_pwd_win),
            W("N-WP2", "应用层密码策略(登录/改密/重置)", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
              "应用登录强制密码复杂度≥8位+3类字符；有效期≤90天；历史≥5次不能复用；登录失败锁定；密码存储 bcrypt/argon2",
              "人工核查业务应用注册/改密/密码重置页面、数据库密码存储方式、会话超时设置",
              check_app_pwd_policy_win),
            # ===== 网络设备直连（SSH + SNMP）=====
            W("N-W10", "ACL 五元组细化控制", CAT_NET, LEVEL_ALL, "8.1.3.2 c)",
              "边界 ACL 按源/目的地址+端口+协议做细化控制",
              "登录设备核查 ACL 是否含 address pair 与 dport 条件", check_netdev_acl_5tuple),
            W("N-W11", "应用层协议过滤(三级)", CAT_NET, LEVEL_L3, "8.1.3.2 d)",
              "三级系统边界应具备应用层协议过滤能力（WAF/应用识别/ALG）",
              "在边界启用 WAF/应用识别/ALG 或前置 WAF", check_netdev_app_filter),
            W("N-W12", "边界攻击记录与报警", CAT_NET, LEVEL_ALL, "8.1.3.3 b)",
              "边界设备记录攻击事件并可实时告警",
              "启用 IPS/IDS/抗DDoS 与日志 syslog 外送告警", check_netdev_intrusion_alarm),
            W("N-W13", "边界恶意代码/钓鱼防御(三级)", CAT_NET, LEVEL_L3, "8.1.3.3 c)",
              "三级系统主要节点具备恶意代码与钓鱼防御",
              "边界部署防病毒网关/内容安全/沙箱/威胁情报", check_netdev_border_av),
            W("N-W14", "边界审计留存≥6个月", CAT_NET, LEVEL_ALL, "8.1.3.4 a)",
              "边界设备审计日志留存≥6个月",
              "配置远程 syslog 集中留存，日志服务器保留≥180天", check_netdev_audit_retention),
            W("N-W15", "仅通过管理口/管理网段管理设备", CAT_NET, LEVEL_ALL, "8.1.3.4 b)",
              "网络设备管理面仅允许管理网段访问，禁用公网管理",
              "VTY/管理接口配置 access-class 限制来源，仅允许 SSH", check_netdev_mgmt_isolation),
            W("N-W16", "网络设备审计集中管理(三级)", CAT_NET, LEVEL_L3, "8.1.3.4 c)",
              "三级系统网络设备审计日志集中收集分析",
              "统一送 syslog/日志审计平台", check_netdev_audit_central),
            W("N-W17", "边界恶意代码检测清除", CAT_NET, LEVEL_ALL, "8.1.3.5 a)",
              "边界处检测并清除恶意代码",
              "部署防病毒网关/内容过滤/附件过滤", check_netdev_malware_clean),
            W("N-W18", "边界设备可信验证(三级)", CAT_NET, LEVEL_L3, "8.1.3.6 a)",
              "三级系统边界设备固件/镜像可信验证",
              "启用 Secure Boot/镜像签名校验/可信启动", check_netdev_trusted_boot),
            W("N-W19", "边界设备与链路冗余", CAT_NET, LEVEL_ALL, "8.1.2.1 a)",
              "边界关键设备与链路冗余（双机/双线/堆叠）",
              "部署 HSRP/VRRP/堆叠或双链路", check_netdev_redundancy),
        ]
    return [
        W("N-1", "IP路由转发关闭", CAT_NET, LEVEL_ALL, "8.1.3.1 a)",
          "非路由器主机 net.ipv4.ip_forward=0",
          "sysctl -w net.ipv4.ip_forward=0 并写入/etc/sysctl.conf", check_ip_forward),
        W("N-2", "SYN Flood防护", CAT_NET, LEVEL_ALL, "8.1.3.3 a)",
          "net.ipv4.tcp_syncookies=1",
          "sysctl -w net.ipv4.tcp_syncookies=1", check_syncookies),
        W("N-3", "禁用ICMP重定向/源路由", CAT_NET, LEVEL_ALL, "8.1.3.2 a)",
          "accept_redirects=0、accept_source_route=0",
          "sysctl.conf中关闭all/default的accept_redirects与accept_source_route", check_redirects),
        W("N-4", "主机防火墙默认拒绝", CAT_NET, LEVEL_ALL, "8.1.3.2 a)",
          "firewalld/iptables默认策略为拒绝，仅放行必要服务",
          "配置默认DROP并添加最小化放行规则", check_firewall_default),
        W("N-5", "对外监听端口最小化", CAT_NET, LEVEL_ALL, "8.1.3.1 b)",
          "数据库(3306/5432/6379等)与高危服务不监听对外地址",
          "服务绑定127.0.0.1或防火墙限制来源IP", check_exposed_ports),
        W("N-6", "禁用Telnet/FTP明文服务", CAT_NET, LEVEL_ALL, "8.1.2.2 a)",
          "使用SSH/SFTP替代明文协议",
          "关闭telnet/ftp服务，改用SSH与SFTP", check_telnet_ftp),
        W("N-7", "网络设备访问控制", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "交换机/防火墙安全区域划分与访问控制策略",
          "核查网络设备ACL、区域划分与管理口隔离", check_network_device_config),
        W("N-8", "边界与链路冗余", CAT_NET, LEVEL_L3, "8.1.2.1 b)",
          "三级系统边界设备与链路冗余", "关键设备/链路双机或双线部署", check_boundary_redundancy),

        # 防火墙 egress/ACL (新增)
        W("N-9", "防火墙出口(e-gress)策略", CAT_NET, LEVEL_ALL, "8.1.3.1 c)",
          "限制内部用户非授权外联（VPN/TOR/SOCKS代理等）",
          "iptables/nftables OUTPUT 策略非 ACCEPT ANY→ANY；网关设备 egress ACL 限制",
          check_firewall_egress),
        W("N-10", "网络设备ACL策略", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "边界设备 ACL 应默认拒绝、删除冗余规则、限制源/目的/端口/协议",
          "在界面填写设备 IP/SSH 账号/厂商，工具自动登录执行 show access-lists 解析 ACL",
          check_network_acl),
        W("N-11", "内部用户非授权外联管控", CAT_NET, LEVEL_L3, "8.1.3.1 d)",
          "三级系统应检测内网用户非法外联（绕过边界防火墙访问外网）",
          "在网关设备上配置 egress 规则或流量监控，阻止 VPN/代理工具出站",
          check_internal_outbound),
        # 网络设备密码策略 + 应用层密码策略
        W("N-P1", "网络设备(防火墙/路由/交换)密码策略", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
          "AAA 集中认证；密码长度≥8+复杂度≥3类+有效期≤90天+登录失败≥5次锁定；禁用默认口令；SSH v2 only；SNMP v3 authPriv",
          "在防火墙/路由/交换机上配置 AAA/TACACS+、密码策略、登录锁定、禁用 Telnet/SNMP v1/v2c",
          check_net_device_pwd),
        W("N-P2", "应用层密码策略(登录/改密/重置)", CAT_NET, LEVEL_ALL, "8.1.4.1 a)",
          "应用登录强制密码复杂度≥8位+3类字符；有效期≤90天；历史≥5次不能复用；登录失败锁定；密码存储 bcrypt/argon2",
          "人工核查业务应用注册/改密/密码重置页面、密码存储哈希方式；辅助证据扫描配置文件弱密码",
          check_app_pwd_policy),
        # ===== 网络设备直连（SSH + SNMP）=====
        W("N-12", "ACL 五元组细化控制", CAT_NET, LEVEL_ALL, "8.1.3.2 c)",
          "边界 ACL 按源/目的地址+端口+协议做细化控制",
          "登录设备核查 ACL 是否含 address pair 与 dport 条件", check_netdev_acl_5tuple),
        W("N-13", "应用层协议过滤(三级)", CAT_NET, LEVEL_L3, "8.1.3.2 d)",
          "三级系统边界应具备应用层协议过滤能力（WAF/应用识别/ALG）",
          "在边界启用 WAF/应用识别/ALG 或前置 WAF", check_netdev_app_filter),
        W("N-14", "边界攻击记录与报警", CAT_NET, LEVEL_ALL, "8.1.3.3 b)",
          "边界设备记录攻击事件并可实时告警",
          "启用 IPS/IDS/抗DDoS 与日志 syslog 外送告警", check_netdev_intrusion_alarm),
        W("N-15", "边界恶意代码/钓鱼防御(三级)", CAT_NET, LEVEL_L3, "8.1.3.3 c)",
          "三级系统主要节点具备恶意代码与钓鱼防御",
          "边界部署防病毒网关/内容安全/沙箱/威胁情报", check_netdev_border_av),
        W("N-16", "边界审计留存≥6个月", CAT_NET, LEVEL_ALL, "8.1.3.4 a)",
          "边界设备审计日志留存≥6个月",
          "配置远程 syslog 集中留存，日志服务器保留≥180天", check_netdev_audit_retention),
        W("N-17", "仅通过管理口/管理网段管理设备", CAT_NET, LEVEL_ALL, "8.1.3.4 b)",
          "网络设备管理面仅允许管理网段访问，禁用公网管理",
          "VTY/管理接口配置 access-class 限制来源，仅允许 SSH", check_netdev_mgmt_isolation),
        W("N-18", "网络设备审计集中管理(三级)", CAT_NET, LEVEL_L3, "8.1.3.4 c)",
          "三级系统网络设备审计日志集中收集分析",
          "统一送 syslog/日志审计平台", check_netdev_audit_central),
        W("N-19", "边界恶意代码检测清除", CAT_NET, LEVEL_ALL, "8.1.3.5 a)",
          "边界处检测并清除恶意代码",
          "部署防病毒网关/内容过滤/附件过滤", check_netdev_malware_clean),
        W("N-20", "边界设备可信验证(三级)", CAT_NET, LEVEL_L3, "8.1.3.6 a)",
          "三级系统边界设备固件/镜像可信验证",
          "启用 Secure Boot/镜像签名校验/可信启动", check_netdev_trusted_boot),
        W("N-21", "边界设备与链路冗余", CAT_NET, LEVEL_ALL, "8.1.2.1 a)",
          "边界关键设备与链路冗余（双机/双线/堆叠）",
          "部署 HSRP/VRRP/堆叠或双链路", check_netdev_redundancy),
    ]
