# -*- coding: utf-8 -*-
"""应用与数据安全检测（等保2.0 安全计算环境中的应用与数据部分）"""
import re

from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_APP, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, run_powershell
from .db_checks import _listen

_APP_CONF = {}


def set_app_conf(conf):
    """设置应用访问配置（协议/端口/路径），由 engine 每轮注入"""
    global _APP_CONF
    _APP_CONF = dict(conf or {})


def get_app_conf():
    return _APP_CONF


def _conf_port():
    p = str(get_app_conf().get("port") or "").strip()
    return p or None


def _conf_scheme(port):
    s = str(get_app_conf().get("scheme") or "auto").lower()
    if s in ("http", "https"):
        return s
    return "https" if str(port) in ("443", "8443") else "http"


def _app_path():
    p = str(get_app_conf().get("path") or "").strip()
    if not p:
        return "/"
    return p if p.startswith("/") else "/" + p


def _app_url(port):
    return "%s://127.0.0.1:%s%s" % (_conf_scheme(port), port, _app_path())


def _web_port():
    rows = _listen()
    for want in ("443", "8443", "80", "8080"):
        for h, p in rows:
            if p == want:
                return want
    return None


def check_https_enabled():
    port = _conf_port() or _web_port()
    if port is None:
        return STATUS_MANUAL, "未检测到Web服务端口，如应用为C/S架构请人工核查传输加密"
    if _conf_scheme(port) == "https" or port in ("443", "8443"):
        return STATUS_PASS, "应用已启用HTTPS(%s端口)" % port
    return STATUS_WARN, "仅检测到HTTP(%s端口)，应用通信未加密，建议启用HTTPS" % port


def check_security_headers():
    port = _conf_port() or _web_port()
    if port is None:
        return STATUS_MANUAL, "未检测到Web服务端口"
    url = _app_url(port)
    rc, out = run_cmd(["curl", "-sI", "-k", "-m", "5", url], timeout=12)
    if rc != 0 or not out.strip():
        return STATUS_MANUAL, "无法获取HTTP响应头（可能未安装curl或站点不可达）"
    text = out.lower()
    checks = {
        "X-Frame-Options": "x-frame-options" in text,
        "X-Content-Type-Options": "x-content-type-options" in text,
        "Content-Security-Policy": "content-security-policy" in text,
        "Strict-Transport-Security": "strict-transport-security" in text,
    }
    missing = [k for k, v in checks.items() if not v]
    if len(missing) >= 4:
        return STATUS_FAIL, "未设置任何安全响应头(X-Frame-Options/CSP/HSTS等)，存在点击劫持与注入风险"
    if missing:
        return STATUS_WARN, "缺少安全响应头: %s" % "、".join(missing)
    return STATUS_PASS, "已设置X-Frame-Options、CSP、HSTS等安全响应头"


def check_tls_version():
    port = _conf_port() or _web_port()
    if port is None:
        return STATUS_MANUAL, "未检测到Web服务端口"
    if _conf_scheme(port) == "http":
        return STATUS_MANUAL, "当前按 HTTP 访问应用，未启用 TLS；如已部署 HTTPS 请选择协议 HTTPS 并填写端口"
    cmd = ("echo | openssl s_client -connect 127.0.0.1:%s -tls1 2>/dev/null "
           "| grep -c 'Cipher is'" % port)
    rc, out = run_cmd(cmd, timeout=15)
    if rc != 0 or not out.strip():
        return STATUS_MANUAL, "无法通过openssl探测TLS版本"
    try:
        supports_tls10 = int(out.strip().splitlines()[-1]) > 0
    except ValueError:
        return STATUS_MANUAL, "无法解析TLS探测结果"
    if supports_tls10:
        return STATUS_WARN, "服务端仍支持TLSv1.0，建议仅启用TLSv1.2/1.3"
    return STATUS_PASS, "服务端已禁用TLSv1.0，使用TLSv1.2/1.3"


def check_data_encryption():
    rc, out = run_cmd(["bash", "-c",
                       "lsblk -f -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | grep -i crypto; "
                       "dmsetup ls --target crypt 2>/dev/null"])
    if out.strip():
        return STATUS_PASS, "检测到块设备层加密(crypt/LUKS): %s" % out.strip().splitlines()[0][:80]
    return STATUS_MANUAL, "未检测到磁盘/文件系统加密；请核查重要数据是否采用应用层加密或脱敏"


def check_data_backup():
    return STATUS_MANUAL, "请人工核查重要数据备份策略、备份介质场外存放、定期恢复性测试记录"


def check_privacy():
    return STATUS_MANUAL, "请人工核查个人信息与敏感数据是否最小化采集、脱敏展示、授权访问并留存处理记录"


def check_app_auth():
    return STATUS_MANUAL, "请人工核查应用身份鉴别、会话管理与权限最小化（含默认账户、越权访问测试记录）"


def check_data_integrity():
    return STATUS_MANUAL, "请人工核查数据传输与存储完整性校验、剩余信息保护与安全删除机制"


def check_waf():
    return STATUS_MANUAL, "请人工核查是否部署WAF/IPS并开启Web攻击防护、漏洞防护与告警"


# ---------------- Windows ----------------

def check_win_https():
    port = _conf_port()
    if port:
        if _conf_scheme(port) == "https" or port in ("443", "8443"):
            return STATUS_PASS, "应用已启用HTTPS(%s端口)" % port
        return STATUS_WARN, "应用按HTTP端口(%s)访问，建议启用HTTPS" % port
    rc, out = run_powershell(
        "try{Get-NetTCPConnection -State Listen -ErrorAction Stop | "
        "Where-Object {$_.LocalPort -in 443,8443} | "
        "ForEach-Object {$_.LocalAddress+':'+$_.LocalPort}}catch{'ERR'}")
    rows = [l.strip() for l in out.splitlines() if l.strip() and l.strip() != "ERR"]
    if rows:
        return STATUS_PASS, "应用已启用HTTPS: %s" % "、".join(sorted(set(rows))[:5])
    ports = run_powershell("(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                           "Where-Object {$_.LocalPort -in 80,8080}).LocalPort -join ','")
    if ports[1].strip():
        return STATUS_WARN, "仅检测到HTTP端口(%s)，建议启用HTTPS" % ports[1].strip()
    return STATUS_MANUAL, "未检测到Web服务端口，如为C/S架构请人工核查传输加密"


def check_win_headers():
    url = _app_url(_conf_port() or "80")
    rc, out = run_powershell(
        "try{$r=Invoke-WebRequest -Uri '%s' -Method Head "
        "-UseBasicParsing -TimeoutSec 6 -ErrorAction Stop;"
        "($r.Headers.Keys -join ',')}catch{'ERR'}" % url)
    if "ERR" in out or not out.strip():
        return STATUS_MANUAL, "无法获取HTTP响应头（站点不可达或未部署Web）"
    low = out.lower()
    missing = [k for k in ("x-frame-options", "x-content-type-options",
                           "content-security-policy", "strict-transport-security")
               if k not in low]
    if len(missing) >= 4:
        return STATUS_FAIL, "未设置任何安全响应头，存在点击劫持与注入风险"
    if missing:
        return STATUS_WARN, "缺少安全响应头: %s" % "、".join(missing)
    return STATUS_PASS, "已设置主要HTTP安全响应头"


def check_bitlocker():
    rc, out = run_powershell(
        "try{$v=Get-BitLockerVolume -ErrorAction Stop;"
        "if($v){($v|ForEach-Object{$_.MountPoint+':'+$_.ProtectionStatus}) -join ','}else{'NONE'}}"
        "catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取BitLocker状态（可能非专业版系统）"
    if "NONE" in out or not out.strip():
        return STATUS_WARN, "未检测到BitLocker加密卷，请核查重要数据加密措施"
    if "On" in out:
        return STATUS_PASS, "检测到BitLocker加密卷: %s" % out.strip()[:100]
    return STATUS_WARN, "存在未加密磁盘卷: %s" % out.strip()[:100]


def build_checks(platform):
    W = lambda *a, **k: CheckItem(*a, **k)
    if platform == "windows":
        return [
            W("APP-W1", "应用传输加密(HTTPS)", CAT_APP, LEVEL_ALL, "8.1.4.8 a)",
              "应用采用HTTPS加密传输", "部署证书并强制HTTPS", check_win_https),
            W("APP-W2", "HTTP安全响应头", CAT_APP, LEVEL_ALL, "8.1.4.4 a)",
              "设置X-Frame-Options/CSP/HSTS等",
              "在IIS中配置响应头", check_win_headers),
            W("APP-W3", "数据存储加密", CAT_APP, LEVEL_L3, "8.1.4.8 b)",
              "重要数据加密存储", "启用BitLocker或应用层加密", check_bitlocker),
            W("APP-W4", "数据备份与恢复", CAT_APP, LEVEL_ALL, "8.1.4.9 a)",
              "定期备份并验证可恢复", "配置备份计划并定期恢复演练", None),
            W("APP-W5", "个人信息与敏感数据保护", CAT_APP, LEVEL_L3, "8.1.4.11 a)",
              "最小化采集、脱敏展示、授权访问", "建立数据分类分级与脱敏机制", None),
            W("APP-W6", "应用身份鉴别与权限", CAT_APP, LEVEL_ALL, "8.1.4.1 a)",
              "强鉴别、会话管理、权限最小化", "核查默认账户、越权与会话安全", None),
        ]
    return [
        W("APP-1", "应用传输加密(HTTPS)", CAT_APP, LEVEL_ALL, "8.1.4.8 a)",
          "应用通信采用HTTPS/TLS加密", "部署证书，强制HTTPS访问", check_https_enabled),
        W("APP-2", "HTTP安全响应头", CAT_APP, LEVEL_ALL, "8.1.4.4 a)",
          "设置X-Frame-Options/CSP/HSTS等安全头",
          "在Nginx/Apache中add_header配置", check_security_headers),
        W("APP-3", "TLS版本安全", CAT_APP, LEVEL_ALL, "8.1.2.2 a)",
          "禁用TLSv1.0/1.1，仅启用TLSv1.2/1.3", "调整ssl_protocols/cipher suite", check_tls_version),
        W("APP-4", "数据存储加密", CAT_APP, LEVEL_L3, "8.1.4.8 b)",
          "重要数据加密存储", "启用LUKS/dm-crypt或应用层加密", check_data_encryption),
        W("APP-5", "数据备份与恢复", CAT_APP, LEVEL_ALL, "8.1.4.9 a)",
          "定期备份、异地存放并验证恢复", "制定备份策略并定期恢复演练", check_data_backup),
        W("APP-6", "个人信息与敏感数据保护", CAT_APP, LEVEL_L3, "8.1.4.11 a)",
          "最小化采集、脱敏展示、授权访问", "建立数据分类分级与脱敏机制", check_privacy),
        W("APP-7", "应用身份鉴别与权限最小化", CAT_APP, LEVEL_ALL, "8.1.4.1 d)",
          "强鉴别、会话安全、越权防护", "核查默认账户、会话超时与水平越权", check_app_auth),
        W("APP-8", "数据完整性保护", CAT_APP, LEVEL_ALL, "8.1.4.7 a)",
          "传输与存储完整性校验", "启用TLS、校验和与数字签名", check_data_integrity),
        W("APP-9", "Web攻击防护(WAF/IPS)", CAT_APP, LEVEL_L3, "8.1.3.3 a)",
          "部署WAF/IPS防护SQL注入、XSS等", "部署WAF并开启防护规则与告警", check_waf),
    ]
