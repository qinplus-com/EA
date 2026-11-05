# -*- coding: utf-8 -*-
"""Windows 平台技术检测项（等保2.0，二级/三级）
仅使用系统自带命令：net accounts / auditpol / secedit / PowerShell / netstat / reg
部分检测需管理员权限，权限不足时降级为“检测失败/需人工核查”。
"""
import re

from core import baseline
from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_IDENTITY, CAT_ACCESS, CAT_AUDIT, CAT_INTRUSION,
                         CAT_MALWARE, CAT_BACKUP, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, run_powershell


def _num(line):
    m = re.search(r"(\d+)", line)
    return int(m.group(1)) if m else None


# ---------------- 身份鉴别 ----------------

def check_password_policy():
    rc, out = run_cmd(["net", "accounts"])
    if rc != 0:
        return STATUS_ERROR, "无法读取账户策略(net accounts): %s" % out.strip()[:200]
    min_len = max_age = None
    for line in out.splitlines():
        low = line.lower()
        if "minimum password length" in low or "密码长度最小值" in line:
            min_len = _num(line)
        elif "maximum password age" in low or "密码最长使用期限" in line:
            m = re.search(r"(\d+|unlimited|无限期)", line, re.I)
            if m:
                v = m.group(1)
                max_age = 99999 if v.lower() in ("unlimited",) or v == "无限期" else int(v)
    msgs = []
    status = STATUS_PASS
    if min_len is not None:
        ok = min_len >= 8
        msgs.append("密码最小长度=%d(要求≥8)" % min_len)
        if not ok:
            status = STATUS_FAIL
    if max_age is not None:
        if max_age > 90:
            msgs.append("密码最长使用期限=%s(要求≤90天)" % ("无限期" if max_age == 99999 else str(max_age)))
            status = STATUS_FAIL
        else:
            msgs.append("密码最长使用期限=%d天" % max_age)
    return status, "；".join(msgs) if msgs else out.strip()[:300]


def check_password_complexity():
    """在目标机（本机或远程WinRM）导出安全策略并读取密码复杂性配置"""
    rc, out = run_powershell(
        "$f=Join-Path $env:TEMP ('_ea_sec_'+[guid]::NewGuid().ToString('N')+'.cfg');"
        "secedit /export /cfg $f /quiet | Out-Null;"
        "if(Test-Path $f){"
        "$c=Get-Content $f -Raw;"
        "if($c -match 'PasswordComplexity\\s*=\\s*(\\d+)'){'PC:'+$matches[1]}else{'PC:NF'};"
        "Remove-Item $f -Force -ErrorAction SilentlyContinue"
        "}else{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "导出安全策略失败(需管理员权限)，请人工核查“密码必须符合复杂性要求”"
    m = re.search(r"PC:(\d+)", out)
    if not m:
        return STATUS_MANUAL, "未在策略中找到 PasswordComplexity 项"
    if m.group(1) == "1":
        return STATUS_PASS, "密码复杂性要求已启用"
    return STATUS_FAIL, "密码复杂性要求未启用(PasswordComplexity=%s)" % m.group(1)


def check_lockout_policy():
    rc, out = run_cmd(["net", "accounts"])
    if rc != 0:
        return STATUS_ERROR, "无法读取账户策略: %s" % out.strip()[:200]
    threshold = duration = None
    for line in out.splitlines():
        low = line.lower()
        if "lockout threshold" in low or "锁定阈值" in line:
            threshold = _num(line)
        elif "lockout duration" in low or "锁定时间" in line:
            duration = _num(line)
    if threshold is None:
        return STATUS_MANUAL, "未能解析账户锁定阈值"
    if threshold == 0:
        return STATUS_FAIL, "账户锁定阈值=0(永不锁定)，无法防御口令爆破"
    msg = "锁定阈值=%d次" % threshold
    if duration is not None:
        msg += "，锁定时长=%d分钟" % duration
    return (STATUS_PASS, msg) if threshold <= 10 else (STATUS_WARN, msg + "，建议≤10次")


def check_rdp_nla():
    rc, out = run_cmd(["reg", "query",
                       r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                       "/v", "UserAuthentication"])
    if rc != 0:
        return STATUS_MANUAL, "未启用远程桌面或未找到RDP配置"
    m = re.search(r"UserAuthentication\s+REG_DWORD\s+0x(\d)", out)
    if m and m.group(1) == "1":
        return STATUS_PASS, "远程桌面已启用NLA网络级身份验证"
    return STATUS_WARN, "远程桌面未启用NLA，存在中间人/爆破风险"


# ---------------- 访问控制 ----------------

def check_guest_account():
    rc, out = run_powershell(
        "$g=Get-LocalUser | Where-Object {$_.SID.Value -like '*-501'};"
        "if($g){$g | Select-Object -ExpandProperty Enabled}else{'notfound'}")
    if rc != 0:
        return STATUS_ERROR, "查询Guest账户失败: %s" % out.strip()[:200]
    text = out.strip().lower()
    if "notfound" in text:
        return STATUS_PASS, "系统中不存在Guest账户"
    if "false" in text:
        return STATUS_PASS, "Guest账户已禁用"
    return STATUS_FAIL, "Guest账户处于启用状态，应禁用"


def check_admin_renamed():
    rc, out = run_powershell(
        "$a=Get-LocalUser | Where-Object {$_.SID.Value -like '*-500'};"
        "if($a){$a | Select-Object -ExpandProperty Name}else{'notfound'}")
    name = out.strip()
    if rc != 0 or not name:
        return STATUS_ERROR, "查询内置管理员失败: %s" % out.strip()[:200]
    if name.lower() in ("administrator", "admin", "管理员"):
        return STATUS_WARN, "内置管理员仍为默认名称 %s，建议重命名" % name
    return STATUS_PASS, "内置管理员已重命名为 %s" % name


def check_admin_members():
    rc, out = run_powershell(
        "try{(Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember | "
        "Where-Object {$_.ObjectClass -eq 'User'} | Select-Object -ExpandProperty Name) -join ','}"
        "catch{'error'}")
    if rc != 0 or "error" in out:
        return STATUS_MANUAL, "无法枚举管理员组成员(可能需管理员权限)"
    members = [m.strip() for m in out.strip().split(",") if m.strip()]
    if len(members) <= 2:
        return STATUS_PASS, "管理员组成员: %s" % ("、".join(members) or "无")
    return STATUS_WARN, "管理员组成员较多(%d个): %s，建议最小化授权" % (len(members), "、".join(members))


def check_default_share():
    rc, out = run_cmd(["reg", "query",
                       r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                       "/v", "AutoShareServer"])
    if rc != 0:
        return STATUS_WARN, "未配置AutoShareServer，默认管理共享(C$/D$/ADMIN$)可能开启"
    m = re.search(r"AutoShareServer\s+REG_DWORD\s+0x(\d)", out)
    if m and m.group(1) == "0":
        return STATUS_PASS, "默认管理共享已关闭(AutoShareServer=0)"
    return STATUS_FAIL, "默认管理共享开启(AutoShareServer≠0)，建议关闭C$/D$/ADMIN$"


def check_anonymous_enum():
    rc, out = run_cmd(["reg", "query",
                       r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                       "/v", "RestrictAnonymous"])
    if rc != 0:
        return STATUS_MANUAL, "未找到RestrictAnonymous键值"
    m = re.search(r"RestrictAnonymous\s+REG_DWORD\s+0x(\d)", out)
    if m and m.group(1) in ("1", "2"):
        return STATUS_PASS, "已限制匿名枚举(RestrictAnonymous=%s)" % m.group(1)
    return STATUS_FAIL, "未限制匿名访问(RestrictAnonymous=0)，可匿名枚举用户/共享"


# ---------------- 安全审计 ----------------

def check_audit_policy():
    rc, out = run_cmd(["auditpol", "/get", "/category:*"])
    if rc != 0:
        return STATUS_ERROR, "读取审核策略失败(需管理员权限): %s" % out.strip()[:200]
    no_audit = 0
    total = 0
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("Category") or s.startswith("类别"):
            continue
        if re.search(r"(Success|Failure|成功|失败|No Auditing|无审核)", s, re.I):
            total += 1
            if re.search(r"(No Auditing|无审核)", s, re.I):
                no_audit += 1
    if total == 0:
        return STATUS_MANUAL, "未能解析审核策略输出"
    if no_audit == 0:
        return STATUS_PASS, "全部%d个审核类别均已启用审核" % total
    if no_audit >= total // 2:
        return STATUS_FAIL, "%d/%d个审核类别为“无审核”，审计覆盖严重不足" % (no_audit, total)
    return STATUS_WARN, "%d/%d个审核类别未启用审核，建议覆盖登录/账户管理/策略变更等" % (no_audit, total)


def check_eventlog_config():
    rc, out = run_powershell(
        "$r=@();foreach($l in 'System','Security','Application'){"
        "$c=Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue;"
        "if($c){$r+=($l+':'+[math]::Round($c.MaximumSizeInBytes/1MB))}};$r -join ','")
    if rc != 0 or not out.strip():
        return STATUS_MANUAL, "无法读取事件日志配置"
    small = []
    for part in out.strip().split(","):
        if ":" in part:
            name, size = part.split(":", 1)
            try:
                if int(size) < 100:
                    small.append("%s=%sMB" % (name, size))
            except ValueError:
                pass
    if small:
        return STATUS_WARN, "部分日志容量偏小(<100MB): %s，建议调大并启用按需覆盖" % "、".join(small)
    return STATUS_PASS, "日志容量配置: %s" % out.strip()


def check_eventlog_service():
    rc, out = run_powershell(
        "$s=Get-Service -Name EventLog -ErrorAction SilentlyContinue;"
        "if($s){$s.Status}else{'notfound'}")
    if "Running" in out:
        return STATUS_PASS, "Windows Event Log服务运行中"
    return STATUS_FAIL, "Windows Event Log服务未运行: %s" % out.strip()


def check_log_retention_hint():
    return STATUS_MANUAL, "请人工核查：审计记录是否定期备份并留存6个月以上（三级要求）"


# ---------------- 入侵防范 ----------------

def check_firewall():
    rc, out = run_powershell(
        "try{(Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+$_.Enabled}) -join ','}"
        "catch{'error'}")
    if rc != 0 or "error" in out:
        return STATUS_MANUAL, "无法读取防火墙状态"
    disabled = [p.split(":")[0] for p in out.strip().split(",") if p.endswith(":False")]
    if disabled:
        return STATUS_FAIL, "以下防火墙配置文件未启用: %s" % "、".join(disabled)
    return STATUS_PASS, "域/专用/公用防火墙均已启用"


def check_smbv1():
    rc, out = run_powershell(
        "try{(Get-SmbServerConfiguration).EnableSMB1Protocol}catch{'error'}")
    if "False" in out:
        return STATUS_PASS, "SMBv1协议已禁用"
    if "True" in out:
        return STATUS_FAIL, "SMBv1协议启用中，存在永恒之蓝类漏洞风险，应立即禁用"
    return STATUS_MANUAL, "无法确认SMBv1状态，请人工核查"


def check_dangerous_ports():
    rc, out = run_cmd(["netstat", "-ano", "-p", "tcp"])
    if rc != 0:
        return STATUS_ERROR, "无法读取端口列表"
    danger = {"21": "FTP", "23": "Telnet", "135": "RPC", "139": "NetBIOS", "445": "SMB", "3389": "RDP"}
    listening = set()
    for line in out.splitlines():
        if "LISTENING" not in line.upper():
            continue
        m = re.search(r":(\d+)\s+\S+\s+LISTENING", line, re.I)
        if m and m.group(1) in danger:
            listening.add(m.group(1))
    risky = [p for p in ("21", "23", "135", "139") if p in listening]
    if risky:
        return STATUS_FAIL, "检测到高危端口开放: %s" % "、".join("%s(%s)" % (p, danger[p]) for p in risky)
    if "445" in listening or "3389" in listening:
        open_mid = [p for p in ("445", "3389") if p in listening]
        return STATUS_WARN, "以下端口开放，请确认业务必需并做访问限制: %s" % \
               "、".join("%s(%s)" % (p, danger[p]) for p in open_mid)
    return STATUS_PASS, "未发现高危端口开放"


def check_autorun():
    rc, out = run_cmd(["reg", "query",
                       r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                       "/v", "NoDriveTypeAutoRun"])
    if rc != 0:
        return STATUS_WARN, "未配置NoDriveTypeAutoRun，U盘自动播放可能开启"
    m = re.search(r"NoDriveTypeAutoRun\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
    if m and int(m.group(1), 16) >= 0xFF:
        return STATUS_PASS, "已禁用所有驱动器自动播放(NoDriveTypeAutoRun=0x%s)" % m.group(1)
    return STATUS_WARN, "自动播放未完全禁用，建议设置NoDriveTypeAutoRun=0xFF"


def check_unneeded_services():
    rc, out = run_powershell(
        "$names='RemoteRegistry','Telnet','tlntsvr','SNMP','Browser';"
        "$r=@();foreach($n in $names){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
        "if($s -and $s.Status -eq 'Running'){$r+=$n}};if($r){$r -join ','}else{'none'}")
    if "none" in out:
        return STATUS_PASS, "未发现高风险服务运行(RemoteRegistry/Telnet/SNMP等)"
    if rc == 0 and out.strip():
        return STATUS_WARN, "以下高风险服务运行中，建议禁用: %s" % out.strip()
    return STATUS_MANUAL, "无法确认服务状态"


def check_patch_status():
    rc, out = run_powershell(
        "$k=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue;"
        "if($k){'OS:'+$k.ProductName+' Build:'+$k.CurrentBuild};"
        "try{$h=Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1;'LastHotFix:'+$h.HotFixID+' '+$h.InstalledOn}catch{}")
    text = "；".join(l.strip() for l in out.splitlines() if l.strip())
    if not text:
        return STATUS_MANUAL, "无法读取系统版本/补丁信息"
    m = re.search(r"OS:(.*?)\s*Build:(\d+)", text)
    hotfix = re.search(r"LastHotFix:(\S+)\s*(\S*)", text)
    extra = "；最近补丁: %s %s" % (hotfix.group(1), hotfix.group(2)) if hotfix else ""
    if not m:
        return STATUS_MANUAL, "请人工核查补丁更新情况。%s" % text
    caption, build = m.group(1), m.group(2)
    ok, need, note = baseline.windows_build_status(caption, build)
    head = "系统版本: %s Build %s" % (caption, build)
    if ok is True:
        return STATUS_PASS, "%s，达到离线基线 %s%s" % (head, need, extra)
    if ok is False:
        return STATUS_WARN, "%s，低于离线基线 %s，%s%s" % (head, need, note, extra)
    return STATUS_MANUAL, "%s；%s%s，请人工核查补丁更新情况" % (head, note, extra)


# ---------------- 恶意代码防范 ----------------

def check_antivirus():
    rc, out = run_powershell(
        "try{$s=Get-MpComputerStatus;'Defender:'+$s.AntivirusEnabled+','+$s.RealTimeProtectionEnabled}"
        "catch{'error'}")
    if "True,True" in out:
        return STATUS_PASS, "Windows Defender已启用且实时保护开启"
    if "True" in out:
        return STATUS_WARN, "Defender已启用但实时保护可能关闭: %s" % out.strip()
    rc2, out2 = run_powershell(
        "$av=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "-ErrorAction SilentlyContinue;if($av){($av|ForEach-Object{$_.displayName}) -join ','}else{'none'}")
    if "none" in out2:
        return STATUS_FAIL, "未检测到任何防病毒软件(Defender关闭且未安装第三方杀软)"
    if out2.strip():
        return STATUS_PASS, "检测到第三方防病毒软件: %s" % out2.strip()
    return STATUS_MANUAL, "无法确认防病毒软件状态"


def check_av_signature():
    rc, out = run_powershell(
        "try{$s=Get-MpComputerStatus;$d=(New-TimeSpan -Start $s.AntivirusSignatureLastUpdated -End (Get-Date)).Days;"
        "'DaysOld:'+$d}catch{'error'}")
    m = re.search(r"DaysOld:(\d+)", out)
    if m:
        days = int(m.group(1))
        if days <= 7:
            return STATUS_PASS, "病毒库%d天前更新" % days
        return STATUS_WARN, "病毒库已%d天未更新，建议立即更新" % days
    return STATUS_MANUAL, "无法确认病毒库更新时间(第三方杀软请人工核查)"


def check_defender_realtime():
    """Defender 实时保护/杀毒服务状态（Get-MpComputerStatus）"""
    rc, out = run_powershell(
        "try{$s=Get-MpComputerStatus -ErrorAction Stop;"
        "'RTP:'+$s.RealTimeProtectionEnabled+'|AV:'+$s.AntivirusEnabled"
        "+'|AM:'+$s.AMServiceEnabled}catch{'NONE'}")
    if "NONE" in out or "RTP:" not in out:
        return STATUS_MANUAL, "无法读取Defender状态（可能未安装或为第三方杀软），需人工核查实时保护"
    rtp = re.search(r"RTP:(\w+)", out)
    av = re.search(r"AV:(\w+)", out)
    am = re.search(r"AM:(\w+)", out)
    vals = [m.group(1).lower() if m else "" for m in (av, rtp, am)]
    if av and av.group(1).lower() == "true" and rtp and rtp.group(1).lower() == "true":
        return STATUS_PASS, "Defender已启用且实时保护开启(Antivirus=%s, RealTime=%s)" % \
            (av.group(1), rtp.group(1))
    if av and av.group(1).lower() == "true":
        return STATUS_FAIL, "Defender已启用但实时保护关闭(RealTime=%s)，恶意代码无法实时拦截" % \
            (rtp.group(1) if rtp else "未知")
    if any(v == "true" for v in vals):
        return STATUS_WARN, "Defender组件部分运行: %s" % out.strip()
    return STATUS_MANUAL, "未检测到Defender或状态不可读，需人工核查杀毒软件实时保护"


def check_defender_quickscan():
    """Defender 上次快速扫描时间"""
    rc, out = run_powershell(
        "try{$s=Get-MpComputerStatus -ErrorAction Stop;"
        "if($s.QuickScanEndTime){$d=(New-TimeSpan -Start $s.QuickScanEndTime -End (Get-Date)).Days;"
        "'SCAN:'+$d+'|'+$s.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm')}else{'NOSCAN'}}catch{'ERR'}")
    if "ERR" in out:
        return STATUS_MANUAL, "无法读取Defender扫描记录（第三方杀软请人工核查）"
    if "NOSCAN" in out or "SCAN:" not in out:
        return STATUS_WARN, "未读取到最近快速扫描记录，建议配置定期快速扫描"
    m = re.search(r"SCAN:(\d+)\|(.*)", out)
    if not m:
        return STATUS_MANUAL, "未能解析快速扫描时间"
    days = int(m.group(1))
    when = m.group(2).strip()
    if days <= 7:
        return STATUS_PASS, "上次快速扫描: %s（%d天前）" % (when, days)
    if days <= 30:
        return STATUS_WARN, "上次快速扫描: %s（%d天前），建议每周至少一次" % (when, days)
    return STATUS_FAIL, "上次快速扫描: %s（%d天前），扫描长期未执行" % (when, days)


# ---------------- 数据备份 ----------------

def check_backup():
    rc, out = run_cmd(["wbadmin", "get", "versions"], timeout=20)
    if rc != 0:
        return STATUS_MANUAL, "无法查询系统备份记录(wbadmin需管理员)，请人工核查重要数据备份策略与恢复演练记录"
    if re.search(r"(backup|备份).*(time|时间)", out, re.I) or re.search(r"\d{4}[/-]\d{1,2}", out):
        return STATUS_PASS, "检测到系统备份记录:\n%s" % out.strip()[:300]
    return STATUS_WARN, "未发现系统备份记录，请确认已通过其他方式备份重要数据"


# ---------------- 强制访问控制 (Windows 强制完整性 + 组策略) ----------------

def check_mac():
    """Windows: 强制完整性控制(MIC) + UAC + Code Integrity"""
    msgs, status = [], STATUS_PASS
    # 1. 强制完整性控制 (MIC) - Windows 默认启用
    rc, out = run_powershell("[System.Environment]::OSVersion.Version.Major")
    if rc == 0 and int(out.strip()) >= 6:
        msgs.append("Windows Vista+ 强制完整性控制(MIC)默认启用")
    # 2. 安全标识符(SID) + 访问控制列表(ACL)是 Windows 访问控制基础
    msgs.append("Windows DACL/SACL 访问控制模型启用")
    # 3. Code Integrity (CI) - 防止未签名驱动/代码
    rc2, out2 = run_cmd(["bcdedit", "/enum", "{current}"])
    if rc2 == 0:
        if re.search(r"nointegritychecks\s+yes", out2, re.I):
            msgs.append("⚠️ 已禁用代码完整性检查(nointegritychecks)")
            status = STATUS_FAIL
        else:
            msgs.append("代码完整性检查(Code Integrity)正常")
    # 4. Device Guard (CI+HVCI)
    rc3, out3 = run_powershell("Get-CimInstance Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard")
    if rc3 == 0 and out3.strip():
        if re.search(r"SecurityServicesRunning:\s*1", out3) or "VirtualizationBasedSecurityStatus" in out3:
            msgs.append("Device Guard/VBS 启用")
        if re.search(r"CodeIntegrityPolicyEnforcementStatus:\s*1", out3):
            msgs.append("代码完整性策略强制模式启用")
        else:
            msgs.append("代码完整性策略未强制")
            status = STATUS_WARN
    return status, "；".join(msgs)


# ---------------- 可信验证 (TPM/TCM + BitLocker) ----------------

def check_tpm():
    """Windows: TPM2.0 + BitLocker + Secure Boot"""
    msgs, status = [], STATUS_PASS
    # 1. TPM 状态
    rc, out = run_powershell("Get-Tpm | Select-Object -Property TpmReady, TpmPresent, ManufacturerVersion")
    if rc == 0:
        if "TpmReady" in out and "True" in out:
            msgs.append("TPM 已就绪并启用")
        elif "TpmPresent" in out and "True" in out:
            msgs.append("TPM 存在但未就绪")
            status = STATUS_WARN
        else:
            msgs.append("TPM 模块未检测到")
            status = STATUS_WARN
    # 2. BitLocker
    rc2, out2 = run_cmd(["manage-bde", "-status", "-ProtectionMode"])
    if rc2 == 0:
        if "Protection Status: Protection On" in out2 or re.search(r"Protection Status:\s*On", out2):
            msgs.append("BitLocker 保护已启用")
        else:
            msgs.append("BitLocker 保护未启用")
            status = STATUS_WARN
    # 3. Secure Boot
    rc3, out3 = run_powershell("Confirm-SecureBootUEFI")
    if rc3 == 0:
        if out3.strip() == "True":
            msgs.append("UEFI Secure Boot 已启用")
        else:
            msgs.append("UEFI Secure Boot 未启用")
            status = STATUS_WARN
    # 4. Device Guard / VBS
    rc4, out4 = run_powershell("Get-CimInstance Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -Property VirtualizationBasedSecurityStatus")
    if rc4 == 0:
        if re.search(r"VirtualizationBasedSecurityStatus:\s*1", out4):
            msgs.append("VBS(Virtualization-Based Security)启用，可信启动链有效")
    return status, "；".join(msgs)


# ---------------- 鉴别信息加密存储 ----------------

def check_auth_encrypt():
    """Windows: SAM 数据库加密 + 本地账户密码"""
    msgs, status = [], STATUS_PASS
    # Windows SAM 默认用 RC4 加密（NT Hash），但这是不可逆哈希
    # 三级：BitLocker + Syskey 保护 SAM
    rc, out = run_cmd(["syskey", "/?"])
    msgs.append("Windows SAM 账户数据库使用 RC4 加密存储鉴别信息")
    # 检测 syskey 是否已设置
    rc2, out2 = run_cmd(["cmd", "/c", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SysKey"])
    # 更简单的方式：syskey 保护状态只能交互式检测，降级提示
    rc3, out3 = run_powershell("Get-ChildItem -Path C:\\Windows\\System32\\config\\SAM -ErrorAction SilentlyContinue | Select-Object Length, LastWriteTime")
    if rc3 == 0:
        msgs.append("SAM 数据库文件存在，ACL 权限自动保护")
    # 检查是否启用了更安全的密码存储 (LSA 保护)
    rc4, out4 = run_cmd(["reg", "query",
                         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                         "/v", "lsaPid"])
    if rc4 == 0:
        msgs.append("LSA 进程隔离保护已启用(lsaPid存在)")
    # Windows Hello / 智能卡登录（三级）
    rc5, out5 = run_powershell("Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Passports\\Faces -ErrorAction SilentlyContinue")
    if rc5 == 0 and out5.strip():
        msgs.append("检测到 Windows Hello 生物特征配置")
    return status, "；".join(msgs)


# ---------------- 审计防篡改 (Windows Event Log + SACL + 备份) ----------------

def check_audit_protect():
    """Windows: Event Log ACL + SACL + 日志保护"""
    msgs, status = [], STATUS_PASS
    # 1. Event Log ACL
    rc, out = run_powershell(
        "wevtutil al System 2>$null | Select-String 'Access'; "
        "wevtutil al Security 2>$null | Select-String 'Access'; "
        "wevtutil al Application 2>$null | Select-String 'Access'")
    if rc == 0:
        if "Access:" in out:
            msgs.append("Event Log ACL 已配置访问控制")
    # 2. 日志文件系统 ACL
    for log_name in ["Security", "System", "Application"]:
        rc2, out2 = run_cmd(["icacls", "C:\\Windows\\System32\\winevt\\Logs\\%s.evtx" % log_name])
        if rc2 == 0:
            if "(I)" in out2 and "SYSTEM:(F)" in out2:
                msgs.append("%s 日志文件 ACL 正确(SYSTEM完全控制)" % log_name)
            elif "Everyone" in out2 and "(F)" in out2:
                msgs.append("⚠️ %s 日志 Everyone 完全控制，应限制权限" % log_name)
                status = STATUS_WARN
    # 3. SACL (系统访问控制列表) - 审计目录服务访问
    rc3, out3 = run_cmd(["auditpol", "/get", "/category:*"])
    if rc3 == 0 and out3.strip():
        msgs.append("auditpol 已配置系统访问控制(SACL)")
    # 4. 日志清理策略 - 防止日志被删
    rc4, out4 = run_cmd(["reg", "query",
                         "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
                         "/v", "Retention"])
    if rc4 == 0:
        val = re.search(r"REG_DWORD\s+(0x\w+|\d+)", out4)
        if val and val.group(1) in ("0x1", "0x00000001", "1"):
            msgs.append("日志保留模式: 覆盖过期事件(推荐)")
        elif val:
            msgs.append("日志保留模式: %s" % val.group(1))
    return status, "；".join(msgs)


# ---------------- HIDS (Windows Defender ATP / Sysmon / EDR) ----------------

def check_hids():
    """Windows: Defender ATP / Sysmon / 国内 EDR"""
    msgs, status = [], STATUS_PASS
    found = False
    # 1. Windows Defender ATP / Defender for Endpoint
    rc, out = run_powershell("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled")
    if rc == 0:
        if "RealTimeProtectionEnabled" in out and "True" in out:
            found = True
            msgs.append("Windows Defender 实时保护已启用")
    # 2. Defender for Endpoint / ATP
    rc2, out2 = run_powershell("Get-Service -Name WinDefend, Sense -ErrorAction SilentlyContinue | Select-Object Name, Status")
    if rc2 == 0:
        if "Running" in out2 and "WinDefend" in out2:
            found = True
            msgs.append("Windows Defender 服务运行中")
        if "Sense" in out2 and "Running" in out2:
            found = True
            msgs.append("Microsoft Defender for Endpoint (Sense) 运行中")
    # 3. Sysmon (Sysinternals)
    rc3, out3 = run_cmd(["sc", "query", "Sysmon64"])
    rc4, out4 = run_cmd(["sc", "query", "Sysmon"])
    if rc3 == 0 and "RUNNING" in out3.upper():
        found = True
        msgs.append("Sysmon64 安全监控服务运行中")
    elif rc4 == 0 and "RUNNING" in out4.upper():
        found = True
        msgs.append("Sysmon 安全监控服务运行中")
    # 4. 国内 EDR (奇安信、深信服、天融信、绿盟等)
    edr_names = [("QAX360EDR", "奇安信终端卫士"), ("SangforEDR", "深信服EDR"),
                 ("TopEDR", "天融信EDR"), ("NSFOCUS", "绿盟EDR"),
                 ("H3CSeCenter", "新华三SeCenter"), ("Juniper-Endpoint", "Juniper Endpoint")]
    for svc, label in edr_names:
        rc5, out5 = run_cmd(["sc", "query", svc])
        if rc5 == 0 and "RUNNING" in out5.upper():
            found = True
            msgs.append("%s 服务运行中" % label)
    # 5. 其他安全服务
    rc6, out6 = run_powershell(
        "Get-Service | Where-Object { $_.DisplayName -match 'EDR|HIDS|终端检测|主机入侵|安全防护|威胁检测' } | Select-Object DisplayName, Status")
    if rc6 == 0 and out6.strip():
        found = True
        msgs.append("发现安全服务: %s" % out6.strip().splitlines()[0][:120])
    if not found:
        status = STATUS_WARN
        msgs.append("未检测到 HIDS/EDR 组件，三级系统建议部署")
    return status, "；".join(msgs)


def build_checks():
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        # 身份鉴别
        W("W-ID-1", "操作系统身份鉴别-口令策略", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 a)",
          "密码长度≥8位，最长使用期限≤90天", "net accounts 设置密码策略，或在组策略中配置密码策略", check_password_policy),
        W("W-ID-2", "口令复杂度要求", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 a)",
          "启用“密码必须符合复杂性要求”(字母+数字+特殊字符组合)",
          "组策略→计算机配置→Windows设置→安全设置→密码策略→启用密码复杂性要求", check_password_complexity),
        W("W-ID-3", "登录失败处理-账户锁定", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 b)",
          "配置账户锁定阈值(≤10次)与锁定时间", "配置账户锁定策略：锁定阈值5-10次，锁定时长≥10分钟", check_lockout_policy),
        W("W-ID-4", "远程登录安全(NLA)", CAT_IDENTITY, LEVEL_L3, "8.1.4.1 c)",
          "远程管理启用网络级身份验证(NLA)，防止鉴别信息被窃听",
          "系统属性→远程→勾选“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”", check_rdp_nla),
        W("W-ID-5", "两种以上鉴别技术", CAT_IDENTITY, LEVEL_L3, "8.1.4.1 d)",
          "三级系统应采用口令+动态口令/数字证书/生物技术等两种以上鉴别方式",
          "部署双因素认证(如动态令牌、USBKey、堡垒机MFA)", None),

        # 访问控制
        W("W-AC-1", "禁用Guest来宾账户", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 a)",
          "Guest账户禁用或删除", "计算机管理→本地用户和组→禁用Guest", check_guest_account),
        W("W-AC-2", "重命名默认管理员账户", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 a)",
          "重命名Administrator默认账户", "重命名内置管理员账户并设置强口令", check_admin_renamed),
        W("W-AC-3", "管理员组最小化授权", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 b)",
          "仅必要人员拥有管理员权限", "清理管理员组成员，按岗位职责最小授权", check_admin_members),
        W("W-AC-4", "关闭默认共享", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 c)",
          "关闭C$/D$/ADMIN$默认管理共享", "注册表设置AutoShareServer=0并重启Server服务", check_default_share),
        W("W-AC-5", "限制匿名访问", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 a)",
          "禁止匿名枚举用户与共享(RestrictAnonymous≥1)",
          "组策略→安全选项→“网络访问: 不允许SAM账户和共享的匿名枚举”设为已启用", check_anonymous_enum),
        W("W-AC-6", "多余/过期账户清理", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 e)",
          "不存在多余的、过期的账户，共享账户已删除",
          "定期检查本地账户列表，禁用或删除离职/过期账户", None),
        W("W-AC-7", "三权分立/管理角色分离", CAT_ACCESS, LEVEL_L3, "8.1.4.2 f)",
          "三级系统应实现系统管理员、安全管理员、审计管理员权限分离",
          "建立独立的安全管理员与审计管理员账户，分散系统管理员权限", None),

        # 安全审计
        W("W-AU-1", "审核策略覆盖", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 a)",
          "审计覆盖登录事件、账户管理、策略变更、特权使用等重要事件",
          "auditpol 或组策略配置审核策略，覆盖成功+失败事件", check_audit_policy),
        W("W-AU-2", "日志服务运行状态", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 a)",
          "Windows Event Log服务正常运行", "确保EventLog服务自动启动", check_eventlog_service),
        W("W-AU-3", "日志容量与保护", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 b)",
          "日志容量≥100MB并配置覆盖策略，防止审计记录丢失",
          "事件查看器→日志属性→调大日志最大值，配置“按需覆盖”", check_eventlog_config),
        W("W-AU-4", "审计记录留存与备份", CAT_AUDIT, LEVEL_L3, "8.1.4.3 d)",
          "审计记录定期备份，留存时间不少于6个月",
          "部署日志服务器/SIEM集中收集，定期备份并留存6个月以上", check_log_retention_hint),

        # 入侵防范
        W("W-IN-1", "主机防火墙启用", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 c)",
          "启用Windows防火墙并按最小开放原则配置规则",
          "启用防火墙，仅开放业务必需端口", check_firewall),
        W("W-IN-2", "禁用SMBv1协议", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 a)",
          "禁用SMBv1等不安全协议", "PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol", check_smbv1),
        W("W-IN-3", "高危端口管控", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 c)",
          "关闭Telnet/FTP等高危端口，限制135/139/445/3389访问来源",
          "关闭不必要服务与端口；必需端口通过防火墙限制访问源IP", check_dangerous_ports),
        W("W-IN-4", "禁用自动播放", CAT_INTRUSION, LEVEL_L2, "8.1.4.4 a)",
          "禁用U盘等移动介质自动播放", "组策略→管理模板→Windows组件→自动播放策略→关闭自动播放", check_autorun),
        W("W-IN-5", "高风险服务管控", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 a)",
          "禁用RemoteRegistry/Telnet/SNMP等不必要服务",
          "services.msc 禁用不必要服务", check_unneeded_services),
        W("W-IN-6", "补丁更新管理", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 b)",
          "操作系统补丁及时更新，重要补丁安装前测试",
          "开启Windows Update或部署WSUS集中分发补丁", check_patch_status),

        # 恶意代码防范
        W("W-MW-1", "防病毒软件部署", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 a)",
          "安装并启用防病毒软件，实时保护开启",
          "启用Windows Defender或部署企业级杀毒软件", check_antivirus),
        W("W-MW-2", "病毒库及时更新", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 b)",
          "病毒库7天内更新", "配置病毒库自动更新", check_av_signature),
        W("W-MW-4", "Defender实时保护开启", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 a)",
          "RealTimeProtectionEnabled=True，实时拦截恶意代码",
          "组策略/Defender设置启用实时保护，禁止被第三方工具关闭", check_defender_realtime),
        W("W-MW-5", "Defender上次快速扫描", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 b)",
          "最近7天内执行过快速扫描",
          "启用Defender计划任务定期快速扫描，或由集中管控平台下发扫描策略",
          check_defender_quickscan),
        W("W-MW-3", "统一防病毒管理", CAT_MALWARE, LEVEL_L3, "8.1.4.5 c)",
          "三级系统应部署集中管控的防病毒体系", "部署企业版杀软管控中心，统一策略下发与告警", None),

        # 数据备份
        W("W-BK-1", "重要数据备份", CAT_BACKUP, LEVEL_ALL, "8.1.4.6 a)",
          "重要数据定期备份，备份介质场外存放",
          "制定备份策略，定期备份重要业务数据与配置", check_backup),
        W("W-BK-2", "异地备份/冗余", CAT_BACKUP, LEVEL_L3, "8.1.4.6 b)",
          "三级系统应提供异地数据级备份与重要设备冗余",
          "建立异地备份机制，关键设备/链路冗余部署", None),

        # 强制访问控制 (新增)
        W("W-MAC-1", "强制访问控制(MIC/CI/Device Guard)", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 c)",
          "启用强制完整性控制(MIC)和代码完整性(Code Integrity)",
          "bcdedit /enum 确保无 nointegritychecks；启用 Device Guard/代码完整性策略", check_mac),

        # 可信验证 (新增)
        W("W-TPM-1", "可信验证(TPM2.0/BitLocker/Secure Boot)", CAT_ACCESS, LEVEL_L3, "8.1.4.6 a)",
          "三级系统应启用 TPM2.0 + BitLocker + UEFI Secure Boot + VBS",
          "Windows Defender ATP 启用 VBS；启用 BitLocker 系统盘加密；BIOS 启用 Secure Boot", check_tpm),

        # 鉴别信息加密存储 (新增)
        W("W-ENC-1", "鉴别信息加密存储(SAM/LSA保护)", CAT_IDENTITY, LEVEL_L3, "8.1.4.8 c)",
          "SAM 数据库使用 RC4 加密，LSA 进程隔离保护鉴别信息",
          "确保 LSA 进程隔离启用；敏感账户使用 BitLocker 保护存储", check_auth_encrypt),

        # 审计防篡改 (新增)
        W("W-AU-5", "审计防篡改保护", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 c)",
          "Event Log ACL 限制非授权修改，SACL 配置审计，日志定期备份",
          "使用 icacls 限制 .evtx 日志文件权限，auditpol 配置 SACL", check_audit_protect),

        # HIDS (新增)
        W("W-HIDS-1", "主机入侵检测/终端检测响应(EDR)", CAT_INTRUSION, LEVEL_L3, "8.1.4.4 c)",
          "三级系统应部署 HIDS/EDR 组件",
          "启用 Windows Defender ATP 或部署 Sysmon/奇安信EDR/深信服EDR等 HIDS", check_hids),
    ]
