# -*- coding: utf-8 -*-
"""Linux 平台技术检测项（等保2.0，二级/三级）
适配麒麟(Kylin V10)、统信UOS、Deepin 等国产发行版，
检测基于 /etc 配置文件、systemctl、ss、PAM 配置，无需额外依赖。
"""
import glob
import os
import re
import time

from core import baseline
from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR,
                         CAT_IDENTITY, CAT_ACCESS, CAT_AUDIT, CAT_INTRUSION,
                         CAT_MALWARE, CAT_BACKUP, LEVEL_ALL, LEVEL_L2, LEVEL_L3)
from .platform_util import run_cmd, read_file, is_privileged, file_mode


def _login_defs_value(key, default=None):
    m = re.search(r"^\s*%s\s+(\S+)" % re.escape(key), read_file("/etc/login.defs"), re.M)
    return m.group(1) if m else default


def _service_active(*names):
    for n in names:
        rc, out = run_cmd(["systemctl", "is-active", n])
        if rc == 0 and out.strip() == "active":
            return True, n
    return False, ""


def _service_enabled(*names):
    for n in names:
        rc, out = run_cmd(["systemctl", "is-enabled", n])
        if rc == 0 and out.strip() in ("enabled", "static"):
            return True, n
    return False, ""


def _sshd_param(key):
    content = read_file("/etc/ssh/sshd_config")
    m = re.search(r"^\s*%s\s+(\S+)" % re.escape(key), content, re.M | re.I)
    return m.group(1) if m else None


# ---------------- 身份鉴别 ----------------

def check_password_aging():
    max_days = _login_defs_value("PASS_MAX_DAYS")
    min_len = _login_defs_value("PASS_MIN_LEN")
    msgs, status = [], STATUS_PASS
    if max_days is None:
        msgs.append("未配置PASS_MAX_DAYS")
        status = STATUS_FAIL
    else:
        try:
            v = int(max_days)
            if v > 90 or v == 99999:
                msgs.append("PASS_MAX_DAYS=%s(要求≤90)" % max_days)
                status = STATUS_FAIL
            else:
                msgs.append("PASS_MAX_DAYS=%s" % max_days)
        except ValueError:
            msgs.append("PASS_MAX_DAYS=%s" % max_days)
    if min_len is not None:
        ok = int(min_len) >= 8 if min_len.isdigit() else False
        msgs.append("PASS_MIN_LEN=%s%s" % (min_len, "" if ok else "(要求≥8)"))
        if not ok:
            status = STATUS_FAIL
    else:
        msgs.append("未配置PASS_MIN_LEN(由PAM复杂度模块控制)")
    return status, "；".join(msgs)


def check_password_complexity():
    content = ""
    for f in ("/etc/pam.d/system-auth", "/etc/pam.d/common-password",
              "/etc/pam.d/password-auth"):
        content += read_file(f)
    if "pam_pwquality" in content or "pam_cracklib" in content:
        detail = []
        m = re.search(r"(minlen|dcredit|ucredit|lcredit|ocredit)\s*=\s*(-?\d+)", content)
        mod = "pam_pwquality" if "pam_pwquality" in content else "pam_cracklib"
        return STATUS_PASS, "已启用%s口令复杂度模块" % mod
    return STATUS_FAIL, "未在PAM中发现pam_pwquality/pam_cracklib复杂度模块"


def check_login_lockout():
    content = ""
    for f in ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
              "/etc/pam.d/common-auth", "/etc/pam.d/login", "/etc/pam.d/sshd"):
        content += read_file(f)
    if "pam_faillock" in content:
        return STATUS_PASS, "已启用pam_faillock登录失败锁定"
    if "pam_tally2" in content or "pam_tally" in content:
        return STATUS_PASS, "已启用pam_tally2登录失败锁定"
    return STATUS_FAIL, "未配置登录失败锁定(pam_faillock/pam_tally2)，无法防御口令爆破"


def check_ssh_root_login():
    v = _sshd_param("PermitRootLogin")
    if v is None:
        return STATUS_WARN, "sshd未显式配置PermitRootLogin(默认可能允许)"
    if v.lower() in ("no", "forced-commands-only"):
        return STATUS_PASS, "PermitRootLogin=%s，已禁止root直接远程登录" % v
    if v.lower() == "prohibit-password" or v.lower() == "without-password":
        return STATUS_WARN, "PermitRootLogin=%s(仅密钥登录)，建议改为no" % v
    return STATUS_FAIL, "PermitRootLogin=%s，允许root口令远程登录，风险极高" % v


def check_ssh_params():
    msgs, status = [], STATUS_PASS
    pa = _sshd_param("PasswordAuthentication")
    tries = _sshd_param("MaxAuthTries")
    if pa and pa.lower() == "yes":
        msgs.append("允许口令认证(建议结合失败锁定或改用密钥)")
        status = STATUS_WARN
    if tries:
        try:
            if int(tries) > 4:
                msgs.append("MaxAuthTries=%s(建议≤4)" % tries)
                status = STATUS_WARN
            else:
                msgs.append("MaxAuthTries=%s" % tries)
        except ValueError:
            pass
    if not msgs:
        return STATUS_MANUAL, "未读取到SSH鉴别参数，请人工核查sshd_config"
    return status, "；".join(msgs)


def check_login_timeout():
    content = read_file("/etc/profile") + read_file("/etc/bashrc") + read_file("/etc/profile.d/timeout.sh")
    m = re.search(r"TMOUT\s*=\s*(\d+)", content)
    if m:
        v = int(m.group(1))
        if 0 < v <= 600:
            return STATUS_PASS, "已设置会话超时TMOUT=%d秒" % v
        return STATUS_WARN, "TMOUT=%d秒，超过600秒不符合要求" % v
    return STATUS_FAIL, "未设置shell会话超时(TMOUT)，应配置≤600秒自动退出"


# ---------------- 访问控制 ----------------

def check_empty_password():
    ok, msg = is_privileged()
    if not ok:
        return STATUS_MANUAL, "读取/etc/shadow需root权限(%s)，请以root身份检测后复核" % msg
    content = read_file("/etc/shadow")
    if not content.strip():
        return STATUS_MANUAL, "未能读取/etc/shadow内容"
    empty = [l.split(":")[0] for l in content.splitlines()
             if l.strip() and not l.startswith("#") and len(l.split(":")) > 1 and l.split(":")[1] == ""]
    if empty:
        return STATUS_FAIL, "存在空口令账户: %s" % "、".join(empty)
    return STATUS_PASS, "/etc/shadow中未发现空口令账户"


def check_uid0():
    content = read_file("/etc/passwd")
    uid0 = [l.split(":")[0] for l in content.splitlines()
            if len(l.split(":")) > 2 and l.split(":")[2] == "0"]
    extra = [u for u in uid0 if u != "root"]
    if extra:
        return STATUS_FAIL, "存在除root外的UID=0账户: %s" % "、".join(extra)
    return STATUS_PASS, "仅root账户UID=0"


def check_file_perm():
    problems = []
    checks = [("/etc/passwd", 0o644), ("/etc/shadow", 0o600), ("/etc/group", 0o644)]
    for path, maxperm in checks:
        mode_str, _ = file_mode(path)
        if not mode_str:
            continue
        try:
            mode = int(mode_str, 8)
        except ValueError:
            continue
        if path == "/etc/shadow":
            if mode & 0o077:
                problems.append("%s权限%s过宽(应≤640)" % (path, mode_str))
        else:
            if (mode & 0o022) and (mode & 0o002):
                problems.append("%s权限%s过宽(其他用户可写)" % (path, mode_str))
    if problems:
        return STATUS_FAIL, "；".join(problems)
    return STATUS_PASS, "/etc/passwd、/etc/shadow、/etc/group 权限配置正确"


def check_umask():
    content = read_file("/etc/login.defs")
    m = re.search(r"^\s*UMASK\s+(\d+)", content, re.M)
    if m:
        v = m.group(1)
        if v in ("077", "027"):
            return STATUS_PASS, "login.defs UMASK=%s" % v
        return STATUS_WARN, "UMASK=%s，建议设置为027或077" % v
    return STATUS_MANUAL, "未在login.defs找到UMASK配置，请人工核查"


def check_sudoers():
    ok, msg = is_privileged()
    if not ok:
        return STATUS_MANUAL, "读取/etc/sudoers需root权限(%s)，请人工核查授权最小化" % msg
    content = read_file("/etc/sudoers")
    nopasswd = [l.strip() for l in content.splitlines()
                if "NOPASSWD" in l and not l.strip().startswith("#")]
    if nopasswd:
        return STATUS_WARN, "存在NOPASSWD免密sudo授权(%d处)，建议消除" % len(nopasswd)
    return STATUS_PASS, "sudoers中未发现NOPASSWD免密授权"


def check_world_writable():
    rc, out = run_cmd(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], timeout=20)
    if rc != 0:
        return STATUS_MANUAL, "无法扫描/etc全局可写文件"
    files = [l for l in out.strip().splitlines() if l.strip()]
    if files:
        return STATUS_WARN, "发现/etc下全局可写文件%d个: %s" % (len(files), "、".join(files[:5]))
    return STATUS_PASS, "/etc下未发现全局可写文件"


# ---------------- 安全审计 ----------------

def check_auditd():
    active, name = _service_active("auditd")
    if not active:
        return STATUS_FAIL, "auditd审计服务未运行"
    enabled, _ = _service_enabled("auditd")
    if enabled:
        return STATUS_PASS, "auditd运行中且开机自启"
    return STATUS_WARN, "auditd运行中但未设置开机自启"


def check_rsyslog():
    active, name = _service_active("rsyslog", "syslog", "syslog-ng", "systemd-journald")
    if active:
        return STATUS_PASS, "日志服务运行中(%s)" % name
    return STATUS_FAIL, "未检测到运行中的日志服务(rsyslog/syslog-ng/journald)"


def check_log_perm():
    problems = []
    for path in ("/var/log/messages", "/var/log/secure", "/var/log/audit/audit.log"):
        mode_str, _ = file_mode(path)
        if not mode_str:
            continue
        try:
            mode = int(mode_str, 8)
        except ValueError:
            continue
        if mode & 0o077:
            problems.append("%s权限%s过宽" % (path, mode_str))
    if problems:
        return STATUS_WARN, "；".join(problems)
    return STATUS_PASS, "关键日志文件权限配置正确(≤640)"


def check_remote_syslog():
    content = read_file("/etc/rsyslog.conf")
    if re.search(r"^\s*[^#].*(@@?)[\w.\-]+", content, re.M):
        return STATUS_PASS, "rsyslog已配置远程日志服务器转发"
    return STATUS_MANUAL, "未发现远程日志转发配置，三级系统应将审计日志发送至日志服务器集中留存(≥6个月)"


# ---------------- 入侵防范 ----------------

def check_firewall():
    active, name = _service_active("firewalld", "ufw", "iptables", "nftables")
    if active:
        return STATUS_PASS, "防火墙服务运行中(%s)" % name
    rc, out = run_cmd(["iptables", "-L", "-n"], timeout=10)
    if rc == 0 and out.count("ACCEPT") + out.count("DROP") > 0:
        return STATUS_WARN, "防火墙服务未运行，但存在iptables规则，请确认规则完备性"
    return STATUS_FAIL, "未检测到运行中的防火墙(firewalld/ufw/nftables)"


def check_dangerous_ports():
    rc, out = run_cmd(["ss", "-tuln"])
    if rc != 0:
        rc, out = run_cmd(["netstat", "-tuln"])
    if rc != 0:
        return STATUS_ERROR, "无法读取监听端口"
    danger = {"21": "FTP", "23": "Telnet", "69": "TFTP", "111": "RPC", "513": "rlogin", "514": "rsh"}
    open_danger = []
    for line in out.splitlines():
        m = re.search(r":(\d+)\s", line)
        if m and m.group(1) in danger:
            open_danger.append("%s(%s)" % (m.group(1), danger[m.group(1)]))
    if open_danger:
        return STATUS_FAIL, "检测到高危端口开放: %s" % "、".join(sorted(set(open_danger)))
    return STATUS_PASS, "未发现Telnet/FTP/TFTP/rsh等高危端口开放"


def check_ssh_protocol():
    proto = _sshd_param("Protocol")
    if proto and proto != "2":
        return STATUS_FAIL, "SSH Protocol=%s，应仅使用SSHv2" % proto
    x11 = _sshd_param("X11Forwarding")
    msgs = []
    status = STATUS_PASS
    if x11 and x11.lower() == "yes":
        msgs.append("X11Forwarding开启(建议关闭)")
        status = STATUS_WARN
    empty = _sshd_param("PermitEmptyPasswords")
    if empty and empty.lower() == "yes":
        msgs.append("PermitEmptyPasswords=yes，允许空口令登录")
        status = STATUS_FAIL
    if msgs:
        return status, "；".join(msgs)
    return STATUS_PASS, "SSH协议安全配置正常(Protocol 2/禁空口令)"


def check_unneeded_services():
    risky = ["telnet", "vsftpd", "tftp", "rsh", "rlogin", "rexec", "xinetd", "cups", "avahi-daemon"]
    running = []
    for n in risky:
        active, _ = _service_active(n)
        if active:
            running.append(n)
    if running:
        return STATUS_WARN, "以下高风险/非必要服务运行中，建议关闭: %s" % "、".join(running)
    return STATUS_PASS, "未发现telnet/vsftpd/rsh等高风险服务运行"


def check_patch_hint():
    rc, out = run_cmd(["uname", "-r"])
    kernel = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
    evidence = "内核 %s" % kernel if kernel else ""
    if kernel:
        ok, need, note = baseline.evaluate("linux", kernel)
        if ok is False:
            return STATUS_WARN, "%s 低于离线安全基线 %s；%s" % (evidence, need, note)
        evidence = "%s 达到基线 %s" % (evidence, need)
    rc, out = run_cmd(["rpm", "-qa", "--last"], timeout=15)
    if rc == 0 and out.strip():
        first = out.strip().splitlines()[0]
        return STATUS_MANUAL, "%s；最近软件包更新: %s。请结合发行版安全公告核查补丁" % (evidence, first[:100])
    evidence = evidence or "未读取到内核版本"
    return STATUS_MANUAL, "%s；请核查apt/dnf更新记录与发行版安全公告" % evidence


# ---------------- 恶意代码防范 ----------------

def check_antivirus():
    rc, out = run_cmd(["bash", "-c",
                       "command -v clamscan || command -v fscan || command -v rkav "
                       "|| rpm -qa 2>/dev/null | grep -iE 'clam|antivirus|sangfor|qax|360' "
                       "|| dpkg -l 2>/dev/null | grep -iE 'clam|antivirus'"], timeout=15)
    if out.strip():
        return STATUS_PASS, "检测到防病毒软件/组件: %s" % out.strip().splitlines()[0][:100]
    return STATUS_WARN, "未检测到常见防病毒软件，服务器应部署恶意代码防范措施(或采取可信计算/白名单机制)"


def check_av_update():
    return STATUS_MANUAL, "请人工核查防病毒软件病毒库/规则库更新记录(应定期自动更新)"


def check_clamav_service():
    """ClamAV 是否安装且 clamd 守护进程运行"""
    rc, out = run_cmd(["bash", "-c",
                       "command -v clamscan || command -v clamdscan || command -v clamd "
                       "|| rpm -qa 2>/dev/null | grep -i clamav"], timeout=15)
    text = (out or "").strip()
    if "命令不存在" in text:
        return STATUS_MANUAL, "目标机无法执行shell命令，需人工核查是否部署ClamAV等恶意代码检测组件"
    if not text or rc != 0:
        return STATUS_MANUAL, "未部署ClamAV恶意代码检测组件（与防病毒检查结论一致），需人工核查其他恶意代码防范措施"
    active, name = _service_active("clamav-daemon", "clamd", "clamav-freshclam")
    if active:
        return STATUS_PASS, "ClamAV已安装且守护进程 %s 运行中" % name
    return STATUS_WARN, "已安装ClamAV但clamd/freshclam未运行，仅支持手动clamscan扫描"


def check_clamav_signature():
    """ClamAV 病毒库版本日期是否在7天内"""
    rc, out = run_cmd(["bash", "-c",
                       "stat -c '%n %Y' /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null"],
                      timeout=15)
    newest = 0
    newest_name = ""
    for line in (out or "").splitlines():
        parts = line.strip().rsplit(" ", 1)
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        ts = int(parts[1])
        if ts > newest:
            newest, newest_name = ts, parts[0]
    if newest:
        days = (time.time() - newest) / 86400.0
        if days <= 7:
            return STATUS_PASS, "病毒库 %s 在%.1f天内更新" % (newest_name, days)
        return STATUS_FAIL, "病毒库 %s 已%.1f天未更新，恶意代码特征库失效" % (newest_name, days)
    rc2, out2 = run_cmd(["bash", "-c", "clamscan -V 2>/dev/null || freshclam --version 2>/dev/null"],
                        timeout=15)
    if "ClamAV" in (out2 or ""):
        return STATUS_MANUAL, "未读取到病毒库文件更新时间（可能需root权限），需人工核查：%s" % \
            out2.strip().splitlines()[0][:200]
    if not (out or "").strip():
        return STATUS_MANUAL, "未检测到ClamAV病毒库文件，未部署ClamAV时需人工核查其他恶意代码防护"
    return STATUS_MANUAL, "未能解析病毒库更新时间，需人工核查 /var/lib/clamav 目录"


# ---------------- 剩余信息保护 (8.1.4.10 a) ----------------

def check_remaining_info_protect():
    """鉴别信息/文件删除后空间清零、磁盘擦除策略"""
    msgs, status = [], STATUS_PASS
    # 1. tmpfs/discard 挂载（自动清零已删文件）
    rc, out = run_cmd(["mount"])
    if rc == 0:
        tmpfs = [l for l in out.splitlines() if "tmpfs" in l.lower() and "/tmp" in l]
        discard = [l for l in out.splitlines() if re.search(r"\bdiscard\b", l, re.I)]
        if tmpfs:
            msgs.append("✅ /tmp 使用 tmpfs（内存文件系统，重启自动清空）")
        if discard:
            msgs.append("✅ %d 个挂载点启用 discard（SSD/TRIM 自动清零已删块）" % len(discard))
    # 2. shred 是否可用（安全擦除工具）
    rc2, _ = run_cmd(["which", "shred"])
    if rc2 == 0:
        msgs.append("✅ shred 安全擦除工具可用")
    else:
        msgs.append("⚠️ shred 未安装，建议 yum/apt install coreutils (含 shred)"); status = STATUS_WARN
    # 3. 敏感目录权限（/var/log、/etc/shadow）
    rc3, shadow = run_cmd(["stat", "-c", "%a %U", "/etc/shadow"])
    if rc3 == 0:
        if shadow.split()[0] in ("600", "640"):
            msgs.append("✅ /etc/shadow 权限 %s" % shadow.strip())
        else:
            msgs.append("⚠️ /etc/shadow 权限异常: %s" % shadow.strip()); status = STATUS_WARN
    # 4. LUKS/dm-crypt 加密分区（加密即自动清零）
    rc4, out4 = run_cmd(["bash", "-c", "lsblk -o TYPE,NAME,FSTYPE | grep -i crypt || echo none"])
    if "crypt" in (out4 or "").lower():
        msgs.append("✅ 检测到加密分区（LUKS/dm-crypt，删除自动清零）")
    return status, "；".join(msgs)


# ---------------- 统一安全等级标记 (8.1.4.2 d) ----------------

def check_security_label():
    """SELinux / Smack / NTFS DACL 安全标记"""
    msgs, status = [], STATUS_PASS
    # SELinux context
    rc, out = run_cmd(["bash", "-c", "ls -Z /etc/passwd 2>/dev/null || echo no_selinux"])
    if "no_selinux" not in (out or "") and rc == 0:
        if re.search(r"[^?]\s+[^?]\s+[^?]\s+[^?]:[^?]:[^?]:", out):
            msgs.append("✅ SELinux 文件安全标签(context)已应用: %s" % out.strip()[:80])
        else:
            msgs.append("⚠️ SELinux context 格式异常: %s" % out.strip()[:80]); status = STATUS_WARN
    else:
        rc2, out2 = run_cmd(["bash", "-c", "cat /proc/self/attr/current 2>/dev/null || echo unconfined"])
        msgs.append("当前安全上下文: %s" % (out2 or "unconfined").strip())
        status = STATUS_WARN
    return status, "；".join(msgs)


# ---------------- 异地备份 (8.1.4.9 b) ----------------

def check_offsite_backup():
    """异地/场外备份证据：rsync+SSH、异地 NAS 挂载、磁带/云备份"""
    msgs, status = [], STATUS_MANUAL
    # 1. rsync + SSH cron（指向异地主机）
    rc, crontab = run_cmd(["bash", "-c",
        "cat /etc/crontab; ls /etc/cron.d/ 2>/dev/null | xargs -I{} cat /etc/cron.d/{} 2>/dev/null"])
    if rc == 0:
        rsync_ssh = re.findall(r"(rsync.*-e\s+ssh|rsync@\w[-\w.]+:|scp.*@)", crontab, re.I)
        if rsync_ssh:
            msgs.append("✅ 检测到 rsync/ssh 异地备份 cron: %s" % rsync_ssh[0][:100])
            status = STATUS_PASS
    # 2. 异地 NAS/NFS 挂载
    rc2, mounts = run_cmd(["mount"])
    if rc2 == 0:
        remote_mounts = [l for l in mounts.splitlines() if re.match(r"\d+\.\d+\.\d+\.\d+:|//|nfs|cifs|smb", l)]
        if remote_mounts:
            msgs.append("✅ 检测到 %d 个远程挂载点(异地NAS/SMB/NFS)" % len(remote_mounts))
            for rm in remote_mounts[:2]:
                msgs.append("   %s" % rm.strip()[:120])
            if status == STATUS_MANUAL: status = STATUS_PASS
    # 3. 云备份工具（restic/borg/duplicity）
    rc3, out3 = run_cmd(["bash", "-c", "which restic borg duplicity rclone ossutil aws 2>/dev/null || true"])
    if out3.strip():
        msgs.append("✅ 云/异地备份工具: %s" % out3.strip())
    if status == STATUS_MANUAL:
        msgs.append("⚠️ 未检测到自动异地备份迹象（需人工核查：异地NAS挂载、磁带轮换、云备份、冷备介质场外存放）")
    return status, "；".join(msgs)


# ---------------- 完整性破坏后数据恢复 (8.1.4.7 b 三级) ----------------

def check_recovery_test():
    """是否有定期恢复演练证据"""
    msgs = []
    # 看 /var/log/ 或 /opt/backup 下有没有恢复日志
    import glob, os
    for pattern, label in [
        ("/var/log/*restore*", "恢复日志"),
        ("/var/log/*recovery*", "恢复演练日志"),
        ("/opt/*restore*", "恢复脚本"),
        ("/usr/local/bin/*restore*", "恢复脚本"),
    ]:
        hits = glob.glob(pattern)
        for h in hits[:2]:
            msgs.append("✅ %s: %s" % (label, h))
    msgs.append("⚠️ 请人工核查是否定期执行恢复演练（至少每季度一次）并留存记录")
    return STATUS_MANUAL, "；".join(msgs)


# ---------------- MFA 多因素鉴别 (8.1.4.1 e 三级) ----------------

def check_mfa():
    """SSH/登录是否启用 MFA（Google Authenticator / Duo / pam_otp / yubikey）"""
    msgs, status = [], STATUS_MANUAL
    # PAM 栈查 pam_google_authenticator / pam_duo / pam_yubico
    for pam_cfg in ("/etc/pam.d/sshd", "/etc/pam.d/login", "/etc/pam.d/sudo"):
        txt = read_file(pam_cfg)
        if not txt: continue
        for mfa_mod in ("pam_google_authenticator", "pam_duo", "pam_yubico", "pam_pkcs11", "pam_radius", "pam_shield"):
            if mfa_mod in txt:
                msgs.append("✅ %s 启用 MFA 模块: %s" % (pam_cfg, mfa_mod)); status = STATUS_PASS
                break
    # SSH 公钥认证 + 密码禁用（也算双因素一种）
    rc, sshd = run_cmd(["cat", "/etc/ssh/sshd_config"])
    if rc == 0:
        if re.search(r"PubkeyAuthentication\s+yes", sshd, re.I) and re.search(r"PasswordAuthentication\s+no", sshd, re.I):
            msgs.append("✅ SSH 启用密钥认证+禁用密码（可视为强鉴别）")
    # /etc/security/pam_env.conf / pam_access.conf
    if os.path.isfile("/etc/google_authenticator"):
        msgs.append("⚠️ /etc/google_authenticator 系统级 OTP 配置（注意安全）"); status = STATUS_PASS
    msgs.append("【三级必查】请人工核查：管理员 SSH 是否配置 OTP/Duo/YubiKey；Web 管理后台是否强制 MFA（短信/邮箱/TOTP）")
    return status, "；".join(msgs)


# ---------------- 授权冗余/多余账户 (8.1.4.2 e) ----------------

def check_unused_accounts():
    """检测过期/闲置/多余账户"""
    msgs, status = [], STATUS_PASS
    # 1. 空口令账户
    rc, out = run_cmd(["bash", "-c",
        "awk -F: '($2==\"\" || $2==\"!\") && $3>=1000 {print $1}' /etc/shadow 2>/dev/null"])
    if rc == 0 and out.strip():
        msgs.append("❌ 存在空口令/锁定账户: %s" % out.strip()); status = STATUS_FAIL
    # 2. UID >=1000 非系统账户数 + 最近未登录
    rc2, out2 = run_cmd(["bash", "-c",
        "awk -F: '$3>=1000 {print $1}' /etc/passwd | wc -l; "
        "lastlog --time +90 2>/dev/null | grep -v 'Never' | wc -l || echo 0"])
    parts = out2.strip().split()
    if len(parts) >= 2:
        total_users = int(parts[0])
        active_90d = int(parts[1])
        idle = total_users - active_90d
        if idle > 0:
            msgs.append("⚠️ 本地非系统账户 %d 个，其中 %d 个 90 天未登录（应禁用/清理）" % (total_users, idle))
            status = STATUS_WARN
        else:
            msgs.append("✅ 本地非系统账户 %d 个，均 90 天内活跃" % total_users)
    # 3. sudoers 中 NOPASSWD
    rc3, out3 = run_cmd(["bash", "-c",
        "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"])
    if rc3 == 0 and out3.strip():
        msgs.append("⚠️ sudo 存在 NOPASSWD 条目:\n   %s" % out3.strip().splitlines()[0][:120])
        status = STATUS_WARN
    return status, "；".join(msgs)


# ---------------- 数据备份 ----------------

def check_backup_cron():
    content = ""
    for f in ("/etc/crontab",):
        content += read_file(f)
    rc, out = run_cmd(["bash", "-c", "ls /etc/cron.d/ /var/spool/cron/ 2>/dev/null"], timeout=10)
    files = out.strip()
    kw = re.compile(r"(backup|dump|tar|rsync|mysqldump|pg_dump|xtrabackup)", re.I)
    if kw.search(content) or (rc == 0 and files):
        if kw.search(content):
            return STATUS_PASS, "crontab中发现备份相关任务"
        return STATUS_MANUAL, "发现定时任务(%s)，请人工核查是否包含有效备份任务及异地备份" % files[:120]
    return STATUS_MANUAL, "未发现备份类定时任务，请人工核查重要数据备份策略、备份介质场外存放及恢复演练记录"


# ---------------- 强制访问控制 (SELinux/AppArmor) ----------------

def check_mac():
    """检查强制访问控制：SELinux 或 AppArmor 或 MAC 模式"""
    msgs, status = [], STATUS_PASS
    found = False
    # SELinux
    rc, out = run_cmd(["getenforce"])
    if rc == 0:
        val = out.strip().upper()
        if val in ("ENFORCING", "PERMISSIVE"):
            found = True
            if val == "ENFORCING":
                msgs.append("SELinux 运行于 Enforcing 模式（强制访问控制已启用）")
            else:
                msgs.append("SELinux 运行于 Permissive 模式（仅记录不强制）")
                status = STATUS_WARN
        elif val == "Disabled":
            msgs.append("SELinux 已禁用")
    # AppArmor
    rc2, out2 = run_cmd(["aa-status"])
    if rc2 == 0 and "profiles are in enforce mode" in out2.lower():
        found = True
        n = re.search(r"(\d+)\s+profiles? are in enforce mode", out2, re.I)
        if n:
            msgs.append("AppArmor 启用中，%d 个 profile 处于 enforce 模式" % int(n.group(1)))
        else:
            msgs.append("AppArmor 启用中")
    # grsecurity / RHEL7+ targeted 模式检查
    if not found:
        rc3, out3 = run_cmd(["cat", "/proc/self/attr/current"])
        if rc3 == 0 and out3.strip() and out3.strip() != "unconfined":
            found = True
            msgs.append("内核安全上下文: %s" % out3.strip())
    if not found:
        # 检查内核配置
        rc4, out4 = run_cmd(["grep", "-iE", "(selinux|apparmor|smack)",
                            "/boot/config-$(uname -r) 2>/dev/null || /boot/config-$(uname -r)"])
        if rc4 == 0:
            msgs.append("内核支持 MAC，但未检测到 SELinux/AppArmor 运行")
        else:
            msgs.append("未检测到 SELinux / AppArmor / Smack 强制访问控制框架")
        status = STATUS_FAIL
    return status, "；".join(msgs)


# ---------------- 可信验证 (TPM/TCM) ----------------

def check_tpm():
    """检查 TPM/TCM 可信启动和硬件模块"""
    msgs, status = [], STATUS_PASS
    found_tpm = False
    # 1. /dev/tpm* 设备存在
    import glob as _glob
    devs = _glob.glob("/dev/tpm*") + _glob.glob("/dev/tpmrm*") + _glob.glob("/dev/tcm*")
    if devs:
        found_tpm = True
        msgs.append("可信计算设备: %s" % ", ".join(os.path.basename(d) for d in devs))
    # 2. tpm2-tools
    rc, out = run_cmd(["which", "tpm2_pcrread"])
    if rc == 0:
        found_tpm = True
        msgs.append("TPM2 工具可用，可进一步验证 PCR 值")
    # 3. TCM (国密)
    rc2, _ = run_cmd(["which", "tcm_tool"])
    if rc2 == 0:
        found_tpm = True
        msgs.append("TCM 国密可信模块工具可用")
    # 4. systemd-boot / UEFI Secure Boot
    rc3, out3 = run_cmd(["mokutil", "--sb-state"])
    if rc3 == 0:
        if "SecureBoot enabled" in out3 or "SecureBoot=enabled" in out3:
            msgs.append("UEFI Secure Boot 已启用")
        else:
            msgs.append("UEFI Secure Boot 未启用")
            status = STATUS_WARN
    # 5. dm-verity (Android-like) / 完整性验证
    rc4, out4 = run_cmd(["mount"])
    if rc4 == 0 and "verity" in out4.lower():
        msgs.append("检测到 dm-verity 完整性验证挂载")
    # 6. IMA/EVM
    if os.path.isdir("/sys/kernel/security/ima"):
        msgs.append("IMA 完整性度量框架已加载")
        found_tpm = True
    if not found_tpm and status == STATUS_PASS:
        status = STATUS_WARN
        msgs.append("未检测到 TPM/TCM 可信计算硬件模块，建议三级系统加装")
    return status, "；".join(msgs)


# ---------------- 鉴别信息加密存储 ----------------

def check_auth_encrypt():
    """检查鉴别信息（shadow/口令文件）是否加密存储"""
    msgs, status = [], STATUS_PASS
    shadow_path = "/etc/shadow"
    if not os.path.isfile(shadow_path):
        msgs.append("/etc/shadow 不存在或不可读")
        return STATUS_WARN, "；".join(msgs)
    try:
        with open(shadow_path, "r") as f:
            lines = f.readlines()
    except PermissionError:
        return STATUS_MANUAL, "无法读取 /etc/shadow（权限不足），请人工核查口令加密存储方式"
    has_valid_hash = False
    has_bad_hash = False
    has_plaintext = False
    has_weak = False
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) < 2:
            continue
        pwd = parts[1]
        if not pwd or pwd in ("*", "!", "!!"):
            continue  # 锁定或无密码
        if pwd.startswith("$6$"):
            has_valid_hash = True  # SHA-512
        elif pwd.startswith("$5$"):
            has_valid_hash = True  # SHA-256
        elif pwd.startswith("$y$"):
            has_valid_hash = True  # yescrypt (Debian/Ubuntu 新默认)
        elif pwd.startswith("$argon2") or pwd.startswith("$2b$") or pwd.startswith("$2a$"):
            has_valid_hash = True  # Argon2 / bcrypt
        elif pwd.startswith("$1$"):
            has_weak = True  # MD5 旧格式
        elif pwd.startswith("$2$"):
            has_weak = True  # Blowfish 旧格式
        elif not pwd.startswith("$"):
            has_plaintext = True  # 明文！
    if has_valid_hash:
        msgs.append("使用安全哈希算法加密存储鉴别信息")
    if has_plaintext:
        status = STATUS_FAIL
        msgs.append("⚠️ 发现明文口令存储！应立即整改为 SHA-512 或 Argon2")
    if has_weak:
        status = STATUS_WARN if status == STATUS_PASS else status
        msgs.append("⚠️ 存在弱哈希格式（MD5/Blowfish），建议升级到 SHA-512 或 yescrypt")
    if not has_valid_hash and not has_plaintext:
        msgs.append("未发现有效鉴别信息加密格式，建议核查")
    return status, "；".join(msgs)


# ---------------- 审计防篡改 ----------------

def check_audit_protect():
    """检查审计防篡改：文件权限 + immutable + 远程集中存储"""
    import stat as _stat
    msgs, status = [], STATUS_PASS
    audit_logs = ["/var/log/audit/audit.log", "/var/log/audit.log",
                  "/var/log/messages", "/var/log/syslog",
                  "/var/log/secure"]
    any_exist = False
    any_immutable = False
    # 1. 文件权限检查
    for p in audit_logs:
        if os.path.isfile(p):
            any_exist = True
            try:
                st = os.stat(p)
                mode = _stat.S_IMODE(st.st_mode)
                if mode & _stat.S_IWOTH:
                    msgs.append("%s 全局可写(0%o)，应限制为 640 或 600" % (p, mode))
                    status = STATUS_WARN
                # 文件所有者 root
                if st.st_uid != 0:
                    msgs.append("%s 非 root 拥有" % p)
            except Exception:
                pass
    if not any_exist:
        msgs.append("未找到常见审计日志文件")
        status = STATUS_WARN
    # 2. immutable 属性
    for p in audit_logs[:2]:
        rc, out = run_cmd(["lsattr", p])
        if rc == 0 and "----i" in out:
            any_immutable = True
            break
    if any_immutable:
        msgs.append("审计日志已设置 immutable 属性防止误删")
    else:
        status = STATUS_WARN if status == STATUS_PASS else status
        msgs.append("审计日志未设置 immutable 防篡改属性（推荐 chattr +i 关键日志）")
    # 3. 远程集中（上一轮 check_remote_syslog 已覆盖，这里补充确认）
    rc, out = run_cmd(["grep", "-rE", "(@@|*.)", "/etc/rsyslog.conf", "/etc/rsyslog.d/"])
    if rc == 0 and out.strip():
        msgs.append("rsyslog 已配置远程日志转发")
    return status, "；".join(msgs)


# ---------------- HIDS 入侵检测 ----------------

def check_hids():
    """检查是否部署主机入侵检测系统"""
    msgs, status = [], STATUS_PASS
    hids_list = [
        ("wazuh", ["wazuh-manager", "wazuh-agent", "wazuh-indexer"]),
        ("ossec", ["ossec-hids", "ossec-agentd", "ossec-remoted"]),
        ("snort", ["snort", "snortd"]),
        ("suricata", ["suricata", "suricata.service"]),
        ("auditd", ["auditd"]),
        ("tetagon/insurvo", ["insurvo", "tetagon"]),
        ("奇安信EDR", ["qax-360edr", "qaxhids"]),
        ("深信服EDR", ["sfedr", "sangfor"]),
    ]
    found_any = False
    for name, svc_names in hids_list:
        for s in svc_names:
            rc, out = run_cmd(["systemctl", "is-active", s])
            if rc == 0 and out.strip() == "active":
                found_any = True
                msgs.append("部署: %s (服务: %s)" % (name, s))
                break
    # ps 检查（容器/systemd service 外）
    if not found_any:
        rc, out = run_cmd(["bash", "-c",
                           "ps aux | grep -iE 'wazuh|ossec|snort|suricata|edr|hids|osquery|tetagon' | grep -v grep"])
        if rc == 0 and out.strip():
            found_any = True
            lines = out.strip().splitlines()[:3]
            msgs.append("进程发现入侵检测组件: %s" % ", ".join(l.split()[11] if len(l.split()) > 11 else l.strip() for l in lines))
    if not found_any:
        status = STATUS_WARN
        msgs.append("未检测到 HIDS/EDR 组件，三级系统建议部署")
    return status, "；".join(msgs)


def build_checks():
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        # 身份鉴别
        W("L-ID-1", "口令有效期与长度策略", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 a)",
          "PASS_MAX_DAYS≤90，PASS_MIN_LEN≥8", "修改/etc/login.defs配置口令策略", check_password_aging),
        W("L-ID-2", "口令复杂度(PAM)", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 a)",
          "启用pam_pwquality，要求字母数字特殊字符组合",
          "在/etc/pam.d/system-auth配置pam_pwquality.so minlen=8 dcredit=-1 ucredit=-1 ocredit=-1", check_password_complexity),
        W("L-ID-3", "登录失败锁定", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 b)",
          "启用pam_faillock，连续失败后锁定账户",
          "配置pam_faillock.so deny=5 unlock_time=600", check_login_lockout),
        W("L-ID-4", "禁止root远程直接登录", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 c)",
          "sshd PermitRootLogin=no", "修改/etc/ssh/sshd_config后重启sshd", check_ssh_root_login),
        W("L-ID-5", "SSH鉴别参数加固", CAT_IDENTITY, LEVEL_L3, "8.1.4.1 c)",
          "MaxAuthTries≤4，限制口令爆破", "配置MaxAuthTries 4并考虑密钥认证", check_ssh_params),
        W("L-ID-6", "会话超时自动退出", CAT_IDENTITY, LEVEL_ALL, "8.1.4.1 b)",
          "设置TMOUT≤600秒", "在/etc/profile设置TMOUT=600并export", check_login_timeout),
        W("L-ID-7", "两种以上鉴别技术", CAT_IDENTITY, LEVEL_L3, "8.1.4.1 d)",
          "三级系统应采用口令+动态口令/证书等组合鉴别",
          "部署双因素认证或堡垒机MFA", None),

        # 访问控制
        W("L-AC-1", "空口令账户检查", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 a)",
          "不存在空口令账户", "为所有账户设置强口令或锁定账户", check_empty_password),
        W("L-AC-2", "唯一UID=0账户", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 a)",
          "仅root账户UID=0", "删除或修改其他UID=0账户", check_uid0),
        W("L-AC-3", "重要文件权限", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 c)",
          "/etc/passwd≤644、/etc/shadow≤640", "chmod修正关键文件权限", check_file_perm),
        W("L-AC-4", "默认UMASK加固", CAT_ACCESS, LEVEL_L3, "8.1.4.2 c)",
          "UMASK为027或077", "修改/etc/login.defs UMASK为027", check_umask),
        W("L-AC-5", "sudo授权最小化", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 b)",
          "无NOPASSWD免密授权，按岗位授权", "审计/etc/sudoers，消除NOPASSWD", check_sudoers),
        W("L-AC-6", "全局可写文件检查", CAT_ACCESS, LEVEL_L3, "8.1.4.2 c)",
          "/etc下不存在全局可写文件", "修正全局可写文件权限", check_world_writable),
        W("L-AC-7", "三权分立/管理角色分离", CAT_ACCESS, LEVEL_L3, "8.1.4.2 f)",
          "系统管理员、安全管理员、审计管理员权限分离",
          "建立独立管理角色账户，分散特权", None),

        # 安全审计
        W("L-AU-1", "auditd审计服务", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 a)",
          "auditd运行并开机自启", "systemctl enable --now auditd", check_auditd),
        W("L-AU-2", "日志服务运行", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 a)",
          "rsyslog/journald运行中", "systemctl enable --now rsyslog", check_rsyslog),
        W("L-AU-3", "日志文件权限保护", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 b)",
          "关键日志权限≤640，防止篡改删除", "chmod 640 /var/log/messages 等", check_log_perm),
        W("L-AU-4", "日志集中留存(远程转发)", CAT_AUDIT, LEVEL_L3, "8.1.4.3 d)",
          "审计日志发送至日志服务器，留存≥6个月",
          "rsyslog配置@@logserver转发，日志服务器留存6个月以上", check_remote_syslog),

        # 入侵防范
        W("L-IN-1", "主机防火墙", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 c)",
          "firewalld/nftables运行，最小开放原则", "启用防火墙，仅开放业务必需端口", check_firewall),
        W("L-IN-2", "高危端口管控", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 c)",
          "关闭Telnet/FTP/rsh等高危服务端口", "关闭并卸载高危服务", check_dangerous_ports),
        W("L-IN-3", "SSH协议安全", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 a)",
          "仅SSHv2，禁空口令，关闭X11转发", "加固/etc/ssh/sshd_config", check_ssh_protocol),
        W("L-IN-4", "高风险服务管控", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 a)",
          "关闭telnet/vsftpd/rsh/cups等非必要服务", "systemctl disable --now 关闭非必要服务", check_unneeded_services),
        W("L-IN-5", "补丁更新管理", CAT_INTRUSION, LEVEL_ALL, "8.1.4.4 b)",
          "系统及关键组件补丁及时更新", "定期yum/apt更新，关注OpenSSL/openssh漏洞", check_patch_hint),

        # 恶意代码防范
        W("L-MW-1", "防病毒/恶意代码措施", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 a)",
          "部署防病毒软件或可信验证机制", "部署企业级杀软或主机白名单", check_antivirus),
        W("L-MW-2", "病毒库/规则库更新", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 b)",
          "病毒库定期自动更新", "配置病毒库自动更新并留存记录", check_av_update),
        W("L-MW-4", "ClamAV安装与clamd运行", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 a)",
          "已部署恶意代码检测组件且守护进程运行（clamav-daemon/clamd/freshclam）",
          "安装clamav/clamav-daemon并 systemctl enable --now clamav-daemon",
          check_clamav_service),
        W("L-MW-5", "ClamAV病毒库7天内更新", CAT_MALWARE, LEVEL_ALL, "8.1.4.5 b)",
          "病毒库文件（.cvd/.cld）更新时间在7天内",
          "启用freshclam定时更新，或配置内网更新源", check_clamav_signature),
        W("L-MW-3", "统一防病毒管理", CAT_MALWARE, LEVEL_L3, "8.1.4.5 c)",
          "集中管控的防病毒体系", "部署企业版管控中心统一策略与告警", None),

        # 数据备份
        W("L-BK-1", "重要数据备份", CAT_BACKUP, LEVEL_ALL, "8.1.4.6 a)",
          "重要数据定期备份，备份介质场外存放", "制定备份策略(cron+rsync/备份软件)", check_backup_cron),
        W("L-BK-2", "异地备份/冗余", CAT_BACKUP, LEVEL_L3, "8.1.4.6 b)",
          "三级系统应提供异地数据级备份与重要设备冗余",
          "建立异地备份机制，关键设备/链路冗余部署", None),

        # 强制访问控制 (新增)
        W("L-MAC-1", "强制访问控制(MAC)", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 c)",
          "启用SELinux Enforcing模式或AppArmor enforce模式",
          "RHEL/CentOS: getenforce → Enforcing; Ubuntu/Debian: aa-status → enforce", check_mac),

        # 可信验证 (新增)
        W("L-TPM-1", "可信验证(TPM/TCM SecureBoot)", CAT_ACCESS, LEVEL_L3, "8.1.4.6 a)",
          "三级系统应启用可信启动链(TPM/TCM+UEFI Secure Boot)",
          "BIOS/UEFI启用Secure Boot + TPM2.0；启用IMA/EVM完整性度量", check_tpm),

        # 鉴别信息加密存储 (新增)
        W("L-ENC-1", "鉴别信息加密存储(shadow哈希)", CAT_IDENTITY, LEVEL_L3, "8.1.4.8 c)",
          "鉴别信息应使用不可逆加密算法存储(禁止明文/弱哈希)",
          "确保 /etc/shadow 使用 SHA-512 或 yescrypt 哈希格式", check_auth_encrypt),

        # 审计防篡改 (新增)
        W("L-AU-5", "审计防篡改保护", CAT_AUDIT, LEVEL_ALL, "8.1.4.3 c)",
          "审计日志文件权限≤640，关键文件设置immutable属性，远程集中存储",
          "chattr +i /var/log/audit/audit.log；rsyslog@@logserver转发", check_audit_protect),

        # HIDS (新增)
        W("L-HIDS-1", "主机入侵检测系统(HIDS/EDR)", CAT_INTRUSION, LEVEL_L3, "8.1.4.4 c)",
          "三级系统应部署主机入侵检测/终端检测响应系统",
          "部署Wazuh/OSSEC/Suricata/奇安信EDR/深信服EDR等HIDS/EDR", check_hids),

        # ===== A类补齐：之前 clause 完全缺失的 =====
        # 8.1.4.10 a) 剩余信息保护
        W("L-RI-1", "剩余信息保护(磁盘擦除/自动清零)", CAT_IDENTITY, LEVEL_ALL, "8.1.4.10 a)",
          "鉴别信息/敏感文件删除后空间自动清零；安全擦除工具可用",
          "/tmp 使用 tmpfs；分区启用 discard；shred 可用；LUKS/dm-crypt 加密",
          check_remaining_info_protect),
        # 8.1.4.2 d) 统一安全等级标记
        W("L-SL-1", "统一安全等级标记(SELinux context)", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 d)",
          "文件/进程有 SELinux/Smack 安全标记(context)",
          "SELinux Enforcing 模式下 ls -Z 显示完整 user:role:type:level context",
          check_security_label),
        # 8.1.4.9 b) 异地备份
        W("L-BK-3", "异地备份/场外存放", CAT_BACKUP, LEVEL_L3, "8.1.4.9 b)",
          "三级系统重要数据异地备份；支持 NAS/NFS/SMB/rsync+SSH/云备份",
          "异地 NAS 挂载点；rsync 远程 cron；restic/borg 等云备份工具",
          check_offsite_backup),
        # 8.1.4.7 b) 恢复演练
        W("L-REC-1", "完整性破坏后恢复演练(三级)", CAT_BACKUP, LEVEL_L3, "8.1.4.7 b)",
          "定期执行备份恢复演练并留存记录（建议每季度一次）",
          "保留恢复演练日志/报告", check_recovery_test),
        # 8.1.4.1 e) MFA
        W("L-MFA-1", "MFA 多因素鉴别(三级)", CAT_IDENTITY, LEVEL_L3, "8.1.4.1 e)",
          "三级系统管理员登录使用两种以上鉴别技术（密码+密钥/OTP/Duo/YubiKey）",
          "PAM 配置 pam_google_authenticator / pam_duo；SSH 密钥+禁用密码", check_mfa),
        # 8.1.4.2 e) 授权冗余
        W("L-RED-1", "防止授权冗余/未授权访问", CAT_ACCESS, LEVEL_ALL, "8.1.4.2 e)",
          "无空口令账户；定期清理 90 天未登录账户；sudoers 无 NOPASSWD",
          "awk 扫 /etc/shadow 空口令；lastlog 扫闲置账户；sudoers 扫 NOPASSWD",
          check_unused_accounts),
    ]
