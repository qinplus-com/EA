# -*- coding: utf-8 -*-
"""新增场景检测：无线网络安全、虚拟化/云主机、容器安全、IPv6
说明：core.models 中未定义 CAT_DEV，虚拟化与容器相关项归入 CAT_APP（应用与数据安全层）；
无线与 IPv6 相关项归入 CAT_NET。
取证原则：能从目标机取到证据才判 PASS/FAIL/WARN，取不到一律 STATUS_MANUAL 并注明“需人工核查”。
"""
import re
import shlex

from core.models import (CheckItem, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL,
                         CAT_NET, CAT_APP, LEVEL_ALL, LEVEL_L3)
from .platform_util import run_cmd, run_powershell


def _ps(script, timeout=30):
    """执行 PowerShell 并只返回输出文本"""
    return run_powershell(script, timeout)[1]


# ---------------- 无线网络安全 ----------------

def check_wireless_encryption(platform):
    """无线网卡/已保存配置的加密算法（WEP/TKIP 属弱加密）"""
    if platform == "windows":
        rc, out = run_cmd(["netsh", "wlan", "show", "interfaces"])
        if rc != 0 or not out.strip():
            return STATUS_MANUAL, "无法读取无线网卡信息（netsh 无输出），需人工核查无线接入加密方式"
        auth = [a.strip() for a in re.findall(
            r"(?:Authentication|身份验证)\s*[:：]\s*(.+)", out)]
        cipher = [c.strip() for c in re.findall(
            r"(?:Cipher|加密算法|密码)\s*[:：]\s*(.+)", out)]
        if not auth:
            return STATUS_MANUAL, "未解析到无线认证/加密算法字段（可能未连接无线网络），需人工核查"
        weak = [a for a in auth + cipher
                if re.search(r"WEP|TKIP|OPEN|NONE|无", a, re.I)]
        if weak:
            return STATUS_FAIL, "无线网络使用弱加密/开放认证: %s" % "、".join(sorted(set(weak)))
        return STATUS_PASS, "无线网络加密方式: %s" % "、".join(sorted(set(auth + cipher)))
    # Linux
    rc, out = run_cmd(["bash", "-c",
                       "nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -i wireless"],
                      timeout=20)
    names = [l.split(":")[0] for l in (out or "").splitlines() if l.strip()]
    if rc != 0 or not names:
        rc2, out2 = run_cmd(["bash", "-c", "iwconfig 2>/dev/null | grep -i 'IEEE 802.11'"],
                            timeout=15)
        if rc2 == 0 and out2.strip():
            if re.search(r"Encryption key:off", out2, re.I):
                return STATUS_FAIL, "无线网卡未启用加密(Encryption key:off)"
            return STATUS_MANUAL, "检测到无线网卡但无法读取加密算法，需人工核查 iw/nmcli 配置"
        return STATUS_MANUAL, "未检测到无线连接配置（nmcli/iwconfig 无输出），需人工核查无线接入方式"
    weak = []
    good = []
    for name in names[:5]:
        rc3, info = run_cmd(
            ["bash", "-c", "nmcli connection show %s 2>/dev/null" % shlex.quote(name)], timeout=20)
        if rc3 != 0:
            continue
        m = re.search(r"key-mgmt:\s*(\S+)", info, re.I)
        if not m:
            continue
        val = m.group(1).strip().lower()
        if val in ("none", "wep"):
            weak.append("%s(%s)" % (name, val))
        else:
            good.append("%s(%s)" % (name, val))
    if weak:
        return STATUS_FAIL, "无线连接使用开放/WEP弱加密: %s" % "、".join(weak)
    if good:
        return STATUS_PASS, "无线连接加密方式: %s" % "、".join(good)
    return STATUS_MANUAL, "未能读取无线连接的key-mgmt配置，需人工核查"


def check_wireless_wps():
    """WPS 一键配网状态（终端侧无对应接口，需登录AP管理后台核查）"""
    return STATUS_MANUAL, ("WPS状态无法从终端侧取证，需人工核查无线AP/路由器管理后台："
                           "关闭WPS一键配网（PIN/按钮配对存在暴力破解风险）")


def check_wireless_guest_isolation():
    """访客网络与内网隔离（需在AP/交换机侧核查VLAN与ACL）"""
    return STATUS_MANUAL, ("访客网络隔离需人工核查：访客SSID应独立VLAN，"
                           "并通过ACL禁止访问内网业务网段与管理网段")


# ---------------- 虚拟化 / 云主机 --------------

VM_SIGN = r"VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Hyper-V|Microsoft Corporation|" \
          r"OpenStack|Amazon|Alibaba|Aliyun|Huawei|云|Bochs|Parallels|innotek"


def check_virtualization(platform):
    """是否运行于虚拟机，以及虚拟化增强工具是否安装"""
    if platform == "windows":
        out = _ps(
            "$c=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue;"
            "if($c){'M:'+$c.Manufacturer+'|'+$c.Model}else{'M:NONE'};"
            "$svc=@();foreach($n in 'VMTools','vm3dservice','VBoxService','VBoxSF',"
            "'vmicheartbeat','vmicvss','qemu-ga','QEMU-GA'){"
            "$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
            "if($s){$svc+=$n+'='+$s.Status}};'S:'+($svc -join ',')")
        m = re.search(r"M:(.*)", out)
        mfr = m.group(1).strip() if m else ""
        svc = re.search(r"S:(.*)", out)
        services = [x for x in (svc.group(1).split(",") if svc else []) if x.strip()]
        if re.search(VM_SIGN, mfr, re.I):
            running = [s for s in services if "Running" in s]
            if running:
                return STATUS_PASS, "运行于虚拟化平台(%s)，增强工具运行中: %s" % (
                    mfr, "、".join(running))
            return STATUS_WARN, "运行于虚拟化平台(%s)，未检测到虚拟化增强工具运行" % mfr
        if mfr and mfr.upper() != "NONE":
            return STATUS_PASS, "运行于物理主机(%s)，无需虚拟化增强工具" % mfr
        return STATUS_MANUAL, "未能读取主机厂商/型号，需人工核查是否为虚拟化或云主机"
    # Linux
    rc, out = run_cmd(["systemd-detect-virt"], timeout=10)
    virt = (out or "").strip().lower()
    if rc == 0 and virt and virt != "none":
        running = []
        for n in ("open-vm-tools", "vmtoolsd", "qemu-guest-agent", "vboxadd", "vboxadd-service"):
            rc2, st = run_cmd(["systemctl", "is-active", n], timeout=10)
            if st.strip() == "active":
                running.append(n)
        if running:
            return STATUS_PASS, "运行于虚拟化平台(%s)，增强工具运行中: %s" % (virt, "、".join(running))
        return STATUS_WARN, "运行于虚拟化平台(%s)，未检测到增强工具(open-vm-tools/qemu-guest-agent)" % virt
    if rc == 0 and virt == "none":
        return STATUS_PASS, "未运行于虚拟化平台（systemd-detect-virt=none），物理主机"
    # systemd-detect-virt 不可用时退回 DMI 信息
    rc3, dmi = run_cmd(["bash", "-c",
                        "cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name "
                        "2>/dev/null | tr '\\n' ' '"], timeout=10)
    text = (dmi or "").strip() if rc3 == 0 else ""
    if "命令不存在" in (dmi or ""):
        text = ""
    if text and re.search(VM_SIGN, text, re.I):
        return STATUS_WARN, "DMI信息显示可能为虚拟化平台(%s)，需人工核查增强工具与隔离配置" % text[:80]
    if text:
        return STATUS_PASS, "DMI信息显示为物理主机: %s" % text[:80]
    return STATUS_MANUAL, "无法获取虚拟化识别信息（systemd-detect-virt/dmidecode 不可用），需人工核查"


def check_virt_shared_snapshot(platform):
    """虚拟机共享文件夹/快照（快照只能从虚拟化平台侧核查）"""
    if platform == "windows":
        out = _ps(
            "$r=@();foreach($n in 'vmhgfs','VBoxSF','vboxsf','VBoxGuest'){"
            "$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
            "if($s){$r+=$n+'='+$s.Status}};if($r){$r -join ','}else{'NONE'}")
        if "Running" in out:
            return STATUS_WARN, "检测到虚拟机共享文件夹驱动运行: %s，建议关闭与宿主机的共享" % out.strip()
        return STATUS_MANUAL, "未检测到共享文件夹驱动；虚拟机快照需在虚拟化平台人工核查"
    rc, out = run_cmd(["bash", "-c",
                       "mount | grep -Ei 'vmhgfs|vboxsf|9p|virtiofs' || true"], timeout=10)
    if rc != 0:
        return STATUS_MANUAL, "无法读取目标机挂载信息，需人工核查虚拟机共享目录与快照"
    if (out or "").strip():
        return STATUS_WARN, "检测到虚拟机共享目录挂载: %s，建议关闭与宿主机的共享" % out.strip()[:200]
    return STATUS_MANUAL, "未检测到共享目录挂载；虚拟机快照需在虚拟化平台人工核查"


# ---------------- 容器安全 --------------

def _docker_cmd(cmd, timeout=20):
    rc, out = run_cmd(["bash", "-c", cmd], timeout=timeout)
    return rc, out


def _docker_available(platform):
    """返回 (是否安装容器运行时, 服务/命令证据)"""
    if platform == "windows":
        out = _ps("$c=Get-Command docker -ErrorAction SilentlyContinue;if($c){'CLI'}else{'NOCLI'};"
                  "$s=Get-Service docker -ErrorAction SilentlyContinue;if($s){'SVC:'+$s.Status}else{'NOSVC'}")
        return "NOCLI" not in out, out.strip()
    rc, out = run_cmd(["bash", "-c", "command -v docker || command -v podman || true"], timeout=15)
    return (rc == 0 and bool((out or "").strip())), (out or "").strip()


def check_docker_present(platform):
    """Docker 是否存在及 daemon 是否可用"""
    installed, info = _docker_available(platform)
    if not installed:
        return STATUS_PASS, "未检测到Docker/Podman容器运行时（Get-Command/command -v 无结果），不适用"
    if platform == "windows":
        if "Running" in info:
            return STATUS_PASS, "Docker服务运行中（Windows容器运行时）"
    else:
        rc, ver = _docker_cmd("docker version --format '{{.Server.Version}}' 2>&1")
        if rc == 0 and re.match(r"\d+(\.\d+)+", (ver or "").strip()):
            return STATUS_PASS, "检测到Docker运行中，Server版本 %s" % ver.strip()
    return STATUS_MANUAL, "检测到容器运行时但daemon不可用（%s），需人工核查启动状态与权限" % info[:120]


def check_docker_tls(platform):
    """Docker daemon 是否暴露未加密远程API(tcp://0.0.0.0:2375)"""
    installed, _info = _docker_available(platform)
    if not installed:
        return STATUS_MANUAL, "未检测到Docker/Podman容器运行时，如已部署需人工核查远程API(2375/2376)"
    if platform == "windows":
        conf = _ps(
            "$p='C:\\ProgramData\\docker\\config\\daemon.json';"
            "if(Test-Path $p){(Get-Content $p -Raw)}else{''}")
        rc, listen = run_cmd(["netstat", "-ano", "-p", "TCP"], timeout=20)
        open2375 = [l for l in (listen or "").splitlines()
                    if ":2375" in l and "LISTENING" in l.upper() and not l.strip().startswith("127.")]
    else:
        rc, conf = run_cmd(["bash", "-c",
                            "cat /etc/docker/daemon.json 2>/dev/null || true"], timeout=15)
        rc2, listen = run_cmd(["bash", "-c", "ss -tln 2>/dev/null || netstat -tln 2>/dev/null"],
                              timeout=20)
        open2375 = [l for l in (listen or "").splitlines()
                    if ":2375" in l and not re.search(r"127\.0\.0\.1:2375", l)]
    if open2375:
        return STATUS_FAIL, "Docker远程API 2375端口对外监听（未加密），主机会被完全控制"
    if re.search(r"tcp://(0\.0\.0\.0|\[::\]|\*)?:2375", conf or "", re.I):
        return STATUS_FAIL, "daemon.json 配置 tcp://0.0.0.0:2375 未加密远程访问"
    if re.search(r"2376", conf or "") and re.search(r"tls", conf or "", re.I):
        return STATUS_PASS, "Docker开启TLS远程访问(2376)且已配置证书"
    if re.search(r"tcp://", conf or "", re.I):
        return STATUS_WARN, "Docker配置了TCP远程访问但未确认TLS，请人工核查证书与来源限制"
    return STATUS_PASS, "Docker未配置未加密远程TCP访问（仅本地socket）"


def check_docker_privileged(platform):
    """是否存在 --privileged 特权容器"""
    installed, _info = _docker_available(platform)
    if not installed:
        return STATUS_MANUAL, "未检测到Docker/Podman容器运行时，如已部署需人工核查特权容器"
    if platform == "windows":
        rc, out = run_cmd(["docker", "ps", "-q"], timeout=20)
        if rc != 0:
            return STATUS_MANUAL, "无法执行docker ps（daemon未运行或无权限），需人工核查特权容器"
        ids = [i.strip() for i in (out or "").splitlines() if i.strip()]
        if not ids:
            return STATUS_PASS, "当前无运行中的容器，不存在privileged容器"
        rc2, out2 = run_cmd(["docker", "inspect", "--format",
                             "{{.Name}}={{.HostConfig.Privileged}}"] + ids, timeout=25)
    else:
        rc, out = run_cmd(["bash", "-c",
                           "ids=$(docker ps -q 2>/dev/null);"
                           "if [ -z \"$ids\" ]; then echo EMPTY; "
                           "else docker inspect --format '{{.Name}}={{.HostConfig.Privileged}}' $ids; fi"],
                          timeout=30)
        out2 = out
        rc2 = rc
        if "EMPTY" in (out or ""):
            return STATUS_PASS, "当前无运行中的容器，不存在privileged容器"
    if rc2 != 0:
        return STATUS_MANUAL, "无法读取容器配置（daemon权限不足或容器未运行），需人工核查privileged"
    priv = [l.strip() for l in (out2 or "").splitlines() if l.strip().endswith("=true")]
    if priv:
        return STATUS_FAIL, "存在特权(--privileged)容器: %s，可获取宿主机全部权限" % "、".join(priv[:8])
    return STATUS_PASS, "运行中的容器均未启用privileged特权模式"


def check_docker_image_tag(platform):
    """镜像是否使用 latest 标签（版本不可控）"""
    installed, _info = _docker_available(platform)
    if not installed:
        return STATUS_MANUAL, "未检测到Docker/Podman容器运行时，如已部署需人工核查镜像标签"
    if platform == "windows":
        rc, out = run_cmd(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=20)
    else:
        rc, out = run_cmd(["bash", "-c",
                           "docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null"], timeout=20)
    if rc != 0 or not (out or "").strip():
        return STATUS_MANUAL, "无法读取镜像列表（未安装Docker或daemon不可用），需人工核查镜像标签"
    tags = [l.strip() for l in out.splitlines() if l.strip()]
    latest = [t for t in tags if t.lower().endswith(":latest")]
    if latest:
        return STATUS_WARN, "存在latest标签镜像(%d个): %s，建议使用固定版本标签" % (
            len(latest), "、".join(latest[:6]))
    return STATUS_PASS, "镜像均使用固定标签，未发现latest标签"


def check_docker_socket(platform):
    """Docker socket/管道权限"""
    installed, _info = _docker_available(platform)
    if not installed:
        return STATUS_MANUAL, "未检测到Docker/Podman容器运行时，如已部署需人工核查socket权限"
    if platform == "windows":
        return STATUS_MANUAL, ("Windows使用命名管道 \\\\.\\pipe\\docker_engine，"
                               "需人工核查docker组与管道ACL权限")
    rc, out = run_cmd(["bash", "-c",
                       "stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null"], timeout=10)
    text = (out or "").strip()
    if rc != 0 or not text:
        return STATUS_MANUAL, "未找到/var/run/docker.sock（Docker可能未运行），需人工核查socket权限"
    parts = text.split()
    if len(parts) < 2:
        return STATUS_MANUAL, "无法解析docker.sock权限: %s" % text
    mode_str, owner = parts[0], parts[1]
    try:
        mode = int(mode_str, 8)
    except ValueError:
        return STATUS_MANUAL, "无法解析docker.sock权限: %s" % text
    if mode & 0o006:
        return STATUS_FAIL, "docker.sock 其他用户可写(%s)，等同于宿主机root权限泄露" % mode_str
    if mode & 0o060 and owner.split(":")[-1] == "docker":
        return STATUS_PASS, "docker.sock 权限 %s（%s），仅root与docker组可访问" % (mode_str, owner)
    return STATUS_WARN, "docker.sock 权限 %s（%s），请核查访问组成员是否最小化" % (mode_str, owner)


# ---------------- IPv6 --------------

def check_ipv6_tunnels(platform):
    """6to4 / Teredo / ISATAP 隧道是否禁用"""
    if platform == "windows":
        rc, out = run_cmd(["reg", "query",
                           r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                           "/v", "DisabledComponents"])
        val = None
        m = re.search(r"DisabledComponents\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out or "")
        if m:
            val = int(m.group(1), 16)
        rc2, ter = run_cmd(["netsh", "interface", "teredo", "show", "state"])
        ttype, tstate = "", ""
        mt = re.search(r"(?:Type|类型)\s*[:：]\s*(\S+)", ter or "")
        if mt:
            ttype = mt.group(1).lower()
        ms = re.search(r"(?:State|状态)\s*[:：]\s*(\S+)", ter or "")
        if ms:
            tstate = ms.group(1).lower()
        teredo_off = ttype in ("disabled", "禁用") or tstate in ("disabled", "offline", "禁用")
        if val is not None:
            if val & 0x1 or val in (0xff, 0xffffffff) or (val & 0xff) == 0xff:
                return STATUS_PASS, "已通过DisabledComponents=0x%x禁用IPv6隧道适配器(6to4/Teredo/ISATAP)" % val
            if teredo_off:
                return STATUS_WARN, ("DisabledComponents=0x%x 未禁用隧道适配器；Teredo虽关闭，"
                                     "6to4/ISATAP仍可能启用" % val)
            return STATUS_FAIL, ("6to4/Teredo/ISATAP隧道未禁用(DisabledComponents=0x%x, Teredo=%s)"
                                 % (val, ttype or tstate or "未知"))
        if teredo_off:
            return STATUS_WARN, ("未配置DisabledComponents（默认0）；Teredo已关闭(%s/%s)，"
                                 "6to4/ISATAP仍需人工核查" % (ttype or "-", tstate or "-"))
        return STATUS_MANUAL, "未读取到DisabledComponents与Teredo状态，需人工核查IPv6隧道"
    rc, out = run_cmd(["bash", "-c", "ip -6 tunnel show 2>/dev/null || true"], timeout=15)
    if rc != 0:
        return STATUS_MANUAL, "无法执行ip -6 tunnel show，需人工核查IPv6隧道接口"
    if (out or "").strip():
        return STATUS_FAIL, "存在IPv6隧道接口: %s，应禁用6to4/Teredo/ISATAP" % out.strip()[:200]
    rc2, mods = run_cmd(["bash", "-c",
                         "lsmod 2>/dev/null | grep -E '^sit|ip6_tunnel|ip6_udp_tunnel' || true"],
                        timeout=15)
    if (mods or "").strip():
        return STATUS_WARN, "未发现IPv6隧道接口，但隧道内核模块已加载: %s" % mods.strip()[:120]
    return STATUS_PASS, "未发现IPv6隧道接口与隧道内核模块"


def check_ipv6_firewall(platform):
    """IPv6 防火墙/过滤策略"""
    if platform == "windows":
        rc, out = run_cmd(["reg", "query",
                           r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                           "/v", "DisabledComponents"])
        m = re.search(r"DisabledComponents\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out or "")
        if m:
            dc = int(m.group(1), 16)
            if dc == 0xffffffff or (dc & 0xff) == 0xff:
                return STATUS_PASS, "IPv6已禁用(DisabledComponents=0x%s)，无IPv6暴露面" % m.group(1)
        fw = _ps("try{(Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+$_.Enabled}) -join ','}"
                 "catch{'ERR'}")
        if "ERR" in fw:
            return STATUS_MANUAL, "无法读取Windows防火墙配置，需人工核查IPv6策略"
        disabled = [p.split(":")[0] for p in fw.strip().split(",") if p.endswith(":False")]
        if disabled:
            return STATUS_FAIL, "防火墙未启用(%s)，IPv6流量同样不受控" % "、".join(disabled)
        return STATUS_PASS, "防火墙各配置文件均已启用，IPv6流量受同一策略保护"
    rc, out = run_cmd(["bash", "-c",
                       "cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null"], timeout=10)
    if (out or "").strip() == "1":
        return STATUS_PASS, "IPv6协议栈已禁用(disable_ipv6=1)，无IPv6暴露面"
    rc2, rules = run_cmd(["bash", "-c",
                          "ip6tables -L -n 2>/dev/null || nft list ruleset 2>/dev/null | grep -i ipv6"],
                         timeout=20)
    if rc2 != 0:
        return STATUS_MANUAL, "无法读取IPv6防火墙规则（ip6tables/nftables不可用），需人工核查"
    lines = [l for l in (rules or "").splitlines()
             if l.strip() and not re.match(r"^Chain|^target|^pkts", l.strip(), re.I)]
    if not lines:
        return STATUS_WARN, "IPv6过滤规则为空（默认放行），建议配置ip6tables/nftables策略"
    return STATUS_PASS, "已配置IPv6过滤规则(%d条)" % len(lines)


def build_checks(platform):
    """返回新增场景检测项（无线/IPv6 二级三级通用，虚拟化/容器限三级）"""
    W = lambda *a, **k: CheckItem(*a, **k)
    return [
        W("NL-WL-1", "无线网络弱加密(WEP/TKIP)", CAT_NET, LEVEL_ALL, "8.1.2.2 a)",
          "无线接入使用WPA2/WPA3(CCMP/AES)，禁止WEP/TKIP/开放认证",
          "无线AP/客户端改为WPA2-AES或WPA3，停用WEP与TKIP",
          lambda: check_wireless_encryption(platform)),
        W("NL-WL-2", "无线WPS一键配网关闭", CAT_NET, LEVEL_ALL, "8.1.4.4 a)",
          "关闭WPS（PIN码/按钮配对），防止PIN暴力破解接入",
          "登录AP管理后台关闭WPS功能",
          check_wireless_wps),
        W("NL-WL-3", "访客网络与内网隔离", CAT_NET, LEVEL_ALL, "8.1.3.2 b)",
          "访客SSID独立VLAN，ACL禁止访问内网业务与管理网段",
          "为访客网络划分独立VLAN并配置边界ACL",
          check_wireless_guest_isolation),
        W("NL-VT-1", "虚拟化/云主机识别与增强工具", CAT_APP, LEVEL_L3, "8.1.4.4 a)",
          "运行于虚拟化平台时安装增强工具（VMware Tools/open-vm-tools/qemu-guest-agent）",
          "安装并运行虚拟化增强工具，保持其版本与宿主平台匹配",
          lambda: check_virtualization(platform)),
        W("NL-VT-2", "虚拟机共享文件夹/快照管控", CAT_APP, LEVEL_L3, "8.1.4.10 a)",
          "关闭宿主机共享文件夹，及时清理含敏感数据的快照",
          "关闭VM共享文件夹；在虚拟化平台定期清理快照并核查存储加密",
          lambda: check_virt_shared_snapshot(platform)),
        W("NL-CT-1", "容器运行时存在性", CAT_APP, LEVEL_L3, "8.1.4.4 a)",
          "如部署Docker/Podman，daemon应正常运行并纳入监控",
          "非必要不部署容器运行时；部署时限制docker组权限并纳入监控",
          lambda: check_docker_present(platform)),
        W("NL-CT-2", "Docker远程API加密(2375/2376)", CAT_APP, LEVEL_L3, "8.1.2.2 a)",
          "禁止未加密tcp://0.0.0.0:2375，远程访问须TLS双向认证(2376)",
          "daemon.json 配置 tlsverify + tlscacert/tlscert/tlskey，仅监听管理网段",
          lambda: check_docker_tls(platform)),
        W("NL-CT-3", "容器特权模式(--privileged)", CAT_APP, LEVEL_L3, "8.1.4.2 b)",
          "容器不以--privileged运行，按需授予capabilities",
          "删除--privileged，使用--cap-drop与最小cap-add",
          lambda: check_docker_privileged(platform)),
        W("NL-CT-4", "容器镜像latest标签", CAT_APP, LEVEL_L3, "8.1.4.4 b)",
          "镜像使用固定版本标签，不使用latest（版本不可控）",
          "镜像改用固定tag并定期扫描漏洞",
          lambda: check_docker_image_tag(platform)),
        W("NL-CT-5", "Docker socket 权限", CAT_APP, LEVEL_L3, "8.1.4.2 c)",
          "docker.sock 权限660且属主root:docker，禁止其他用户可写",
          "chown root:docker /var/run/docker.sock && chmod 660 /var/run/docker.sock",
          lambda: check_docker_socket(platform)),
        W("NL-IP-1", "IPv6隧道(6to4/Teredo/ISATAP)禁用", CAT_NET, LEVEL_ALL, "8.1.3.1 a)",
          "禁用6to4/Teredo/ISATAP隧道，避免绕过边界防护",
          "Windows: DisabledComponents=0xFF；Linux: 卸载 sit/ip6_tunnel 模块并删除隧道",
          lambda: check_ipv6_tunnels(platform)),
        W("NL-IP-2", "IPv6防火墙策略", CAT_NET, LEVEL_ALL, "8.1.3.2 a)",
          "IPv6禁用或纳入防火墙/ip6tables策略，默认拒绝非授权访问",
          "启用防火墙IPv6策略或配置ip6tables默认拒绝规则",
          lambda: check_ipv6_firewall(platform)),
    ]
