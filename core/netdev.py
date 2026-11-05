# -*- coding: utf-8 -*-
"""网络设备（防火墙/路由器/交换机）连接与厂商命令解析。

支持通过 SSH（paramiko）直登设备执行 show/display 命令，并按厂商语法解析：
  - Cisco IOS / IOS-XE / NX-OS
  - 华为 VRP
  - H3C Comware
  - Juniper JunOS
  - 锐捷 RGOS
另提供 SNMP（pysnmp）只读探测，用于拿设备型号、接口、HA 状态。

本模块只做"取事实"，等保条款判定放在 checks/network_checks.py。
"""
import re
import time

# 厂商 → 命令集。每个键的值可为字符串或候选命令列表（依次尝试，取第一个有效输出）
VENDOR_CMDS = {
    "asa": {
        "name": "Cisco ASA",
        "version": ["show version", "show version detail"],
        "config": ["show running-config"],
        "acl": ["show access-list", "show running-config | include access-list|access-group"],
        "logging": ["show logging", "show running-config | include logging|logging list"],
        "snmp": ["show snmp-server", "show running-config | include snmp"],
        "aaa": ["show running-config | include aaa|radius|tacacs"],
        "ha": ["show failover", "show running-config | include failover|redundancy"],
        "interface": ["show interface", "show ip interface brief"],
        "mgmt": ["show running-config | include line vty|access-class|transport input|ssh"],
        "paging": "terminal paging lines 0",
    },
    "cisco": {
        "name": "Cisco IOS",
        "version": ["show version", "show version detail"],
        "config": ["show running-config", "show running-config"],
        "acl": ["show access-lists", "show ip access-lists", "show access-list",
                "show running-config | include access-list|access-group"],
        "logging": ["show logging", "show running-config | include logging"],
        "snmp": ["show snmp", "show snmp-server", "show running-config | include snmp"],
        "aaa": ["show running-config | include aaa|tacacs|radius|login"],
        "ha": ["show standby brief", "show failover", "show redundancy",
               "show running-config | include standby|vrrp|redundancy|failover"],
        "interface": ["show ip interface brief", "show interface"],
        "mgmt": ["show running-config | include line vty|access-class|transport input"],
        "paging": "terminal length 0",
    },
    "huawei": {
        "name": "Huawei VRP",
        "version": ["display version"],
        "config": ["display current-configuration"],
        "acl": ["display acl all", "display current-configuration | include acl"],
        "logging": ["display logbuffer", "display current-configuration | include info-center"],
        "snmp": ["display snmp-agent", "display current-configuration | include snmp"],
        "aaa": ["display current-configuration | include aaa|radius|tacacs"],
        "ha": ["display vrrp brief", "display current-configuration | include vrrp"],
        "interface": ["display ip interface brief"],
        "mgmt": ["display current-configuration | include user-interface|acl"],
        "paging": "screen-length 0 temporary",
    },
    "h3c": {
        "name": "H3C Comware",
        "version": ["display version"],
        "config": ["display current-configuration"],
        "acl": ["display acl all", "display current-configuration | include acl"],
        "logging": ["display logbuffer", "display current-configuration | include info-center"],
        "snmp": ["display snmp-agent", "display current-configuration | include snmp"],
        "aaa": ["display current-configuration | include aaa|radius|tacacs"],
        "ha": ["display vrrp brief", "display current-configuration | include vrrp"],
        "interface": ["display ip interface brief"],
        "mgmt": ["display current-configuration | include user-interface|acl"],
        "paging": "screen-length disable",
    },
    "juniper": {
        "name": "Juniper JunOS",
        "version": ["show version"],
        "config": ["show configuration"],
        "acl": ["show configuration firewall", "show configuration security"],
        "logging": ["show log messages", "show configuration syslog"],
        "snmp": ["show configuration snmp"],
        "aaa": ["show configuration system radius|tacplus"],
        "ha": ["show vrrp"],
        "interface": ["show interfaces terse"],
        "mgmt": ["show configuration system services"],
        "paging": "set cli screen-length 0",
    },
    "ruijie": {
        "name": "Ruijie RGOS",
        "version": ["show version"],
        "config": ["show running-config"],
        "acl": ["show access-lists", "show running-config | include access-list"],
        "logging": ["show logging", "show running-config | include logging"],
        "snmp": ["show snmp", "show running-config | include snmp"],
        "aaa": ["show running-config | include aaa|radius|tacacs"],
        "ha": ["show vrrp brief", "show running-config | include vrrp"],
        "interface": ["show ip interface brief"],
        "mgmt": ["show running-config | include line vty|access-class"],
        "paging": "terminal length 0",
    },
}

# 输出中表示"命令不被支持"的特征
ERR_PATTERNS = re.compile(
    r"(% ?(Invalid input|Unknown command|Error|Incomplete command|Ambiguous command)"
    r"|command not found|unable to find computer address|Bad command or file name)",
    re.I)


VENDOR_HINTS = [
    ("asa",      ("Adaptive Security Appliance", "Cisco ASA", "cisco asa")),
    ("cisco",    ("Cisco IOS", "Cisco IOS XE", "Cisco NX-OS", "Cisco IOS Software", "cisco")),
    ("huawei",   ("Huawei Versatile Routing Platform", "Huawei VRP", "VRP (R) software",
                  "huawei", "华为")),
    ("h3c",      ("H3C Comware", "Comware Software", "h3c", "华三")),
    ("juniper",  ("JUNOS", "Juniper Networks", "juniper", "瞻博")),
    ("ruijie",   ("Ruijie", "RGOS", "锐捷")),
]

# 仅用于 SNMP sysDescr 展示的厂商识别（这些厂商不走 SSH 命令集）
SNMP_VENDOR_HINTS = [
    ("Fortinet FortiGate", ("fortinet", "fortigate")),
    ("深信服 Sangfor", ("sangfor", "深信服")),
    ("天融信 Topsec", ("topsec", "天融信")),
    ("山石网科 Hillstone", ("hillstone", "山石网科", "山石")),
    ("绿盟 NSFOCUS", ("nsfocus", "绿盟")),
    ("启明星辰 Venustech", ("venustech", "启明星辰")),
    ("奇安信", ("qianxin", "奇安信")),
    ("Aruba", ("aruba",)),
    ("F5 BIG-IP", ("f5 networks", "big-ip")),
    ("Palo Alto", ("palo alto", "pan-os")),
    ("中兴 ZTE", ("zte", "中兴")),
    ("新华三 H3C", ("h3c", "华三")),
]


def vendor_display_from_descr(descr):
    """由 SNMP sysDescr / 版本行识别 (厂商展示名, 命令集键)。"""
    low = (descr or "").lower()
    for vk, hints in VENDOR_HINTS:
        if any(h.lower() in low for h in hints):
            return VENDOR_CMDS[vk]["name"], vk
    for name, hints in SNMP_VENDOR_HINTS:
        if any(h.lower() in low for h in hints):
            return name, ""
    return "未知厂商", "auto"

_PROMPT_RE = re.compile(r"[^\r\n]*[>#]\s*$")


class NetdevError(RuntimeError):
    pass


class NetdevConnector:
    """SSH 直登网络设备并取 show/display 输出。"""

    def __init__(self, host, port=22, user="", password="", keyfile="",
                 vendor="auto", timeout=15, enable_password=""):
        self.host = host
        self.port = int(port or 22)
        self.user = user or ""
        self.password = password or ""
        self.keyfile = keyfile or ""
        self.vendor_cfg = (vendor or "auto").lower()
        self.timeout = int(timeout or 15)
        self.enable_password = enable_password or ""
        self.client = None
        self.shell = None
        self._vendor = None
        self._vendor_display = ""
        self._cache = {}
        self.mode = "shell"      # shell | exec
        self.banner = ""

    # ---------------- 连接 ----------------
    def connect(self):
        try:
            import paramiko
        except ImportError:
            raise NetdevError("缺少 paramiko 依赖，请执行：pip install paramiko")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.host, port=self.port, username=self.user,
                password=self.password or None,
                key_filename=self.keyfile or None,
                timeout=self.timeout, banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=not self.password, allow_agent=not self.password,
            )
        except paramiko.AuthenticationException:
            self.client = None
            raise NetdevError("设备 SSH 认证失败：用户名/口令/私钥不正确")
        except Exception as e:
            self.client = None
            raise NetdevError("无法连接网络设备 %s:%s —— %s" % (self.host, self.port, e))
        try:
            self.shell = self.client.invoke_shell(width=200, height=1000)
            self.shell.settimeout(self.timeout)
            self.mode = "shell"
        except Exception:
            # 部分安全产品/网络设备禁用了交互式 shell，只能走 exec 通道
            self.shell = None
            self.mode = "exec"
            probe = ""
            for cmd in ("show version", "display version", "echo READY"):
                try:
                    probe = self._exec(cmd, timeout=10) or ""
                except Exception:
                    probe = ""
                if probe.strip():
                    break
            if not probe.strip():
                self.client.close()
                self.client = None
                raise NetdevError("设备 SSH 会话不可用（shell 与 exec 通道均无法执行命令）")
        if self.mode == "shell":
            self._drain(1.0)
            if self.enable_password:
                self._send("enable", 1.0, expect_more=True)
        self._vendor = self._detect_vendor()
        # 关分页，确保长输出一次取全（exec 模式通常无分页，失败也无妨）
        if self.mode == "shell":
            try:
                self.run(VENDOR_CMDS[self._vendor]["paging"], cache=False)
            except Exception:
                pass
        return True

    def _exec(self, cmd, timeout=None):
        """exec 通道执行单条命令。

        网络设备/安全产品的 CLI 通常禁用了 PTY，优先用 no-pty；
        Linux 类设备可能需要 PTY，故失败后回退。
        """
        if not self.client:
            raise NetdevError("尚未连接网络设备")
        timeout = timeout or self.timeout
        last_err = None
        for use_pty in (False, True):
            try:
                stdin, stdout, stderr = self.client.exec_command(
                    cmd, timeout=timeout, get_pty=use_pty)
            except TypeError:
                try:
                    stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
                except Exception as e:
                    last_err = e
                    break
            except Exception as e:
                last_err = e
                continue
            try:
                out = stdout.read().decode("utf-8", errors="replace")
            except Exception as e:
                last_err = e
                continue
            try:
                err = stderr.read().decode("utf-8", errors="replace")
            except Exception:
                err = ""
            if out.strip() or err.strip():
                return out if out.strip() else err
        raise NetdevError("设备命令执行失败：%s" % (last_err or "无输出"))

    def close(self):
        for obj, fn in ((self.shell, "close"), (self.client, "close")):
            try:
                if obj:
                    getattr(obj, fn)()
            except Exception:
                pass
        self.shell = None
        self.client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------------- 底层收发 ----------------
    def _drain(self, wait=0.3):
        buf = b""
        end = time.time() + wait
        while time.time() < end:
            try:
                if self.shell.recv_ready():
                    buf += self.shell.recv(65535)
                    end = time.time() + 0.15
                else:
                    time.sleep(0.05)
            except Exception:
                break
        return buf.decode("utf-8", errors="replace")

    def _send(self, cmd, wait=1.0, expect_more=False):
        self.shell.send(cmd + "\n")
        buf = ""
        end = time.time() + max(wait, self.timeout)
        idle = time.time() + wait
        while time.time() < end:
            try:
                if self.shell.recv_ready():
                    buf += self.shell.recv(65535).decode("utf-8", errors="replace")
                    idle = time.time() + 0.4
                    if expect_more and re.search(r"\[confirm\]|continue\?|\[yes/no\]", buf, re.I):
                        self.shell.send("y\n" if not self.enable_password else (self.enable_password + "\n"))
                        expect_more = False
                elif _PROMPT_RE.search(buf.splitlines()[-1] if buf.splitlines() else "") and time.time() > idle:
                    break
                else:
                    time.sleep(0.05)
                if time.time() > idle and buf:
                    break
            except Exception:
                break
        return buf

    # ---------------- 厂商识别 ----------------
    def _detect_vendor(self):
        if self.vendor_cfg in VENDOR_CMDS:
            return self.vendor_cfg
        # 先用 show/display version 判定（Cisco 系命令优先）
        seen = ""
        for cand in ("cisco", "huawei", "h3c", "juniper", "ruijie"):
            try:
                out = self._show_key(cand, "version")
            except Exception:
                out = ""
            if out and not is_error_output(out):
                seen += "\n" + out
                low = out.lower()
                # 型号带 ASA xxxx 即 ASA 平台（部分版本行不含 "Adaptive Security Appliance"）
                if re.search(r"\bASA\s*\d{3,4}", out, re.I):
                    return "asa"
                for vk, hints in VENDOR_HINTS:
                    if any(h.lower() in low for h in hints):
                        return vk
        # 再用完整输出兜底匹配
        low = seen.lower()
        for vk, hints in VENDOR_HINTS:
            if any(h.lower() in low for h in hints):
                return vk
        # 未命中已知厂商：从版本首行提取"厂商 设备类型"前缀（如 "QinPlus 防火墙 FW-3000"）
        m = re.search(
            r"^([A-Za-z][A-Za-z0-9\-\.]{1,20})\s+(?:防火墙|路由器|交换机|Firewall|Router|Switch)",
            (seen or "").strip(), re.I | re.M)
        if m:
            self._vendor_display = m.group(1)
        # 兜底：按 Cisco 语法探测（不影响已识别出的厂商名称）
        return "cisco"

    def _show_key(self, vendor_key, key):
        """按厂商命令候选列表依次尝试，返回第一个有效输出。"""
        cmds = VENDOR_CMDS.get(vendor_key, {}).get(key)
        if not cmds:
            return ""
        if isinstance(cmds, str):
            cmds = [cmds]
        last = ""
        for cmd in cmds:
            try:
                out = self.run(cmd, cache=False)
            except Exception:
                continue
            if out and not is_error_output(out):
                return out
            last = out or last
        return last if not is_error_output(last) else ""

    @property
    def vendor(self):
        return self._vendor or "auto"

    @property
    def vendor_name(self):
        if self._vendor_display:
            return self._vendor_display
        return VENDOR_CMDS.get(self._vendor, {}).get("name", "未知厂商")

    # ---------------- 命令执行 ----------------
    def run(self, cmd, wait=2.5, cache=True):
        if not self.client:
            raise NetdevError("尚未连接网络设备")
        if cache and cmd in self._cache:
            return self._cache[cmd]
        if self.mode == "exec":
            raw = self._exec(cmd)
        else:
            if not self.shell:
                raise NetdevError("交互式会话已断开")
            raw = self._send(cmd, wait=wait)
        out = clean_output(raw, cmd)
        if cache:
            self._cache[cmd] = out
        return out

    def show(self, key, wait=3.0):
        """按语义 key 取输出：version/config/acl/logging/snmp/aaa/ha/interface/mgmt"""
        if not self._vendor:
            return ""
        out = self._show_key(self._vendor, key)
        if out:
            return out
        # 设备不支持该命令时，回退到 running-config 中检索（多数配置项都在配置里）
        if key not in ("version", "config", "interface"):
            cfg = self._show_key(self._vendor, "config")
            if cfg:
                return cfg
        return ""

    # ---------------- 事实提取 ----------------
    def facts(self):
        f = {
            "vendor": self.vendor_name,
            "host": self.host,
            "hostname": "",
            "model": "",
            "os_version": "",
            "config": "",
            "acl": "",
            "logging": "",
            "snmp": "",
            "aaa": "",
            "ha": "",
            "mgmt": "",
        }
        try:
            ver = self.show("version")
            f["os_version"] = first_meaningful(ver)
            f["model"] = parse_model(ver)
        except Exception:
            pass
        for key in ("config", "acl", "logging", "snmp", "aaa", "ha", "mgmt"):
            try:
                f[key] = self.show(key)
            except Exception:
                f[key] = ""
        m = re.search(r"(?:hostname|sysname)\s+(\S+)", f["config"] or "", re.I)
        if m:
            f["hostname"] = m.group(1).strip()
        return f


# ---------------- 输出清洗与解析工具 ----------------

def clean_output(raw, cmd=""):
    """去掉回显行、分页提示、控制字符。"""
    if not raw:
        return ""
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)   # ANSI 转义
    text = re.sub(r"\x08+", "", text)                     # 退格
    lines = text.split("\n")
    # 去掉第一行回显（内容与命令一致时）
    if lines and cmd and lines[0].strip().lower().startswith(cmd.split()[0].lower()):
        lines = lines[1:]
    out = []
    for ln in lines:
        s = ln.rstrip()
        if not s:
            out.append("")
            continue
        if re.search(r"--More--|--MORE--|\bpress any key\b", s, re.I):
            continue
        if re.match(r"^[^\s>#]+[>#]\s*$", s) and len(s) < 80:
            continue
        out.append(s)
    # 去掉尾部空行
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def is_error_output(text):
    """判断是否为设备"命令不支持/参数错误"类输出。"""
    if not text:
        return False
    return bool(ERR_PATTERNS.search(text[:400]))


def first_meaningful(text):
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s and not re.match(r"^[-=*#\s]+$", s):
            return s[:200]
    return ""


def parse_model(ver_text):
    patterns = [
        r"cisco\s+([A-Z0-9][A-Za-z0-9\-/]+)\s+\(.*?\)\s+processor",
        # 思科常见系列型号（ISR/ASR/ASA/Catalyst/Nexus），兼容"版本行里直接带型号"
        r"\b(ISR\s*\d{4}[A-Za-z\-]*)",
        r"\b(ASR\s*\d{4}[A-Za-z\-]*)",
        r"\b(ASA\s*\d{4}[A-Za-z\-]*)",
        r"\b(Catalyst\s*\d{4}[A-Za-z\-]*)",
        r"\b(Nexus\s*\d{4}[A-Za-z\-]*)",
        # 安全设备自报：<厂商> 防火墙/路由器 <型号> v1.0
        r"(?:防火墙|Firewall|路由器|Router|交换机|Switch)\s+([A-Za-z0-9][A-Za-z0-9\-]{2,20})\s+(?:v\d|version)",
        # 华为 / H3C / 锐捷 / 瞻博版本行
        r"(?:Huawei|华为)\s+([A-Za-z]*\d{3,4}[A-Za-z0-9\-/]*)",
        r"(?:H3C|华三)\s+([A-Za-z]*\d{3,4}[A-Za-z0-9\-/]*)",
        r"(?:Ruijie|锐捷)\s+([A-Za-z]*\d{3,4}[A-Za-z0-9\-/]*)",
        r"(?:Juniper|瞻博)\s+([A-Za-z]*\d{3,4}[A-Za-z0-9\-/]*)",
        r"Juniper\s+Networks[,\s]+(?:Inc[.,]?\s+)?([A-Za-z]*\d{3,4}[A-Za-z0-9\-]*)",
        r"\b(C\d{4}[A-Za-z0-9\-]*)",            # Catalyst C2960 / C9300
        r"\b(FGT-\d{2,4}[A-Za-z0-9\-]*)",       # Fortinet FortiGate
        r"\b(PA-\d{3,5}[A-Za-z0-9\-]*)",        # Palo Alto
        r"\b(BIG-IP\s+\d{3,5}[A-Za-z0-9\-]*)",  # F5
        r"\b(SG-\d{3,4}[A-Za-z0-9\-]*)",        # 深信服
        r"\b(S\d{4}[A-Za-z0-9\-]*)",            # Huawei S 系列（S5735 等）
        r"\b(USG\d{3,5}[A-Za-z0-9\-]*)",        # 华为 USG 防火墙
        r"\b(NS-\d{3,5}[A-Za-z0-9\-]*)",        # 山石/绿盟常见型号前缀
        r"Model\s*(?:number|Name)?\s*:\s*([^,\n]+)",
        r"(?:Product|Device|Hardware)\s*(?:Model|Name|Type)?\s*[:=]\s*([^\s,，\n]+)",
        r"(?:设备型号|型号)\s*[:：]\s*([^\s,，\n]+)",
        r"Hardware\s*:\s*([^,\n]+)",
        r"Chassis\s*:\s*([^,\n]+)",
        r"Platform\s*:\s*([^,\n]+)",
    ]
    for p in patterns:
        m = re.search(p, ver_text or "", re.I)
        if m:
            return m.group(1).strip()
    return ""


_ACL_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$")
# 出现在 permit/deny 之前的修饰词（ASA/IOS 语法）
_ACL_SKIP_TOKENS = {"extended", "standard", "ipv6", "inactive"}


def _acl_rule_from_tokens(name, action, toks, raw):
    """由 permit|deny 之后的 token 序列判定协议/端口/地址维度。"""
    proto = ""
    if toks:
        t0 = toks[0].lower()
        if re.fullmatch(r"[a-z][a-z0-9\-]*", t0) and t0 not in ("source", "destination"):
            proto = t0
    rest = " ".join(toks)
    any_any = (bool(re.search(r"\bany\s+any\b", rest, re.I))
               or bool(re.search(r"\b0\.0\.0\.0/0\s+0\.0\.0\.0/0\b", rest))
               or bool(re.search(r"\b0\.0\.0\.0\s+0\.0\.0\.0\b", rest))
               or bool(re.search(r"source\s+any\s+destination\s+any", rest, re.I)))
    has_port = (bool(re.search(r"\b(eq|gt|lt|range|neq)\s+\S+", rest, re.I))
                or bool(re.search(r"destination-port|source-port|\bdport\b|\bsport\b", rest, re.I))
                or bool(re.search(r":\d+", rest)))
    ips = [t for t in toks if _ACL_IP_RE.match(t)]
    address_pair = len(ips) >= 2
    return {
        "name": name, "action": action, "proto": proto,
        "any_any": any_any, "has_port": has_port,
        "address_pair": address_pair, "raw": raw[:160],
    }


def parse_access_groups(text):
    """解析 ACL 绑定关系。

    兼容两种写法：
      - ASA:   access-group NAME in|out interface IF
      - IOS:   interface IF 块内的 ip access-group NAME in|out（结合 description 判断内外网）
    返回 [{"name","dir","iface"}]，用于区分"外部入口 ACL"与"内网出方向 ACL"。
    """
    groups = []
    cur_iface, cur_desc = None, ""
    for ln in (text or "").splitlines():
        s = ln.strip()
        m = re.match(r"^interface\s+(\S+)", s, re.I)
        if m:
            cur_iface, cur_desc = m.group(1), ""
            continue
        if s in ("!", "end") or s.startswith("!"):
            cur_iface, cur_desc = None, ""
            continue
        if cur_iface is not None:
            d = re.match(r"^description\s+(.+)", s, re.I)
            if d:
                cur_desc = d.group(1).strip()
                continue
            m2 = re.match(r"^ip access-group\s+(\S+)\s+(in|out)", s, re.I)
            if m2:
                groups.append({"name": m2.group(1), "dir": m2.group(2).lower(),
                               "iface": ("%s %s" % (cur_iface, cur_desc)).strip().lower()})
                continue
        m3 = re.match(r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", s, re.I)
        if m3:
            groups.append({"name": m3.group(1), "dir": m3.group(2).lower(),
                           "iface": m3.group(3).lower()})
    return groups


_EXTERNAL_IFACE_RE = re.compile(r"outside|untrust|external|internet|wan|public", re.I)


def external_inbound_acls(config_text, acl_text=""):
    """返回绑在外部接口入方向上的 ACL 名称集合（取不到则返回空集合）。"""
    groups = parse_access_groups(config_text)
    names = {g["name"] for g in groups
             if g["dir"] == "in" and _EXTERNAL_IFACE_RE.search(g["iface"])}
    if not names:
        # ASA 的 nameif outside 也可能只出现在配置里，再兜底一次
        for m in re.finditer(r"access-group\s+(\S+)\s+in\s+interface\s+(outside|untrust|external|internet|wan)\b",
                             config_text or "", re.I):
            names.add(m.group(1))
    return names


def parse_acl(text, names=None):
    """解析 ACL，返回 dict：总规则数、deny 数、permit 数、any-any permit、含端口/协议的规则数。

    兼容以下写法的规则（行内或列表式）：
      Cisco IOS  : access-list 101 permit tcp 10.0.0.0 0.255.255.255 any eq 443
                   access-list 101 (show access-lists 回显) 同上
                   Access-list 101 permit ...（首字母大写）
       Cisco ASA  : access-list inside_access_in line 1 extended permit tcp any any eq https
                   access-list inside_access_in extended permit ip any any
       华为/H3C   : acl number 3000 / rule 10 permit tcp source ... destination-port eq 80
                   acl 3000 / rule 5 permit ip
       纯列表     : 10 permit tcp any any eq 80 / permit ip any any
    """
    rules = []
    cur_name = ""
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        # ---- 1) 上下文头：acl number 3000 / acl name foo（整行只有 ACL 定义）----
        m = re.match(r"^(?:acl|access-list)\s+(?:number\s+|name\s+)?([\w\-\.:]+)\s*$", s, re.I)
        if m:
            cur_name = m.group(1)
            continue
        # ---- 1b) IOS 块式 ACL 头：ip access-list extended WAN-IN / ip access-list standard 10 ----
        m = re.match(r"^ip\s+access-list\s+(?:(?:extended|standard|log|log-update|ipv6)\s+)?([\w\-\.:]+)\s*$",
                     s, re.I)
        if m:
            cur_name = m.group(1)
            continue
        # ---- 1c) show access-lists 回显块头：Extended IP access list WAN-IN ----
        m = re.match(r"^(?:extended|standard)\s+(?:ip|ipv6|mac)\s+access[\s\-]list\s+(\S+)", s, re.I)
        if m:
            cur_name = m.group(1)
            continue
        toks = s.split()
        head = toks[0].lower()
        action_idx = None
        name = cur_name

        # ---- 2) 行内 access-list 规则 ----
        if head in ("access-list", "acl"):
            i = 1
            if i < len(toks) and toks[i].lower() in ("number", "name"):
                i += 1
            if i < len(toks):
                name = toks[i].rstrip(",")
                i += 1
            # 跳过 ASA 的 "line N" / "extended|standard|ipv6" / 序号 / log 等修饰
            while i < len(toks):
                t = toks[i].lower()
                if t == "line" and i + 1 < len(toks) and toks[i + 1].isdigit():
                    i += 2
                elif t in _ACL_SKIP_TOKENS:
                    i += 1
                elif t.isdigit():
                    i += 1
                elif t in ("permit", "deny"):
                    action_idx = i
                    break
                else:
                    break
            if action_idx is None:
                continue

        # ---- 3) 列表式规则：rule 10 permit ... / 10 permit ... / permit ... ----
        elif head == "rule":
            for j in range(1, min(len(toks), 4)):
                if toks[j].lower() in ("permit", "deny"):
                    action_idx = j
                    break
            if action_idx is None:
                continue
        elif head in ("permit", "deny"):
            action_idx = 0
        elif head.isdigit():
            for j in range(1, min(len(toks), 3)):
                if toks[j].lower() in ("permit", "deny"):
                    action_idx = j
                    break
            if action_idx is None:
                continue
        else:
            continue

        action = toks[action_idx].lower()
        rules.append(_acl_rule_from_tokens(name, action, toks[action_idx + 1:], s))
        if name:
            cur_name = name

    if names:
        rules = [r for r in rules if r["name"] in names]
    return {
        "count": len(rules),
        "deny": sum(1 for r in rules if r["action"] == "deny"),
        "permit": sum(1 for r in rules if r["action"] == "permit"),
        "any_any": sum(1 for r in rules if r["any_any"] and r["action"] == "permit"),
        "with_port": sum(1 for r in rules if r["has_port"]),
        "with_addr_pair": sum(1 for r in rules if r["address_pair"]),
        "rules": rules[:400],
    }


def parse_logging(text):
    """日志：是否开启、buffer 大小/条数、是否配置 syslog 服务器（集中审计）。"""
    low = (text or "").lower()
    res = {
        "enabled": bool(re.search(r"logging (on|enabled|buffered)|logbuffer|log (?:host|server)", low)),
        "buffer": bool(re.search(r"logging buffered|logbuffer|logging (?:buffer|file)", low)),
        "syslog_hosts": [],
        "facility": "",
        "severity": "",
    }
    for m in re.finditer(r"logging\s+(?:host|to|server)\s*(\d+\.\d+\.\d+\.\d+)", low):
        res["syslog_hosts"].append(m.group(1))
    for m in re.finditer(r"(?:info-center\s+loghost|loghost)\s+(\d+\.\d+\.\d+\.\d+)", low):
        if m.group(1) not in res["syslog_hosts"]:
            res["syslog_hosts"].append(m.group(1))
    m = re.search(r"logging\s+buffered\s+(?:size)?\s*(\d+)", low)
    if m:
        res["buffer_size"] = int(m.group(1))
    m = re.search(r"logging\s+(?:trap|facility)\s+([a-z]+)", low)
    if m:
        res["facility"] = m.group(1)
    m = re.search(r"logging\s+(?:console|monitor|trap|buffered)\s+([a-z]+)", low)
    if m:
        res["severity"] = m.group(1)
    return res


def parse_snmp(text):
    """SNMP：是否存在 v1/v2c、是否启用 v3 authPriv、community 名。"""
    low = (text or "").lower()
    res = {
        "enabled": bool(re.search(r"snmp", low)),
        "v1v2c": bool(re.search(r"snmp-server community|snmp-agent community|community\s+\S+\s+(ro|rw)", low)),
        "v3": bool(re.search(r"snmp-server group|snmp-server user|snmp-agent usm-user", low)),
        "v3_priv": bool(re.search(r"priv\s+(aes|des)|auth\s+(sha|md5)\s+priv", low)),
        "communities": [],
    }
    for m in re.finditer(r"snmp-server community\s+(\S+)", low):
        res["communities"].append(m.group(1))
    for m in re.finditer(r"snmp-agent community\s+(?:read|write)\s+(\S+)", low):
        res["communities"].append(m.group(1))
    return res


def parse_aaa(text):
    """AAA：TACACS+/RADIUS、本地认证、登录失败锁定、口令策略。"""
    low = (text or "").lower()
    return {
        "tacacs": bool(re.search(r"tacacs", low)),
        "radius": bool(re.search(r"radius", low)),
        "aaa_new_model": bool(re.search(r"aaa (new-model|authentication)", low)),
        "login_lockout": bool(re.search(r"lockout|password-control|login fail|aaa authentication login", low)),
        "password_policy": bool(re.search(r"password-control|password complexity|password min-length", low)),
        "local_fallback": bool(re.search(r"local|line console|line vty", low)),
        "raw_hits": len(re.findall(r"(tacacs|radius|aaa|lockout|password-control)", low)),
    }


def parse_ha(text):
    """HA/冗余：HSRP/VRRP/堆叠/双主控。"""
    low = (text or "").lower()
    return {
        "hsrp": bool(re.search(r"hsrp|standby", low)) and bool(re.search(r"active|standby|virtual ip", low)),
        "vrrp": bool(re.search(r"vrrp", low)) and bool(re.search(r"master|backup|virtual ip", low)),
        "stack": bool(re.search(r"stack|vss|css|irf|m-lag|mlag|vpc", low)),
        "dual_sup": bool(re.search(r"active supervision|standby supervision|redundancy", low)),
        "raw": (text or "")[:600],
    }


def parse_mgmt(text):
    """管理面：管理来源限制、仅允许 SSH、管理 VRF/接口隔离。"""
    low = (text or "").lower()
    # ASA 用 "ssh <网段> <掩码> <接口>" 限制可登录来源，无 access-class 概念
    ssh_source = bool(re.search(
        r"\bssh\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+", low))
    telnet_enabled = bool(re.search(
        r"\btelnet\s+\d+\.\d+\.\d+\.\d+|transport input (?:all|telnet)|protocol inbound telnet",
        low))
    return {
        "vty_acl": bool(re.search(
            r"access-class|acl\s+\d+\s+inbound|protocol inbound ssh", low))
            or ssh_source,
        "ssh_only": bool(re.search(
            r"transport input ssh|protocol inbound ssh|ssh server", low))
            or ssh_source,
        "telnet_disabled": not telnet_enabled,
        "mgmt_vrf": bool(re.search(
            r"management vrf|mgmt-vrf|management interface|mgmt0", low)),
    }


def snmp_walk_device(host, community="public", version="2c", timeout=2, port=161):
    """SNMP v2c 只读取设备基本信息。返回 dict 或抛异常。

    兼容 pysnmp 4.x（同步 hlapi）与 6.x/7.x（asyncio v3arch）。
    """
    oids = [
        ("sysDescr", "1.3.6.1.2.1.1.1.0"),
        ("sysName", "1.3.6.1.2.1.1.5.0"),
        ("sysUpTime", "1.3.6.1.2.1.1.3.0"),
    ]
    res = {"host": host, "community": community}

    # ---- pysnmp 4.x 同步 API ----
    try:
        from pysnmp.hlapi import (getCmd, SnmpEngine, CommunityData,
                                  UdpTransportTarget, ContextData,
                                  ObjectType, ObjectIdentity)
        for key, oid in oids:
            err_ind, err_stat, err_idx, var_binds = next(
                getCmd(SnmpEngine(), CommunityData(community, mpModel=1),
                       UdpTransportTarget((host, port), timeout=timeout, retries=1),
                       ContextData(), ObjectType(ObjectIdentity(oid))))
            if err_ind or err_stat:
                raise NetdevError("SNMP 返回错误：%s" % (err_ind or err_stat))
            for _name, val in var_binds:
                res[key] = str(val)
        return res
    except ImportError:
        pass
    except NetdevError:
        raise

    # ---- pysnmp 6.x/7.x asyncio API ----
    try:
        import asyncio
        from pysnmp.hlapi.v3arch.asyncio import (get_cmd, SnmpEngine, CommunityData,
                                                 UdpTransportTarget, ContextData,
                                                 ObjectType, ObjectIdentity)
    except ImportError as e:
        raise NetdevError("未安装 pysnmp，请执行：pip install pysnmp（报错：%s）" % e)

    async def _run():
        engine = SnmpEngine()
        for key, oid in oids:
            target = await UdpTransportTarget.create(
                (host, port), timeout=timeout, retries=1)
            err_ind, err_stat, err_idx, var_binds = await get_cmd(
                engine, CommunityData(community, mpModel=1),
                target, ContextData(), ObjectType(ObjectIdentity(oid)))
            if err_ind or err_stat:
                raise NetdevError("SNMP 返回错误：%s" % (err_ind or err_stat))
            for var in var_binds:
                res[key] = str(var[1])
        return res

    try:
        return asyncio.run(_run())
    except NetdevError:
        raise
    except Exception as e:
        raise NetdevError("SNMP 请求失败：%s" % e)


def build_connector(conf):
    """由配置字典构造连接器；conf 为空返回 None。"""
    conf = conf or {}
    host = (conf.get("host") or "").strip()
    if not host:
        return None
    return NetdevConnector(
        host=host,
        port=conf.get("port") or 22,
        user=conf.get("user") or "",
        password=conf.get("password") or "",
        keyfile=conf.get("keyfile") or "",
        vendor=conf.get("vendor") or "auto",
        timeout=conf.get("timeout") or 15,
        enable_password=conf.get("enable") or "",
    )
