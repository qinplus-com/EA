# -*- coding: utf-8 -*-
"""批量目标配置文件解析器

支持三种格式：
- JSON：`.json` / `.txt`（内容为 JSON 数组或 {"targets": [...]}）
- Excel：`.xlsx` / `.xls`
- TXT：`.txt`（每行一个目标，CSV 或 字段=值）

JSON 示例（数组）：
[
  {"name": "官网服务器", "mode": "local", "levels": ["三级"],
   "layers": ["设备与计算安全（操作系统）", "网络与边界安全"],
   "db_type": "自动识别", "db_user": "", "db_password": ""},
  {"name": "内网数据库", "mode": "ssh", "host": "192.168.1.10",
   "port": "22", "user": "root", "password": "xx", "layers": ["数据库安全"]}
]

JSON 示例（对象）：
{"targets": [...], "defaults": {"level": "三级", "layers": ["全部层面"]}}

Excel 列（表头在第一行，不区分顺序）：
  name, mode, host, port, user, password, keyfile,
  level, layers, db_host, db_type, db_port, db_user, db_password

TXT（CSV）：
  官网服务器,local,,,三级,设备与计算安全（操作系统）|网络与边界安全
  内网数据库,ssh,192.168.1.10,22,root,pass,三级,数据库安全

TXT（字段=值，每行一个目标，空行分隔）：
  name=官网服务器
  mode=ssh
  host=192.168.1.10
  port=22
  user=root
  password=xx
  level=三级
  layers=数据库安全|中间件与Web安全
"""
import csv
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from .models import LAYERS, LAYER_NET
from .secret import decrypt as _secret_decrypt


def _dec(value):
    """支持配置文件中以 enc: 前缀加密保存的口令"""
    return _secret_decrypt(value or "")


# -------- 数据结构 --------

VALID_MODES = {"local", "ssh", "winrm", "netdev"}
MODE_ALIASES = {
    "网络设备": "netdev", "设备": "netdev", "防火墙": "netdev",
    "netdev": "netdev", "device": "netdev", "network": "netdev",
    "本机": "local", "local": "local",
    "winrm": "winrm", "windows": "winrm",
    "ssh": "ssh", "linux": "ssh",
}
VALID_LEVELS = {"二级", "三级"}
ALL_LAYERS = [l for l, _ in LAYERS]
# 新模板不再有「连接方式」列：按行内容自动推断
WINRM_PORTS = {"5985", "5986"}


def infer_mode(host, port="", net_vendor="", snmp_ip="", layers_text=""):
    """未填写连接方式时自动推断：
    - 填了具体设备厂商（非 auto）/ SNMP → 网络设备
    - 未填 IP → 本机
    - 检测范围仅「网络与边界安全」→ 网络设备直连核查
    - 端口 5985/5986 → WinRM
    - 其余 → SSH"""
    vendor = (net_vendor or "").strip().lower()
    if (vendor and vendor != "auto") or (snmp_ip or "").strip():
        return "netdev"
    if not (host or "").strip():
        return "local"
    try:
        lay = _parse_layers(layers_text)
        if lay == [LAYER_NET]:
            return "netdev"
    except Exception:
        pass
    if str(port or "").strip() in WINRM_PORTS:
        return "winrm"
    return "ssh"


@dataclass
class BatchTarget:
    """单个被测系统/设备的配置"""
    name: str = ""
    mode: str = "local"        # local / ssh / winrm
    host: str = ""
    port: str = ""
    user: str = ""
    password: str = ""
    keyfile: str = ""
    level: str = "三级"         # 二级 / 三级
    layers: List[str] = field(default_factory=lambda: list(ALL_LAYERS))
    # 数据库
    db_host: str = ""
    db_type: str = ""           # 自动识别 / SQL Server / MySQL ...
    db_port: str = ""
    db_user: str = ""
    db_password: str = ""
    # 中间件
    mw_name: str = ""
    mw_path: str = ""
    # 应用
    app_scheme: str = "自动识别"
    app_port: str = ""
    app_path: str = ""
    # 网络设备（mode=netdev 时使用 host/port/user/password 登录设备）
    net_vendor: str = "auto"
    net_snmp_ip: str = ""
    net_snmp_community: str = ""
    # 其他
    transport: str = "ntlm"
    notes: str = ""
    # 运行结果（运行后填充）
    run_score: Optional[float] = None
    run_items: Optional[int] = None
    run_result_id: Optional[str] = None
    run_error: Optional[str] = None

    def as_target_conf(self) -> Dict[str, Any]:
        """转为 HomePage._conf() 需要的 target_conf 字典"""
        return {
            "mode": self.mode,
            "host": self.host,
            "port": self.port or ("22" if self.mode in ("ssh", "netdev") else "5985"),
            "user": self.user,
            "password": _dec(self.password),
            "keyfile": self.keyfile,
            "transport": self.transport,
        }

    def as_db_conf(self) -> Dict[str, Any]:
        """转为 HomePage._db_conf() 需要的 db_conf 字典（显式数据库列优先）"""
        if not self.db_type and not self.db_user:
            return {}
        kind = self.db_type
        kind_map = {"SQL Server": "sqlserver", "SAP ASE (Sybase)": "sap_ase",
                    "SAP IQ": "sap_iq", "SAP SQL Anywhere": "sap_sqlanywhere",
                    "自动识别": "auto"}
        kind = kind_map.get(kind, kind.lower() if kind else "auto")
        return {
            "type": kind or "auto",
            "host": self.db_host or "127.0.0.1",
            "port": self.db_port,
            "user": self.db_user,
            "password": _dec(self.db_password),
        }

    def as_db_conf_auto(self, db_only: bool = False) -> Dict[str, Any]:
        """新模板（无数据库专列）时，从 IP地址/端口/用户名/口令 推断数据库连接。

        - 仅检测数据库层：IP 即数据库地址，端口即数据库端口，账号即数据库账号（直连核查）
        - 数据库与其他层面混检：IP 作为数据库主机（版本/端口探测 + SSH 登录核查），
          账号留给 SSH 登录，不误用作数据库账号
        - 未填 IP → 空配置（按本机数据库检测）"""
        host = (self.db_host or self.host or "").strip()
        if not host:
            return {}
        if db_only:
            return {"type": "auto", "host": host,
                    "port": (self.db_port or self.port or "").strip(),
                    "user": (self.db_user or self.user or "").strip(),
                    "password": _dec(self.db_password or self.password or "")}
        return {"type": "auto", "host": host, "port": "", "user": "", "password": ""}

    def as_net_conf(self) -> Dict[str, Any]:
        """转为网络设备（防火墙/路由器/交换机）接入配置；无则返回空。"""
        host = (self.host or "").strip()
        snmp = (self.net_snmp_ip or "").strip()
        if self.mode != "netdev" and not host and not snmp:
            return {}
        if not host and not snmp:
            return {}
        return {
            "host": host or snmp,
            "port": self.port or "22",
            "vendor": (self.net_vendor or "auto").strip() or "auto",
            "user": self.user,
            "password": _dec(self.password),
            "enable": "",
            "snmp_host": snmp,
            "snmp_community": (self.net_snmp_community or "").strip(),
        }

    def as_mw_conf(self) -> Dict[str, Any]:
        """转为中间件配置；名称为空/自动识别时交由检测端自动识别"""
        name = (self.mw_name or "").strip()
        return {"name": "" if name in ("", "自动识别") else name,
                "path": (self.mw_path or "").strip()}

    def as_app_conf(self) -> Dict[str, Any]:
        """转为应用访问配置（协议/端口/路径）"""
        raw = (self.app_scheme or "").strip()
        scheme = {"HTTPS": "https", "HTTP": "http", "https": "https",
                  "http": "http"}.get(raw, "auto")
        return {"scheme": scheme, "port": (self.app_port or "").strip(),
                "path": (self.app_path or "").strip()}

    def display_layers(self) -> str:
        if set(self.layers) == set(ALL_LAYERS):
            return "全部层面"
        return "、".join(l.split("（")[0] for l in self.layers)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -------- 主入口 --------

def load(path: str) -> List[BatchTarget]:
    """根据扩展名分发到对应解析器"""
    if not os.path.exists(path):
        raise FileNotFoundError("配置文件不存在: %s" % path)
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return _load_json(path)
    if ext == ".xlsx" or ext == ".xls":
        return _load_excel(path)
    if ext == ".txt" or ext == ".csv":
        content = _read_text(path)
        # 尝试 JSON（容错：TXT 可能存 JSON）
        if content.strip().startswith(("[", "{")):
            try:
                return _parse_json_text(content)
            except Exception:
                pass
        # 尝试 字段=值 分组
        if re.search(r"(?m)^\w+\s*=", content):
            return _parse_kv_text(content)
        # 最后尝试 CSV
        return _parse_csv_text(content)
    raise ValueError("不支持的配置文件类型: %s" % ext)


# -------- 文本读取 --------

def _read_text(path: str) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


# -------- JSON --------

def _load_json(path: str) -> List[BatchTarget]:
    return _parse_json_text(_read_text(path))


def _parse_json_text(text: str) -> List[BatchTarget]:
    data = json.loads(text)
    defaults = {}
    if isinstance(data, dict):
        defaults = data.get("defaults", {}) or {}
        items = data.get("targets") or data.get("hosts") or data.get("systems") or []
    else:
        items = data
    if not isinstance(items, list):
        raise ValueError("JSON 中目标列表应为数组，实际为 %s" % type(items).__name__)
    result = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise ValueError("第 %d 条目标不是对象" % (i + 1))
        result.append(_from_dict({**defaults, **it}))
    return result


# -------- Excel --------

def _load_excel(path: str) -> List[BatchTarget]:
    try:
        import openpyxl
    except ImportError:
        raise ImportError("解析 Excel 需要安装 openpyxl：pip install openpyxl")
    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    header = [str(c).strip() if c is not None else "" for c in rows[0]]
    idx = {name: i for i, name in enumerate(header) if name}

    def get(row, *names, default=""):
        for n in names:
            i = idx.get(n)
            if i is not None and i < len(row) and row[i] is not None:
                v = str(row[i]).strip()
                if v:
                    return v
        return default

    def get_list(row, *names):
        v = get(row, *names)
        if not v:
            return list(ALL_LAYERS)
        return _parse_layers(v)

    result = []
    for raw in rows[1:]:
        if not any(raw):
            continue
        t = BatchTarget()
        t.name = get(raw, "name", "业务名称", "host", "target", "名称", "主机名", "目标")
        t.host = get(raw, "host", "ip", "IP地址", "地址", "服务器地址")
        t.port = get(raw, "port", "端口")
        t.user = get(raw, "user", "username", "用户名")
        t.password = get(raw, "password", "pwd", "口令")
        t.keyfile = get(raw, "keyfile", "key", "私钥", "私钥文件")
        t.net_vendor = get(raw, "net_vendor", "设备厂商") or "auto"
        t.net_snmp_ip = get(raw, "net_snmp_ip", "SNMP地址")
        t.level = (get(raw, "level", "等保级别", "级别") or "三级")
        if t.level not in VALID_LEVELS:
            t.level = "三级"
        t.layers = get_list(raw, "layers", "scope", "检测范围", "层面")
        # 连接方式：显式填写优先；留空按行内容自动推断（新模板无此列）
        raw_mode = get(raw, "mode", "方式", "连接方式")
        if raw_mode:
            t.mode = raw_mode.lower()
            t.mode = MODE_ALIASES.get(t.mode, t.mode)
            if t.mode not in VALID_MODES:
                t.mode = "local"
        else:
            scope_text = get(raw, "layers", "scope", "检测范围", "层面")
            t.mode = infer_mode(t.host, t.port, t.net_vendor, t.net_snmp_ip, scope_text)
        t.db_host = get(raw, "db_host", "数据库主机")
        t.db_type = get(raw, "db_type", "dbtype", "数据库类型")
        t.db_port = get(raw, "db_port", "数据库端口")
        t.db_user = get(raw, "db_user", "数据库账号")
        t.db_password = get(raw, "db_password", "数据库口令")
        t.mw_name = get(raw, "mw_name", "middleware", "中间件名称", "中间件")
        t.mw_path = get(raw, "mw_path", "中间件路径", "中间件安装路径")
        t.app_scheme = get(raw, "app_scheme", "应用协议", "访问协议")
        t.app_port = get(raw, "app_port", "应用端口")
        t.app_path = get(raw, "app_path", "应用路径")
        t.net_snmp_community = get(raw, "net_snmp_community", "SNMP团体名")
        t.notes = get(raw, "notes", "note", "备注")
        result.append(t)
    return result


# -------- TXT: 字段=值 分组 --------

def _parse_kv_text(text: str) -> List[BatchTarget]:
    result = []
    current = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            if current:
                result.append(_from_dict(current))
                current = {}
            continue
        m = re.match(r"^\s*(\w[\w-]*)\s*[:=]\s*(.*)$", line)
        if m:
            current[m.group(1).lower()] = m.group(2).strip()
    if current:
        result.append(_from_dict(current))
    return result


# -------- TXT: CSV --------

def _parse_csv_text(text: str) -> List[BatchTarget]:
    result = []
    reader = csv.reader(text.splitlines())
    header = None
    for row in reader:
        if not row or not any(c.strip() for c in row):
            continue
        if header is None:
            header = [c.strip().lower() for c in row]
            continue
        d = {}
        for i, h in enumerate(header):
            if i < len(row):
                d[h] = row[i].strip()
        result.append(_from_dict(d))
    return result


# -------- 字段统一 --------

def _parse_layers(text: str) -> List[str]:
    if not text:
        return list(ALL_LAYERS)
    if text in ("全部", "全部层面", "all"):
        return list(ALL_LAYERS)
    parts = [p.strip() for p in re.split(r"[|,;，；、/]", text) if p.strip()]
    out = []
    for p in parts:
        matched = None
        for layer in ALL_LAYERS:
            if p in layer or layer.startswith(p) or layer.split("（")[0] == p:
                matched = layer
                break
        if matched:
            out.append(matched)
    return out or list(ALL_LAYERS)


def _from_dict(d: Dict[str, Any]) -> BatchTarget:
    """把宽松的 dict 归一成 BatchTarget"""
    t = BatchTarget()

    def s(*keys, default=""):
        for k in keys:
            v = d.get(k)
            if v is None:
                continue
            if isinstance(v, str):
                v = v.strip()
                if v:
                    return v
            else:
                return v
        return default

    t.name = s("name", "业务名称", "host", "target", "hostname", "title",
               "名称", "主机名", "目标")
    if not t.name:
        t.name = s("ip", "host", "IP地址", "地址", "服务器地址") or "未命名目标"
    t.host = s("host", "ip", "IP地址", "address", "地址", "服务器地址")
    t.port = s("port", "端口")
    t.user = s("user", "username", "用户名")
    t.password = s("password", "pwd", "口令")
    t.keyfile = s("keyfile", "key", "private_key", "私钥", "私钥文件")
    t.net_vendor = s("net_vendor", "设备厂商") or "auto"
    t.net_snmp_ip = s("net_snmp_ip", "SNMP地址")
    level = s("level", "等保级别", "级别") or "三级"
    if level not in VALID_LEVELS:
        level = "三级"
    t.level = level
    raw_layers = s("layers", "scope", "范围", "检测范围", "层面")
    if isinstance(raw_layers, list):
        out = []
        for p in raw_layers:
            for layer in ALL_LAYERS:
                if p in layer or layer.split("（")[0] == p:
                    out.append(layer)
                    break
        t.layers = out or list(ALL_LAYERS)
    else:
        t.layers = _parse_layers(str(raw_layers)) if raw_layers else list(ALL_LAYERS)
    # 连接方式：显式填写优先；留空按行内容自动推断（新模板无此列）
    raw_mode = ""
    for k in ("mode", "方式", "连接方式"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            raw_mode = v.strip()
            break
    if raw_mode:
        mode = raw_mode.lower()
        mode = MODE_ALIASES.get(mode, mode)
        if mode not in VALID_MODES:
            mode = "local"
        t.mode = mode
    else:
        layers_text = raw_layers if isinstance(raw_layers, str) else \
            "|".join(raw_layers) if raw_layers else ""
        t.mode = infer_mode(t.host, t.port, t.net_vendor, t.net_snmp_ip, layers_text)
    # 数据库
    t.db_host = s("db_host", "dbhost", "数据库主机")
    t.db_type = s("db_type", "dbtype", "数据库类型")
    t.db_port = s("db_port", "数据库端口")
    t.db_user = s("db_user", "数据库账号")
    t.db_password = s("db_password", "数据库口令")
    t.mw_name = s("mw_name", "middleware", "中间件名称", "中间件")
    t.mw_path = s("mw_path", "中间件路径", "中间件安装路径")
    t.app_scheme = s("app_scheme", "应用协议", "访问协议") or "自动识别"
    t.app_port = s("app_port", "应用端口")
    t.app_path = s("app_path", "应用路径")
    t.net_snmp_community = s("net_snmp_community", "SNMP团体名")
    t.transport = s("transport") or "ntlm"
    t.notes = s("notes", "note", "备注")
    return t


# -------- 示例生成 --------

EXAMPLE_JSON = """[
  {
    "name": "本机服务器",
    "level": "三级",
    "layers": ["全部层面"]
  },
  {
    "name": "内网Linux服务器",
    "host": "192.168.1.10",
    "port": "22",
    "user": "root",
    "password": "your_password",
    "level": "三级",
    "layers": ["设备与计算安全（操作系统）", "中间件与Web安全"],
    "mw_path": "/etc/nginx"
  },
  {
    "name": "生产数据库",
    "host": "192.168.1.20",
    "port": "3306",
    "user": "dba",
    "password": "db_password",
    "level": "三级",
    "layers": ["数据库安全"]
  },
  {
    "name": "业务应用服务器",
    "host": "192.168.1.30",
    "port": "22",
    "user": "deploy",
    "password": "your_password",
    "level": "三级",
    "layers": ["应用与数据安全"],
    "app_scheme": "HTTPS",
    "app_port": "8443",
    "app_path": "/app"
  }
]"""

# 新模板列顺序（无「连接方式」列：按行内容自动推断本机/SSH/WinRM/网络设备）
EXAMPLE_HEADERS = [
    "业务名称", "检测范围", "IP地址", "端口", "用户名", "口令", "私钥文件", "等保级别",
    "中间件路径", "应用协议", "应用端口", "应用路径",
    "设备厂商", "SNMP地址", "SNMP团体名", "备注"]

SCOPE_OPTIONS = ["全部层面"] + [l.split("（")[0] for l in ALL_LAYERS]

EXAMPLE_ROWS = [
    ["本机服务器", "全部层面", "", "", "", "", "", "三级",
     "", "", "", "", "", "", "", "本机全量核查"],
    ["内网Linux服务器", "设备与计算安全（操作系统）|中间件与Web安全",
     "192.168.1.10", "22", "root", "your_password", "", "三级",
     "/etc/nginx", "", "", "", "", "", "", "SSH 登录远程核查"],
    ["生产数据库", "数据库安全", "192.168.1.20", "3306", "dba", "db_password", "",
     "三级", "", "", "", "", "", "", "", "直连数据库核查（IP+端口+数据库账号）"],
    ["业务应用服务器", "应用与数据安全", "192.168.1.30", "22", "deploy",
     "your_password", "", "三级", "", "HTTPS", "8443", "/app", "", "", "",
     "SSH 登录 + 按端口/路径核查应用"],
    ["核心防火墙", "网络与边界安全", "192.168.1.1", "22", "admin", "your_password",
     "", "三级", "", "", "", "", "auto", "", "public", "网络设备直连核查"],
]


def _csv_text() -> str:
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(EXAMPLE_HEADERS)
    w.writerows(EXAMPLE_ROWS)
    return buf.getvalue()


def _write_excel_example(path: str) -> str:
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.worksheet.datavalidation import DataValidation
    except ImportError:
        raise ImportError("生成 Excel 模板需要安装 openpyxl：pip install openpyxl")

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "导入模板"
    ws.append(EXAMPLE_HEADERS)
    for row in EXAMPLE_ROWS:
        ws.append(row)

    head_fill = PatternFill("solid", fgColor="1E3A5F")
    for c in ws[1]:
        c.font = Font(color="FFFFFF", bold=True)
        c.fill = head_fill
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    widths = [20, 34, 16, 10, 12, 18, 20, 10, 20, 12, 10, 14, 12, 16, 14, 26]
    for i, wd in enumerate(widths, 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = wd
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for c in row:
            c.alignment = Alignment(vertical="center", wrap_text=True)
    ws.freeze_panes = "A2"

    def _list_dv(options):
        # showErrorMessage=False：下拉仅作快捷选择，仍允许手填组合值（如多层面 | 分隔）
        dv = DataValidation(type="list", formula1='"%s"' % ",".join(options),
                            allow_blank=True)
        dv.showErrorMessage = False
        return dv

    dv_scope = _list_dv(SCOPE_OPTIONS)
    dv_level = _list_dv(["二级", "三级"])
    dv_scheme = _list_dv(["自动识别", "HTTPS", "HTTP"])
    dv_vendor = _list_dv(["auto", "华为", "H3C", "Cisco", "Juniper", "锐捷"])
    for dv in (dv_scope, dv_level, dv_scheme, dv_vendor):
        ws.add_data_validation(dv)
    dv_scope.add("B2:B200")     # 检测范围
    dv_level.add("H2:H200")     # 等保级别
    dv_scheme.add("J2:J200")    # 应用协议
    dv_vendor.add("M2:M200")    # 设备厂商

    note = wb.create_sheet("填写说明")
    lines = [
        "批量导入模板填写说明（新模板：无需填写连接方式，系统自动识别）",
        "",
        "1. 仅填写“导入模板”工作表，第一行为表头，请勿修改列名；从第二行开始每行一个目标。",
        "2. 连接方式自动识别：未填 IP = 本机检测；填了具体设备厂商（华为/H3C 等）或 SNMP 地址 = 网络设备；"
        "检测范围仅选「网络与边界安全」也按网络设备核查；"
        "端口为 5985/5986 = Windows(WinRM)；其余填了 IP = SSH(Linux/国产系统) 远程检测。",
        "3. 端口含义：远程服务器填 SSH 端口（默认 22）；仅检测「数据库安全」时填数据库端口"
        "（如 MySQL 3306、SQL Server 1433）；网络设备填管理端口。",
        "4. 用户名/口令/私钥文件：远程检测时为目标机登录账号；仅检测「数据库安全」时为数据库账号；"
        "SSH 免密登录可只填私钥文件路径。",
        "5. 等保级别：二级 / 三级（下拉选择）。",
        "6. 检测范围（下拉选择）：全部层面、设备与计算安全（操作系统）、网络与边界安全、数据库安全、"
        "中间件与Web安全、应用与数据安全；多层面用竖线 | 分隔，如：设备与计算安全（操作系统）|中间件与Web安全。",
        "7. 仅检测「数据库安全」时：IP地址=数据库主机、端口=数据库端口、用户名/口令=数据库账号，"
        "系统将直连数据库核查（支持 MySQL、PostgreSQL、SQL Server、Oracle、Redis、达梦、人大金仓等，类型自动识别）。",
        "8. 中间件路径：安装目录（如 /etc/nginx），可留空自动识别。",
        "9. 应用协议：自动识别 / HTTPS / HTTP；应用端口如 443、8443、8080；应用路径如 /app。",
        "10. 网络设备：填设备厂商（auto/华为/H3C/Cisco/Juniper/锐捷）与 SNMP 地址、团体名（可选），"
        "系统按网络与边界安全层面直连核查。",
        "11. 模板中的 your_password 仅为示例，请替换为实际口令；口令可用 enc: 前缀加密保存。",
        "12. 填写完成后，在系统中点击「选择配置文件」导入本文件即可按顺序执行。",
        "13. 支持 .xlsx / .csv / .json 三种格式；JSON 结构与模板字段一一对应（旧模板含连接方式/数据库专列的文件仍兼容）。",
    ]
    for i, line in enumerate(lines, 1):
        cell = note.cell(row=i, column=1, value=line)
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        if i == 1:
            cell.font = Font(bold=True, size=13)
    note.column_dimensions["A"].width = 108
    wb.save(path)
    return path


def write_example(path: str, fmt: str = "json"):
    """生成批量导入模板文件（xlsx / csv / json）"""
    fmt = (fmt or "json").lower()
    if fmt == "xlsx":
        return _write_excel_example(path)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            f.write(EXAMPLE_JSON)
    else:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(_csv_text())
    return path
