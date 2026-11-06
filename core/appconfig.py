# -*- coding: utf-8 -*-
"""应用级配置（设置页持久化）。

配置文件位置：~/.ea_dengbao/settings.json
"""
import json
import os
import sys

CONF_DIR = os.path.join(os.path.expanduser("~"), ".ea_dengbao")
CONF_PATH = os.path.join(CONF_DIR, "settings.json")


def _app_dir():
    """程序所在目录：解压版为 exe 同级目录，源码运行为项目根目录"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _default_report_dir():
    """默认报告目录：应用所在目录（不可写时由导出逻辑回退到用户主目录）"""
    return _app_dir()


DEFAULT_REPORT_DIR = _default_report_dir()

# 旧版默认报告目录（桌面\等保自查报告），首次升级时自动替换为新默认值
_LEGACY_REPORT_DIRS = {
    os.path.join(os.path.expanduser("~"), "Desktop", "等保自查报告"),
    os.path.join(os.path.expanduser("~"), "桌面", "等保自查报告"),
    os.path.join(os.path.expanduser("~"), "等保自查报告"),
}

DEFAULTS = {
    "report_dir": DEFAULT_REPORT_DIR,
    "report_title": "等保测评报告",
    "org_name": "内蒙古勤加软件有限公司",
    "logo_path": "",
    "snmp_community": "public",
    "timeout": 15,
    "theme": "light",
    "operator": "",
    "mask_secrets": True,
    "minimize_to_tray": False,
    "report_signature": True,
    "splash_enabled": True,
}

_cache = None


def load():
    """读取配置，缺失项用默认值补齐"""
    global _cache
    if _cache is not None:
        return dict(_cache)
    cfg = dict(DEFAULTS)
    try:
        with open(CONF_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if k in DEFAULTS:
                    cfg[k] = v
    except Exception:
        pass
    # 旧版默认标题/目录升级（用户自定义过的值保持不变）
    if cfg.get("report_title") in ("等保自查报告", "勤加等保测评助手报告"):
        cfg["report_title"] = DEFAULTS["report_title"]
    if cfg.get("report_dir") in _LEGACY_REPORT_DIRS:
        cfg["report_dir"] = DEFAULTS["report_dir"]
    _cache = cfg
    return dict(cfg)


def save(cfg=None):
    """保存配置（合并到现有配置）"""
    global _cache
    cur = load()
    if cfg:
        cur.update({k: v for k, v in cfg.items() if k in DEFAULTS})
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    _cache = cur
    return dict(cur)


def get(key, default=None):
    cfg = load()
    return cfg.get(key, DEFAULTS.get(key, default))


def set_value(key, value):
    if key not in DEFAULTS:
        return load()
    return save({key: value})
