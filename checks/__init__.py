# -*- coding: utf-8 -*-
"""检测项注册：按平台与等保级别返回检测项列表"""
import platform as _pf


def current_platform() -> str:
    """本机平台：'windows' 或 'linux'"""
    return "windows" if _pf.system().lower().startswith("win") else "linux"


def get_technical_checks(level: str, platform: str = None) -> list:
    """level: '二级' | '三级'；platform 缺省取本机。
    汇总操作系统层 + 网络边界 + 数据库 + 中间件 + 应用数据层的自动检测项
    + 物理环境 + 安全管理中心 + 管理制度 + 机构 + 人员 + 建设 + 运维 的人工核查项。"""
    plat = platform or current_platform()
    if plat == "windows":
        from . import windows_checks as os_mod
    else:
        from . import linux_checks as os_mod
    from . import network_checks, db_checks, middleware_checks, app_checks, advanced_checks
    from .manual_checks import build_manual_checks

    items = []
    for mod in (os_mod, network_checks, db_checks, middleware_checks,
                app_checks, advanced_checks):
        try:
            items.extend(mod.build_checks(plat))
        except TypeError:
            items.extend(mod.build_checks())

    # 追加物理环境 + 安全管理（runner=None，需人工核查）
    items.extend(build_manual_checks(level))

    out = []
    for it in items:
        if it.level == "通用" or it.level == level:
            out.append(it)
        elif level == "三级" and it.level == "二级":
            out.append(it)
    return out
