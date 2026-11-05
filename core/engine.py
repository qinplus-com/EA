# -*- coding: utf-8 -*-
"""检测引擎：在后台线程中逐项执行检测，通过回调汇报进度（不依赖Qt，便于测试）"""
import time
from datetime import datetime

from core.models import (RunSummary, STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         layer_of, LAYERS, LAYER_NET)
from core.remote import LocalExecutor
from checks import get_technical_checks
from checks.platform_util import set_executor
from checks.db_checks import set_db_conf
from checks.network_checks import set_net_conf
from checks.middleware_checks import set_mw_conf
from checks.app_checks import set_app_conf


def compute_score(results) -> tuple:
    """返回 (得分, pass, fail, warn, manual)。manual/error 不计入分母。"""
    p = f = w = m = 0
    score_sum = 0.0
    counted = 0
    for r in results:
        if r.status == STATUS_PASS:
            p += 1
            score_sum += 100
            counted += 1
        elif r.status == STATUS_FAIL:
            f += 1
            counted += 1
        elif r.status == STATUS_WARN:
            w += 1
            score_sum += 50
            counted += 1
        else:
            m += 1
    score = round(score_sum / counted, 1) if counted else 0.0
    return score, p, f, w, m


def run_all(level: str, target: str = "", executor=None,
            on_item=None, on_progress=None, should_stop=None, layers=None,
            db_conf=None, net_conf=None, mw_conf=None, app_conf=None) -> RunSummary:
    """执行技术检测项。
    executor 为空时检测本机；传入 SSHExecutor/WinRMExecutor 则检测远程服务器。
    layers 为选中的等保层面名称列表；为空则检测全部层面。
    db_conf 为数据库访问配置（类型/端口/账号/口令），用于连接库内核对版本与账户。
    on_item(result) 每完成一项回调；on_progress(cur,total,name)；should_stop()->bool 可中断。"""
    # —— 不允许静默回退 ——
    # 调用方必须显式传入 executor。如果传入 None，说明调用方自己不确定要检测谁，
    # 此时直接报错比偷偷跑本机更安全（避免用户以为在测远程实际测的是本机）。
    if executor is None:
        raise ValueError(
            "engine.run_all 收到 executor=None —— 调用方未明确指定检测目标。"
            "请通过 build_executor(mode) 构造后传入，"
            "或显式传入 LocalExecutor() 以检测本机。")
    ex = executor
    # 额外安全：如果远程执行器已经 close() / 未 connect，拒绝运行
    if not isinstance(ex, LocalExecutor):
        if not getattr(ex, "_connected_ok", False):
            raise RuntimeError(
                "远程执行器尚未建立有效连接（host=%s mode=%s）。"
                "请先调用 ex.connect() 并确保成功返回。"
                % (getattr(ex, "host", "?"), type(ex).__name__))
    set_executor(ex)
    set_db_conf(db_conf)
    set_net_conf(net_conf)
    set_mw_conf(mw_conf)
    set_app_conf(app_conf)
    try:
        items = get_technical_checks(level, ex.platform)
        if layers:
            items = [it for it in items if layer_of(it.category) in layers]
        total = len(items)
        summary = RunSummary(target=target or "本机", os_name=ex.os_name(), level=level,
                             started=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        # 明确记录 executor 类型 + 目标信息，供 UI 展示
        summary.executor_type = type(ex).__name__
        summary.target_host = getattr(ex, "host", "127.0.0.1")
        for i, item in enumerate(items, 1):
            if should_stop and should_stop():
                break
            # —— depends 前置条件：不适用的项直接跳过，不出现在报告里 ——
            if item.depends is not None:
                try:
                    if not item.depends():
                        continue
                except Exception:
                    # depends 抛异常视为 False（不适用）
                    continue
            if on_progress:
                on_progress(i, total, item.name)
            try:
                result = item.run()
            except Exception as ex:  # 理论上 CheckItem.run() 已保护，这里再兜一层
                from core.models import STATUS_ERROR
                from core.models import CheckResult
                result = CheckResult(
                    item_id=item.item_id, name=item.name, category=item.category,
                    level=item.level, clause=item.clause, expected=item.expected,
                    suggestion=item.suggestion,
                    status=STATUS_ERROR, evidence=f"检测执行异常: {ex}")
            summary.results.append(result)
            if on_item:
                on_item(result)
            time.sleep(0.02)  # 让UI有机会刷新
        summary.score, summary.pass_count, summary.fail_count, \
            summary.warn_count, summary.manual_count = compute_score(summary.results)
        summary.total = len(summary.results)
        # —— 权限提示 ——
        # 远程检测（SSH/WinRM）时，若登录账号非 root / 非管理员，部分检查项
        # （如 /etc/shadow、sudoers、中间件配置目录等）可能因权限不足无法取证。
        # 在 summary.note 中追加说明，供报告展示；不覆盖网络设备/数据库直连已设的 note。
        if not isinstance(ex, LocalExecutor):
            try:
                priv, priv_desc = ex.is_privileged()
            except Exception:
                priv, priv_desc = True, ""
            if not priv:
                hint = ("检测账号为%s，部分检查项可能因权限不足无法取证，"
                        "建议使用 root/管理员账号检测后复核" % priv_desc)
                summary.note = (summary.note + "；" if summary.note else "") + hint
        # 纯网络/边界设备报告：在报告元信息中展示识别到的设备厂商与型号
        if summary.results and all(layer_of(r.category) == LAYER_NET
                                  for r in summary.results):
            try:
                from checks.network_checks import device_summary
                label = device_summary()
            except Exception:
                label = ""
            if label:
                summary.os_name = "%s（扫描平台 %s）" % (label, summary.os_name)
            elif (net_conf or {}).get("host") or (net_conf or {}).get("snmp_host"):
                summary.os_name = "未识别（扫描平台 %s）" % summary.os_name
            else:
                summary.os_name = "未配置设备（扫描平台 %s）" % summary.os_name
        return summary
    finally:
        set_executor(None)
        set_db_conf(None)
        set_net_conf(None)
        set_mw_conf(None)
        set_app_conf(None)


def os_info() -> str:
    return LocalExecutor().os_name()
