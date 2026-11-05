# -*- coding: utf-8 -*-
"""等保2.0 问卷题库（物理安全 + 管理类：制度/机构/人员/建设/运维）
answer 取值: conform(符合) / partial(部分符合) / nonconform(不符合) / na(不适用)

每道题带 layers 字段表示适用的技术检测层面：
  None 或 [] — 全局必答（所有层面适用）
  [LAYER_*]  — 仅当检测结果覆盖这些层面时才显示
"""
import csv
import glob
import json
import os
from datetime import datetime

from core.models import QuizItem, LEVEL_ALL, LEVEL_L2, LEVEL_L3

Q_WL = "物理安全"
Q_MGR = "安全管理制度"
Q_ORG = "安全管理机构"
Q_STAFF = "人员安全管理"
Q_BUILD = "系统建设管理"
Q_OPS = "系统运维管理"

QUIZ_CATEGORIES = [Q_WL, Q_MGR, Q_ORG, Q_STAFF, Q_BUILD, Q_OPS]

ANSWER_OPTIONS = [
    ("conform", "符合"),
    ("partial", "部分符合"),
    ("nonconform", "不符合"),
    ("na", "不适用"),
]

ANSWER_TEXT = {k: v for k, v in ANSWER_OPTIONS}

# -------- 题库：由 checks/manual_checks.py 的等保2.0人工核查清单自动生成 --------
# 物理安全 = 安全物理环境(22) + 安全通信网络(8)，共 30 项
# 安全管理 = 制度(7)/机构(14)/人员(12)/建设(34)/运维(47)，共 114 项
# 条目级别沿用清单：二级项为基础项（二/三级均核查），三级项为仅三级增强项
# （安全管理中心 12 项属网络与边界安全层面，在技术检测中标注“需人工核查”，不在问卷中）

_CAT_MAP = [
    (("安全物理环境", "安全通信网络"), Q_WL, "Q-WL"),
    (("安全管理制度",), Q_MGR, "Q-GL"),
    (("安全管理机构",), Q_ORG, "Q-JG"),
    (("安全管理人员",), Q_STAFF, "Q-RY"),
    (("安全建设管理",), Q_BUILD, "Q-JS"),
    (("安全运维管理",), Q_OPS, "Q-YW"),
]


def _build_items():
    """从人工核查清单生成问卷题库（单一数据源：清单更新即题库更新）"""
    from checks.manual_checks import build_manual_checks
    pool = build_manual_checks(LEVEL_L3)  # 三级清单 = 全部二级 + 三级条目
    out = []
    for cats, qcat, prefix in _CAT_MAP:
        n = 0
        for it in pool:
            if it.category not in cats:
                continue
            n += 1
            out.append(QuizItem(
                "%s-%d" % (prefix, n), qcat,
                "%s：%s" % (it.name, it.expected),
                LEVEL_L3 if it.level == LEVEL_L3 else LEVEL_L2,
                it.clause, it.suggestion))
    return out


_ALL_ITEMS = _build_items()




def get_quiz_items(level: str, layers=None):
    """按级别 + 实际检测层面返回问卷项。

    Args:
        level: "二级" 或 "三级"
        layers: 本次检测实际覆盖的层面集合，如 {LAYER_DEVICE, LAYER_NET}。
                None 表示全部层面（显示所有通用题）。
    """
    # 先按等保级别过滤
    if level == "三级":
        pool = list(_ALL_ITEMS)
    else:
        pool = [q for q in _ALL_ITEMS if q.level in (LEVEL_ALL, LEVEL_L2)]

    # 再按适用层面过滤
    if layers is not None:
        layers = set(layers)
        pool = [
            q for q in pool
            if not q.layers            # 全局必答
            or not layers              # 没测任何层面 → 显示全部
            or any(l in layers for l in q.layers)  # 有交集则显示
        ]
    return pool


# ---------------- 问卷草稿自动保存 ----------------

def _default_draft_path(level: str) -> str:
    """默认草稿路径：~/.ea_dengbao/quiz_draft_<level>.json"""
    return os.path.join(os.path.expanduser("~"), ".ea_dengbao",
                        "quiz_draft_%s.json" % level)


def save_draft(level, answers, path=None) -> str:
    """保存问卷草稿，返回实际写入的文件路径。

    answers 形如 {qid: {"answer": "conform", "suggestion": "..."}}，
    也兼容 {qid: "conform"} 这种 answer 直接是字符串的形式。
    """
    path = path or _default_draft_path(level)
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    payload = {
        "level": level,
        "answers": answers if isinstance(answers, dict) else {},
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def load_draft(level, path=None) -> dict:
    """读取问卷草稿，返回 {"level":..., "answers": {...}, "saved_at": "..."}。

    文件不存在或内容损坏时返回 {}，由调用方自行容错。
    """
    path = path or _default_draft_path(level)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    if not isinstance(data.get("answers"), dict):
        data["answers"] = {}
    return data


def clear_draft(path=None):
    """清除草稿。path 为空时删除所有级别的问卷草稿。"""
    if path:
        try:
            os.remove(path)
        except OSError:
            pass
        return
    pattern = os.path.join(os.path.expanduser("~"), ".ea_dengbao",
                           "quiz_draft_*.json")
    for p in glob.glob(pattern):
        try:
            os.remove(p)
        except OSError:
            pass


# ---------------- 问卷答案导出 ----------------

def _answer_parts(value):
    """把草稿/state 里的答案值统一成 (answer, suggestion)。"""
    if isinstance(value, dict):
        return value.get("answer", "") or "", value.get("suggestion", "") or ""
    if isinstance(value, str):
        return value, ""
    return "", ""


def export_answers_csv(answers, path, level="三级") -> str:
    """导出问卷答案为 CSV（utf-8-sig，Excel 直接打开不乱码），返回文件路径。

    表头：序号,题库编号,所属类别,等保级别,条款,题目,答案,整改建议
    未作答的题目答案列输出「未作答」。
    """
    answers = answers if isinstance(answers, dict) else {}
    items = get_quiz_items(level)
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["序号", "题库编号", "所属类别", "等保级别",
                         "条款", "题目", "答案", "整改建议"])
        for idx, q in enumerate(items, 1):
            ans, extra = _answer_parts(answers.get(q.qid))
            label = ANSWER_TEXT.get(ans, "未作答")
            writer.writerow([idx, q.qid, q.category, q.level, q.clause,
                             q.text, label, extra or q.suggestion])
    return path
