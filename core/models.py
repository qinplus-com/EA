# -*- coding: utf-8 -*-
"""数据模型：检测项 / 检测结果 / 问卷项"""
from dataclasses import dataclass, field
from typing import Callable, Optional

# 检测结论
STATUS_PASS = "pass"        # 符合
STATUS_FAIL = "fail"        # 不符合
STATUS_WARN = "warn"        # 部分符合 / 存在风险
STATUS_MANUAL = "manual"    # 需人工核查
STATUS_ERROR = "error"      # 检测失败（权限不足等）

STATUS_TEXT = {
    STATUS_PASS: "符合",
    STATUS_FAIL: "不符合",
    STATUS_WARN: "部分符合",
    STATUS_MANUAL: "需人工核查",
    STATUS_ERROR: "检测失败",
}

LEVEL_ALL = "通用"
LEVEL_L2 = "二级"
LEVEL_L3 = "三级"

# 技术检测分类
CAT_IDENTITY = "身份鉴别"
CAT_ACCESS = "访问控制"
CAT_AUDIT = "安全审计"
CAT_INTRUSION = "入侵防范"
CAT_MALWARE = "恶意代码防范"
CAT_BACKUP = "数据备份与恢复"

CAT_NET = "网络与边界安全"
CAT_DB = "数据库安全"
CAT_MW = "中间件与Web安全"
CAT_APP = "应用与数据安全"

OS_CATEGORIES = [CAT_IDENTITY, CAT_ACCESS, CAT_AUDIT, CAT_INTRUSION, CAT_MALWARE, CAT_BACKUP]
CATEGORIES = OS_CATEGORIES + [CAT_NET, CAT_DB, CAT_MW, CAT_APP]

# 等保层面（报告按此分章节）
LAYER_DEVICE = "设备与计算安全（操作系统）"
LAYER_NET = "网络与边界安全"
LAYER_DB = "数据库安全"
LAYER_MW = "中间件与Web安全"
LAYER_APP = "应用与数据安全"

# 新增：物理环境 + 安全管理
CAT_PHYS = "安全物理环境"
CAT_COMM_NET = "安全通信网络"
CAT_SM_CENTER = "安全管理中心"
CAT_SM_SYS = "安全管理制度"
CAT_SM_INST = "安全管理机构"
CAT_SM_PER = "安全管理人员"
CAT_SM_CON = "安全建设管理"
CAT_SM_OPE = "安全运维管理"

# 为了 UI 上不显得太分散，把物理 + 安全通信网络合并为 "物理与通信安全"
# 把管理制度/机构/人员/建设/运维合并为 "安全管理"
LAYER_PHYS = "安全物理与通信安全"
LAYER_SM = "安全管理"

LAYERS = [
    (LAYER_PHYS,  [CAT_PHYS, CAT_COMM_NET]),
    (LAYER_DEVICE, OS_CATEGORIES),
    (LAYER_NET,   [CAT_NET, CAT_SM_CENTER]),
    (LAYER_DB,    [CAT_DB]),
    (LAYER_MW,    [CAT_MW]),
    (LAYER_APP,   [CAT_APP]),
    (LAYER_SM,    [CAT_SM_SYS, CAT_SM_INST, CAT_SM_PER, CAT_SM_CON, CAT_SM_OPE]),
]

CATEGORY_LAYER = {cat: layer for layer, cats in LAYERS for cat in cats}


def layer_of(category):
    return CATEGORY_LAYER.get(category, category)


@dataclass
class CheckResult:
    item_id: str
    name: str
    category: str
    level: str
    clause: str          # 等保条款号
    expected: str        # 期望值/合规要求
    suggestion: str      # 整改建议
    status: str = STATUS_MANUAL
    evidence: str = ""   # 实际检测到的证据/取值


# runner: () -> (status, evidence)
RunnerFn = Callable[[], tuple]


@dataclass
class CheckItem:
    item_id: str
    name: str
    category: str
    level: str
    clause: str
    expected: str
    suggestion: str
    runner: Optional[RunnerFn] = None  # None 表示纯人工核查项
    # 可选前置条件：返回 False 表示当前目标不适用该项（如未运行 Nginx 时跳过 Nginx 检测）
    # engine.run_all 会先调 depends()，False 则完全跳过（不出现在 results 里）
    depends: Optional[Callable[[], bool]] = None

    def run(self) -> CheckResult:
        r = CheckResult(
            item_id=self.item_id, name=self.name, category=self.category,
            level=self.level, clause=self.clause, expected=self.expected,
            suggestion=self.suggestion,
        )
        if self.runner is None:
            r.status = STATUS_MANUAL
            r.evidence = "该项需人工核查"
            return r
        try:
            status, evidence = self.runner()
            r.status = status
            r.evidence = evidence
        except Exception as e:  # 检测异常不阻断整体流程
            r.status = STATUS_ERROR
            r.evidence = f"检测执行异常: {e}"
        return r


@dataclass
class QuizItem:
    qid: str
    category: str
    text: str
    level: str           # 通用/二级/三级
    clause: str
    suggestion: str
    # 适用的技术检测层面集合；None 或空表示所有层面必答
    # 值参考 LAYER_DEVICE / LAYER_NET / LAYER_DB / LAYER_MW / LAYER_APP
    layers: Optional[list] = None


@dataclass
class RunSummary:
    run_id: int = 0
    target: str = ""     # 被测对象名称
    os_name: str = ""
    level: str = ""
    started: str = ""
    score: float = 0.0
    pass_count: int = 0
    fail_count: int = 0
    warn_count: int = 0
    manual_count: int = 0
    total: int = 0
    results: list = field(default_factory=list)   # List[CheckResult]
    quiz_answers: dict = field(default_factory=dict)  # qid -> answer
    note: str = ""       # 附加说明（如「网络设备直连核查」「数据库直连核查」）
