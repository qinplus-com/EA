# -*- coding: utf-8 -*-
"""Windows 打包脚本：勤加等保测评助手 V1.0（仅提供解压版 zip）

运行：
    python build_windows.py

产物：
    dist/勤加等保测评助手V1.0_windows.zip
        ├─ 勤加等保测评助手.exe      （PyInstaller 单文件，绿色免安装）
        ├─ data/                    （基线数据，用户可见可编辑）
        │   ├─ security_baseline.json   版本基线
        │   └─ cve_db.json              CVE 漏洞库
        └─ 报告样例/                （导出报告样例，了解报告样式）

依赖：
    pip install pyinstaller python-docx PyQt5
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
APP_EXE = "ea_dengbao"          # PyInstaller 产物名（spec 中定义）
APP_CN = "勤加等保测评助手"      # 对外中文名
VERSION = "V1.0"


def clean():
    for d in (DIST, BUILD):
        if d.exists():
            print(f"清理 {d} ...")
            shutil.rmtree(d, ignore_errors=True)


def build_exe():
    print("=" * 60)
    print("开始 PyInstaller 打包（Windows）...")
    print("=" * 60)
    cmd = [sys.executable, "-m", "PyInstaller",
           "--noconfirm", str(ROOT / "ea_dengbao.spec")]
    ret = subprocess.call(cmd, cwd=str(ROOT))
    if ret != 0:
        print("打包失败，退出码", ret)
        sys.exit(ret)
    exe = DIST / f"{APP_EXE}.exe"
    if not exe.exists():
        print("✗ 未找到 exe 产物")
        sys.exit(1)
    size_mb = exe.stat().st_size / 1024 / 1024
    print(f"✓ 生成 exe: {exe}  ({size_mb:.1f} MB)")
    return exe


def build_zip(exe):
    """打 zip 解压版：exe（中文名）+ data/ 基线数据"""
    stage = DIST / f"{APP_CN}{VERSION}"
    if stage.exists():
        shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)

    # exe 以中文名放入压缩包
    shutil.copy2(exe, stage / f"{APP_CN}.exe")

    # 基线数据（版本基线 + CVE 漏洞库），随包分发、用户可见可编辑
    data_out = stage / "data"
    data_out.mkdir()
    for name in ("security_baseline.json", "cve_db.json"):
        src = ROOT / "data" / name
        if not src.exists():
            print(f"✗ 缺少基线数据 {src}")
            sys.exit(1)
        shutil.copy2(src, data_out / name)
        print(f"✓ 打包基线数据: data/{name}")

    # 报告样例：随包分发，方便用户了解导出报告样式与结构
    build_sample(stage)

    zip_path = shutil.make_archive(
        str(DIST / f"{APP_CN}{VERSION}_windows"), "zip", root_dir=DIST,
        base_dir=stage.name)
    size_mb = Path(zip_path).stat().st_size / 1024 / 1024
    print(f"✓ 解压版压缩包: {zip_path}  ({size_mb:.1f} MB)")
    return zip_path


# 报告样例数据：(编号, 检测项, 分类, 等保条款, 合规要求, 整改建议, 结论, 检测结果/证据)
_SAMPLE_ROWS = [
    ("DEV-01", "身份鉴别：登录口令复杂度策略", "身份鉴别", "三级 8.1.4.1",
     "口令长度不少于 8 位且包含大小写字母、数字、特殊字符中的三种",
     "启用口令复杂度策略并定期更换", "pass", "已启用 PAM 复杂度策略，最小长度 12 位"),
    ("DEV-02", "访问控制：默认账户与共享账户管理", "访问控制", "三级 8.1.4.2",
     "重命名或禁用默认账户，账户与用户一一对应",
     "禁用默认账户 guest，清理共享账户", "pass", "默认账户已重命名，未发现共享账户"),
    ("DEV-03", "安全审计：审计日志留存", "安全审计", "三级 8.1.4.3",
     "审计记录留存不少于 6 个月", "调整日志轮转策略，审计记录保留 180 天",
     "warn", "auditd 已开启，日志仅保留 90 天（要求 180 天）"),
    ("DEV-04", "入侵防范：最小化安装与端口开放", "入侵防范", "三级 8.1.4.4",
     "仅开放业务必需端口，卸载无关组件", "关闭 23/telnet 端口并卸载无关组件",
     "pass", "仅开放 22/443 端口，telnet 已关闭"),
    ("DEV-05", "恶意代码防范：防恶意代码软件与特征库更新", "恶意代码防范", "三级 8.1.4.5",
     "安装防恶意代码软件并保持特征库更新", "配置特征库每日自动更新",
     "pass", "ClamAV 已安装，特征库每日自动更新"),
    ("DEV-06", "数据备份与恢复：重要数据备份与恢复演练", "数据备份与恢复", "三级 8.1.4.6",
     "重要数据本地与异地备份，定期开展恢复演练",
     "建立每日增量备份与季度恢复演练机制", "manual", "需结合备份策略文档人工核查"),
    ("NET-01", "边界防护：访问控制策略最小化", "网络与边界安全", "三级 8.1.3.1",
     "仅允许业务必需的通信，默认拒绝", "收敛防火墙策略，删除宽松的 any-any 放通规则",
     "fail", "发现 2 条 any-any 放通策略"),
    ("NET-02", "安全通信网络：管理数据传输加密", "安全通信网络", "三级 8.1.2.1",
     "重要数据传输采用加密协议", "关闭 Telnet/HTTP，启用 SSH/HTTPS",
     "pass", "管理通道已启用 SSH v2 与 HTTPS"),
    ("DB-01", "数据库安全：账户权限最小化", "数据库安全", "三级 8.1.4.7",
     "数据库账户按最小权限分配", "回收业务账户的 DBA 权限",
     "pass", "业务账户仅具备 DML 权限"),
    ("APP-01", "应用与数据安全：登录失败处理与会话超时", "应用与数据安全", "三级 8.1.4.8",
     "登录失败 5 次锁定，会话空闲 30 分钟超时", "配置账号锁定策略与会话超时",
     "warn", "失败锁定已配置，会话超时未启用"),
    ("PHY-01", "安全物理环境：机房出入控制与环境监控", "安全物理环境", "三级 8.1.1.1",
     "机房具备门禁、温湿度监控与消防设施", "补充门禁记录与温湿度告警",
     "manual", "需现场核查机房环境"),
]


def build_sample(stage):
    """生成随包分发的报告样例（使用默认品牌信息，不读取本机设置）"""
    sys.path.insert(0, str(ROOT))
    from core import appconfig, report
    from core.models import CheckResult, RunSummary

    appconfig._cache = dict(appconfig.DEFAULTS)  # 样例不引用本机 logo/单位等配置
    results = [
        CheckResult(item_id=r[0], name=r[1], category=r[2], level="三级", clause=r[3],
                    expected=r[4], suggestion=r[5], status=r[6], evidence=r[7])
        for r in _SAMPLE_ROWS
    ]
    p, f, w, m, score = report._counts(results)
    summary = RunSummary(
        target="样例服务器（192.168.10.20）", os_name="Kylin V10 SP3", level="三级",
        started="2026-01-01 10:00:00", score=score, pass_count=p, fail_count=f,
        warn_count=w, manual_count=m, total=len(results), results=results)
    quiz_items = []
    try:
        from questionnaire.data import get_quiz_items
        quiz_items = list(get_quiz_items("三级"))[:3]
        for q in quiz_items:
            summary.quiz_answers[q.qid] = {
                "category": q.category, "text": q.text, "level": q.level,
                "clause": q.clause, "answer": "conform", "suggestion": q.suggestion}
    except Exception:
        pass

    out = stage / "报告样例"
    out.mkdir()
    path = out / "等保测评报告-样例.html"
    path.write_text(report.build_html(summary, quiz_items, summary.quiz_answers),
                    encoding="utf-8")
    print(f"✓ 打包报告样例: 报告样例/{path.name}")


def main():
    clean()
    exe = build_exe()
    zip_path = build_zip(exe)
    print("\n打包完成！")
    print(f"发布产物（解压即用）: {zip_path}")


if __name__ == "__main__":
    main()
