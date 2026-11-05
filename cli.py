#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""勤加等保测评助手 · 命令行版本（Evaluation Assistant CLI）

在无图形环境的服务器（含国产 Linux：麒麟 / 统信 UOS / Deepin / Anolis）
上执行等保技术检测，并输出 HTML / Word / JSON 报告。

示例：
    qinplus-dengbao-cli --level 三级 --layers 全部 --format all
    qinplus-dengbao-cli --mode ssh --host 192.168.81.128 --user root --password sybase
    qinplus-dengbao-cli --mode ssh --host 10.0.0.10 --user root --keyfile ~/.ssh/id_rsa \\
                   --layers 网络与边界安全 --format html --out /tmp/ea-report
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.models import LAYERS, STATUS_TEXT, layer_of          # noqa: E402
from core import engine, report                                 # noqa: E402
from questionnaire import data as qd                            # noqa: E402

APP_NAME = "勤加等保测评助手"
APP_EN = "Evaluation Assistant"
APP_VERSION = "1.0"

LAYER_ALIASES = {
    "全部": [name for name, _c in LAYERS],
    "物理": "安全物理与通信安全",
    "物理与通信": "安全物理与通信安全",
    "计算": "设备与计算安全（操作系统）",
    "设备": "设备与计算安全（操作系统）",
    "操作系统": "设备与计算安全（操作系统）",
    "网络": "网络与边界安全",
    "边界": "网络与边界安全",
    "数据库": "数据库安全",
    "中间件": "中间件与Web安全",
    "web": "中间件与Web安全",
    "应用": "应用与数据安全",
    "管理": "安全管理",
}


def _resolve_layers(text):
    """把 "设备,网络,数据库" 形式的字符串解析为 LAYERS 中的层名列表"""
    if not text:
        return [name for name, _c in LAYERS]
    parts = [p.strip() for p in text.replace("，", ",").split(",") if p.strip()]
    out = []
    for p in parts:
        hit = LAYER_ALIASES.get(p, p)
        if hit is None:
            continue
        if isinstance(hit, list):
            out.extend(hit)
        elif hit in dict(LAYERS):
            out.append(hit)
        else:
            raise SystemExit("未知检测层面：%s（可用：%s）"
                             % (p, "、".join(name for name, _c in LAYERS)))
    return out or [name for name, _c in LAYERS]


def _build_parser():
    p = argparse.ArgumentParser(
        prog="qinplus-dengbao-cli",
        description="%s（%s）命令行版本 V%s" % (APP_NAME, APP_EN, APP_VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  qinplus-dengbao-cli --level 三级 --format all\n"
               "  qinplus-dengbao-cli --mode ssh --host 192.168.81.128 --user root --password sybase\n"
               "  qinplus-dengbao-cli --list-layers\n"
               "  qinplus-dengbao-cli --quiz-template /tmp/问卷模板.csv\n")
    p.add_argument("--version", action="version",
                   version="%s V%s" % (APP_NAME, APP_VERSION))
    p.add_argument("--target", default="", help="被测对象名称（默认取主机地址）")
    p.add_argument("--level", default="三级", choices=["二级", "三级"], help="等保级别")
    p.add_argument("--layers", default="全部",
                   help="检测层面，逗号分隔；可选：%s（默认全部）"
                        % "、".join(name for name, _c in LAYERS))
    p.add_argument("--list-layers", action="store_true", help="列出可用检测层面并退出")

    g = p.add_argument_group("登录方式")
    g.add_argument("--mode", default="local", choices=["local", "ssh", "winrm"],
                   help="本机 / SSH(Linux) / WinRM(Windows)")
    g.add_argument("--host", default="", help="远程主机地址")
    g.add_argument("--port", default="", help="远程端口（SSH 默认 22，WinRM 默认 5985）")
    g.add_argument("--user", default="", help="登录账号")
    g.add_argument("--password", default="", help="登录口令")
    g.add_argument("--keyfile", default="", help="SSH 私钥路径")

    g = p.add_argument_group("数据库（--layers 含数据库时生效）")
    g.add_argument("--db-type", default="auto",
                   help="sqlserver / mysql / postgresql / oracle / mongodb / sap_ase / auto")
    g.add_argument("--db-host", default="", help="数据库主机（留空为本机）")
    g.add_argument("--db-port", default="", help="数据库端口")
    g.add_argument("--db-user", default="", help="数据库账号")
    g.add_argument("--db-password", default="", help="数据库口令")
    g.add_argument("--db-version", default="", help="自动识别失败时手工指定版本")

    g = p.add_argument_group("网络设备（--layers 含网络与边界时生效）")
    g.add_argument("--net-ip", default="", help="防火墙/交换机/路由器管理 IP")
    g.add_argument("--net-vendor", default="auto",
                   help="auto / cisco / huawei / h3c / juniper / ruijie")
    g.add_argument("--net-user", default="", help="设备账号")
    g.add_argument("--net-password", default="", help="设备口令")
    g.add_argument("--net-enable", default="", help="enable 口令（可选）")
    g.add_argument("--snmp-host", default="", help="SNMP 地址（可选）")
    g.add_argument("--snmp-community", default="public", help="SNMP 团体名")

    g = p.add_argument_group("中间件 / 应用")
    g.add_argument("--mw-name", default="", help="中间件名称（留空自动识别）")
    g.add_argument("--mw-path", default="", help="中间件安装路径")
    g.add_argument("--app-scheme", default="auto", choices=["auto", "http", "https"])
    g.add_argument("--app-port", default="", help="应用端口")
    g.add_argument("--app-path", default="", help="应用访问路径")

    g = p.add_argument_group("输出")
    g.add_argument("--format", default="html", choices=["html", "docx", "json", "all"],
                   help="报告格式（默认 html）")
    g.add_argument("--out", default="", help="报告输出目录（默认 ./ea-reports）")
    g.add_argument("--no-report", action="store_true", help="只检测，不生成报告")
    g.add_argument("--quiz", default="", help="问卷答案文件（JSON 或 CSV），写入报告")
    g.add_argument("--quiz-template", default="",
                   help="导出空白问卷模板（CSV）后退出")
    g.add_argument("--quiet", action="store_true", help="不逐项打印进度")
    return p


def _load_quiz(path):
    """读取问卷答案：JSON({qid: answer}) 或 CSV（含「题库编号」「答案」列）"""
    if not path or not os.path.exists(path):
        raise SystemExit("问卷答案文件不存在：%s" % path)
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data = data.get("answers", data) if isinstance(data, dict) else {}
        return {k: (v.get("answer", "") if isinstance(v, dict) else v)
                for k, v in data.items()}
    label2key = {v: k for k, v in qd.ANSWER_TEXT.items()}
    answers = {}
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            qid = (row.get("题库编号") or row.get("qid") or "").strip()
            ans = (row.get("答案") or row.get("answer") or "").strip()
            if qid:
                answers[qid] = label2key.get(ans, ans)
    return answers


def _json_report(summary, quiz_answers):
    return {
        "app": APP_NAME, "app_en": APP_EN, "version": APP_VERSION,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": summary.target, "os": summary.os_name, "level": summary.level,
        "started": summary.started, "score": summary.score,
        "total": summary.total, "pass": summary.pass_count,
        "fail": summary.fail_count, "warn": summary.warn_count,
        "manual": summary.manual_count, "note": summary.note,
        "results": [{
            "item_id": r.item_id, "name": r.name, "category": r.category,
            "layer": layer_of(r.category), "level": r.level, "clause": r.clause,
            "status": r.status, "status_text": STATUS_TEXT.get(r.status, r.status),
            "expected": r.expected, "evidence": r.evidence, "suggestion": r.suggestion,
        } for r in summary.results],
        "quiz_items": [{
            "qid": q.qid, "category": q.category, "clause": q.clause,
            "text": q.text, "answer": quiz_answers.get(q.qid, ""),
        } for q in qd.get_quiz_items(summary.level, layers=None)],
    }


def _print_quiz_answers(quiz_answers):
    if not quiz_answers:
        return
    print("\n问卷答案：")
    for q in qd.get_quiz_items("三级", layers=None):
        if q.qid in quiz_answers:
            label = qd.ANSWER_TEXT.get(quiz_answers[q.qid], quiz_answers[q.qid])
            print("  %-10s [%s] %s" % (q.qid, label, q.text[:46]))


def main(argv=None):
    args = _build_parser().parse_args(argv)

    if args.list_layers:
        print("可用检测层面：")
        for name, cats in LAYERS:
            print("  - %s（%s）" % (name, " / ".join(cats)))
        return 0

    layers = _resolve_layers(args.layers)
    level = args.level

    # 只导出问卷模板
    if args.quiz_template:
        path = qd.export_answers_csv({}, args.quiz_template, level)
        print("已导出空白问卷模板：%s" % path)
        return 0

    # ---------- 构造执行器 ----------
    conf = {"mode": args.mode, "host": args.host, "port": args.port or ("22" if args.mode == "ssh" else "5985"),
            "user": args.user or ("root" if args.mode == "ssh" else "Administrator"),
            "password": args.password, "keyfile": args.keyfile, "transport": "ntlm"}
    if args.mode != "local" and not args.host:
        raise SystemExit("--mode %s 需要指定 --host" % args.mode)
    if args.mode == "ssh" and not (args.password or args.keyfile):
        raise SystemExit("SSH 登录需要 --password 或 --keyfile")

    db_conf = {"type": args.db_type, "host": args.db_host or "127.0.0.1",
               "port": args.db_port, "user": args.db_user,
               "password": args.db_password, "version": args.db_version}
    net_conf = {"host": args.net_ip, "port": "22", "vendor": args.net_vendor,
                "model": "", "user": args.net_user, "password": args.net_password,
                "enable": args.net_enable, "snmp_host": args.snmp_host,
                "snmp_community": args.snmp_community}
    mw_conf = {"name": args.mw_name, "path": args.mw_path}
    app_conf = {"scheme": args.app_scheme, "port": args.app_port, "path": args.app_path}

    print("=" * 62)
    print(" %s V%s 命令行检测" % (APP_NAME, APP_VERSION))
    print("=" * 62)
    print("被测对象：%s　级别：%s" % (args.target or args.host or "本机", level))
    print("检测层面：%s" % "、".join(layers))
    print("登录方式：%s" % {"local": "本机", "ssh": "SSH 远程", "winrm": "WinRM 远程"}[args.mode])

    from core.remote import build_executor
    ex = build_executor(conf)
    if args.mode != "local":
        print("连接目标：%s:%s ..." % (args.host, conf["port"]))
        ex.connect()
        print("连接成功：%s" % ex.os_name())

    def on_progress(cur, total, name):
        if not args.quiet:
            sys.stdout.write("\r检测中 %d/%d  %-36s" % (cur, total, name[:36]))
            sys.stdout.flush()

    try:
        summary = engine.run_all(
            level, target=args.target or args.host or "本机", executor=ex,
            on_progress=on_progress, layers=layers, db_conf=db_conf,
            net_conf=net_conf, mw_conf=mw_conf, app_conf=app_conf)
    finally:
        try:
            ex.close()
        except Exception:
            pass
        if not args.quiet:
            sys.stdout.write("\r" + " " * 78 + "\r")

    print("检测完成：共 %d 项　符合 %d　不符合 %d　部分符合 %d　人工核查 %d"
          % (summary.total, summary.pass_count, summary.fail_count,
             summary.warn_count, summary.manual_count))
    print("自查评分：%.1f 分" % summary.score)
    if summary.note:
        print("说明：%s" % summary.note)

    quiz_answers = _load_quiz(args.quiz) if args.quiz else {}
    _print_quiz_answers(quiz_answers)

    if args.no_report:
        return 0 if summary.total else 2

    out_dir = os.path.abspath(args.out or os.path.join(os.getcwd(), "ea-reports"))
    os.makedirs(out_dir, exist_ok=True)
    safe = "".join(c if c not in '\\/:*?"<>|' else "_" for c in (summary.target or "等保自查"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    base = os.path.join(out_dir, "%s-%s" % (safe, stamp))
    quiz_items = qd.get_quiz_items(level, layers=None)

    wrote = []
    if args.format in ("html", "all"):
        p = report.export_html(summary, base + ".html", quiz_items, quiz_answers)
        wrote.append(p)
    if args.format in ("docx", "all"):
        p = report.export_docx(summary, base + ".docx", quiz_items, quiz_answers)
        wrote.append(p)
    if args.format in ("json", "all"):
        p = base + ".json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(_json_report(summary, quiz_answers), f,
                      ensure_ascii=False, indent=2)
        wrote.append(p)

    print("\n报告已生成：")
    for p in wrote:
        print("  %s" % p)
    return 0 if summary.total else 2


if __name__ == "__main__":
    sys.exit(main())
