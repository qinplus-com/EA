# -*- coding: utf-8 -*-
"""SQLite 历史记录存储 + 基线对比"""
import os
import sqlite3
from datetime import datetime

from core.models import STATUS_TEXT

DB_DIR = os.path.join(os.path.expanduser("~"), ".ea_dengbao")
DB_PATH = os.path.join(DB_DIR, "ea_history.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, os_name TEXT, level TEXT, started TEXT,
    score REAL, pass_count INT, fail_count INT, warn_count INT,
    manual_count INT, total INT, batch_group TEXT
);
CREATE TABLE IF NOT EXISTS results (
    run_id INT, item_id TEXT, name TEXT, category TEXT, level TEXT,
    clause TEXT, expected TEXT, suggestion TEXT, status TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS quiz (
    run_id INT, qid TEXT, category TEXT, text TEXT, level TEXT,
    clause TEXT, answer TEXT, suggestion TEXT
);
CREATE TABLE IF NOT EXISTS remediation (
    run_id INT, item_id TEXT, state TEXT, note TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, level TEXT, message TEXT
);
"""


def _conn():
    os.makedirs(DB_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.executescript(_SCHEMA)
    # 兼容旧库：补 batch_group 列
    try:
        cols = [r[1] for r in c.execute("PRAGMA table_info(runs)").fetchall()]
        if "batch_group" not in cols:
            c.execute("ALTER TABLE runs ADD COLUMN batch_group TEXT")
            c.commit()
    except Exception:
        pass
    return c


def save_run(summary, batch_group=None) -> int:
    c = _conn()
    try:
        cur = c.execute(
            "INSERT INTO runs(target,os_name,level,started,score,pass_count,fail_count,"
            "warn_count,manual_count,total,batch_group) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (summary.target, summary.os_name, summary.level, summary.started,
             summary.score, summary.pass_count, summary.fail_count,
             summary.warn_count, summary.manual_count, summary.total,
             batch_group or ""))
        run_id = cur.lastrowid
        for r in summary.results:
            c.execute(
                "INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?)",
                (run_id, r.item_id, r.name, r.category, r.level, r.clause,
                 r.expected, r.suggestion, r.status, r.evidence))
        for qid, a in summary.quiz_answers.items():
            c.execute(
                "INSERT INTO quiz VALUES(?,?,?,?,?,?,?,?)",
                (run_id, qid, a.get("category", ""), a.get("text", ""),
                 a.get("level", ""), a.get("clause", ""),
                 a.get("answer", ""), a.get("suggestion", "")))
        c.commit()
        summary.run_id = run_id
        return run_id
    finally:
        c.close()


def list_runs(limit=100):
    c = _conn()
    try:
        return c.execute(
            "SELECT id,target,os_name,level,started,score,pass_count,fail_count,"
            "warn_count,manual_count,total,batch_group FROM runs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    finally:
        c.close()


def score_trend(limit=20):
    """得分趋势：按时间正序返回 [(started, score, target)]"""
    c = _conn()
    try:
        rows = c.execute(
            "SELECT started,score,target FROM runs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return list(reversed(rows))
    finally:
        c.close()


def set_remediation(run_id, item_id, state, note=""):
    """标记整改状态：state = done(已整改) / pending(待整改) / ignored(不适用)"""
    c = _conn()
    try:
        c.execute("DELETE FROM remediation WHERE run_id=? AND item_id=?",
                  (run_id, item_id))
        c.execute(
            "INSERT INTO remediation(run_id,item_id,state,note,updated) VALUES(?,?,?,?,?)",
            (run_id, item_id, state, note or "", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        c.commit()
    finally:
        c.close()


def get_remediations(run_id):
    """返回 {item_id: (state, note, updated)}"""
    c = _conn()
    try:
        rows = c.execute(
            "SELECT item_id,state,note,updated FROM remediation WHERE run_id=?",
            (run_id,)).fetchall()
        return {r[0]: (r[1], r[2], r[3]) for r in rows}
    finally:
        c.close()


def remediation_stats(run_id):
    """返回 (已整改数, 待整改数, 不适用数)"""
    c = _conn()
    try:
        rows = c.execute(
            "SELECT state,COUNT(*) FROM remediation WHERE run_id=? GROUP BY state",
            (run_id,)).fetchall()
        d = dict(rows)
        return d.get("done", 0), d.get("pending", 0), d.get("ignored", 0)
    finally:
        c.close()


def backup_db(dest_path):
    """备份历史数据库到指定文件"""
    import shutil
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    if not os.path.exists(DB_PATH):
        raise RuntimeError("尚无历史数据库可备份")
    shutil.copy2(DB_PATH, dest_path)
    return dest_path


def restore_db(src_path):
    """从备份文件恢复历史数据库（先自动备份当前库）"""
    import shutil
    if not os.path.exists(src_path):
        raise RuntimeError("备份文件不存在：%s" % src_path)
    if os.path.exists(DB_PATH):
        auto = DB_PATH + ".before_restore"
        shutil.copy2(DB_PATH, auto)
    shutil.copy2(src_path, DB_PATH)
    return DB_PATH


def add_log(level, message):
    """写入一条日志记录"""
    c = _conn()
    try:
        c.execute("INSERT INTO logs(ts,level,message) VALUES(?,?,?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, str(message)))
        c.commit()
    finally:
        c.close()


def list_logs(limit=500, keyword=""):
    c = _conn()
    try:
        if keyword:
            return c.execute(
                "SELECT ts,level,message FROM logs WHERE message LIKE ? "
                "ORDER BY id DESC LIMIT ?", ("%" + keyword + "%", limit)).fetchall()
        return c.execute(
            "SELECT ts,level,message FROM logs ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    finally:
        c.close()


def clear_logs():
    c = _conn()
    try:
        c.execute("DELETE FROM logs")
        c.commit()
    finally:
        c.close()


def load_run(run_id):
    """返回 (run_row, results_list, quiz_list)"""
    c = _conn()
    try:
        run = c.execute(
            "SELECT id,target,os_name,level,started,score,pass_count,fail_count,"
            "warn_count,manual_count,total FROM runs WHERE id=?", (run_id,)).fetchone()
        results = c.execute(
            "SELECT item_id,name,category,level,clause,expected,suggestion,status,evidence "
            "FROM results WHERE run_id=?", (run_id,)).fetchall()
        quiz = c.execute(
            "SELECT qid,category,text,level,clause,answer,suggestion FROM quiz WHERE run_id=?",
            (run_id,)).fetchall()
        return run, results, quiz
    finally:
        c.close()


def delete_run(run_id):
    c = _conn()
    try:
        for t in ("results", "quiz", "remediation"):
            c.execute("DELETE FROM %s WHERE run_id=?" % t, (run_id,))
        c.execute("DELETE FROM runs WHERE id=?", (run_id,))
        c.commit()
    finally:
        c.close()


def compare_runs(old_id: int, new_id: int):
    """对比两次检测，返回列表 [(item_id, name, category, old_status, new_status, trend)]
    trend: fixed(已整改) / still(仍不符合) / new_issue(新增问题) / same(无变化)"""
    _, old_results, _ = load_run(old_id)
    _, new_results, _ = load_run(new_id)
    old_map = {r[0]: r for r in old_results}
    new_map = {r[0]: r for r in new_results}
    rows = []
    for iid, nr in new_map.items():
        name, cat, nstatus = nr[1], nr[2], nr[7]
        orow = old_map.get(iid)
        ostatus = orow[7] if orow else None
        if ostatus is None:
            trend = "new_item"
        elif ostatus == nstatus:
            trend = "still" if nstatus in ("fail", "warn") else "same"
        else:
            if nstatus == "pass" and ostatus in ("fail", "warn"):
                trend = "fixed"
            elif nstatus in ("fail", "warn") and ostatus == "pass":
                trend = "new_issue"
            else:
                trend = "changed"
        rows.append((iid, name, cat, STATUS_TEXT.get(ostatus, ostatus or "—"),
                     STATUS_TEXT.get(nstatus, nstatus), trend))
    return rows
