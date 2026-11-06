# -*- coding: utf-8 -*-
"""报告导出：HTML（内置样式，直接打印/转PDF）、Word（python-docx 可选）与 PDF（Qt）
技术检测结果按等保层面分章节呈现。
"""
import hashlib
import html as _html
import os
from datetime import datetime
from pathlib import Path

from core import appconfig
from core.models import (STATUS_PASS, STATUS_FAIL, STATUS_WARN,
                         STATUS_MANUAL, STATUS_ERROR, STATUS_TEXT,
                         LAYERS, CATEGORY_LAYER, LAYER_NET)

STATUS_COLOR = {
    STATUS_PASS: "#22c55e", STATUS_FAIL: "#ef4444", STATUS_WARN: "#f59e0b",
    STATUS_MANUAL: "#8b5cf6", STATUS_ERROR: "#94a3b8",
}

_ANSWER_TEXT = {"conform": "符合", "partial": "部分符合",
                "nonconform": "不符合", "na": "不适用"}

_CSS = """
*{box-sizing:border-box}
body{font-family:"Microsoft YaHei","PingFang SC",sans-serif;max-width:1000px;margin:0 auto;padding:40px 24px;color:#1e293b;background:#fff}
h1{font-size:28px;border-bottom:3px solid #2563eb;padding-bottom:12px;color:#1e3a8a}
h2{font-size:20px;margin-top:36px;color:#1e40af;border-left:4px solid #2563eb;padding-left:10px}
h3{font-size:16px;margin-top:24px;color:#1e3a8a}
h4{font-size:14px;margin:16px 0 6px;color:#334155}
table{width:100%;max-width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
th,td{border:1px solid #cbd5e1;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#eff6ff;color:#1e40af}
.badge{color:#fff;padding:2px 10px;border-radius:10px;font-size:12px;white-space:nowrap}
.meta{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 20px;margin:20px 0}
.notice{background:#fffbeb;border:1px solid #f59e0b;border-left:5px solid #f59e0b;color:#92400e;padding:10px 14px;border-radius:6px;margin:16px 0;font-size:13px}
.notice b{color:#b45309}
.grade{font-size:24px;font-weight:600}
.cards{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}
.card{flex:1;min-width:120px;border-radius:10px;padding:16px;text-align:center;color:#fff}
.card .n{font-size:30px;font-weight:700}
.footer{margin-top:48px;color:#94a3b8;font-size:12px;text-align:center;border-top:1px solid #e2e8f0;padding-top:16px}
.signature{margin-top:18px;padding:12px 16px;border:1px dashed #94a3b8;color:#475569;font-size:12px;text-align:center}
@media print{body{padding:0}}
"""

# 供 QTextDocument/Pdf 打印的精简样式：浅色背景、无 flex/grid，避免整页黑底
_PRINT_CSS = """
body{font-family:"Microsoft YaHei","SimSun",sans-serif;color:#000000;background:#ffffff;font-size:10pt}
h1{font-size:18pt;color:#000000;border-bottom:1px solid #444444;padding-bottom:6pt}
h2{font-size:14pt;color:#000000;margin-top:16pt}
h3{font-size:12pt;color:#000000;margin-top:12pt}
h4{font-size:10pt;color:#000000;margin:8pt 0 4pt}
table{font-size:9pt}
th{background-color:#eeeeee;font-weight:bold;text-align:left}
td,th{padding:4pt;vertical-align:top}
.meta{margin:10pt 0}
.notice{border:1px solid #666666;padding:6pt;margin:8pt 0;font-size:9pt}
.footer{margin-top:20pt;border-top:1px solid #999999;padding-top:6pt;color:#444444;font-size:8pt;text-align:center}
.signature{margin-top:16pt;border-top:1px dashed #999999;padding-top:6pt;color:#333333;font-size:8pt}
"""


def _e(s):
    return _html.escape(str(s or ""))


def _cfg_text(key, default=""):
    """读取文本型配置，缺失或异常时回退默认值"""
    try:
        value = appconfig.get(key)
    except Exception:
        value = None
    text = str(value or "").strip()
    return text or default


def _report_title():
    return _cfg_text("report_title", "等保测评报告")


def _org_name():
    return _cfg_text("org_name", "")


def _operator():
    return _cfg_text("operator", "")


def _logo_path():
    """返回存在的 Logo 文件路径，不存在则返回空字符串"""
    path = _cfg_text("logo_path", "")
    if path and os.path.isfile(path):
        return path
    return ""


def _sign_enabled():
    try:
        return bool(appconfig.get("report_signature"))
    except Exception:
        return False


def _logo_src():
    path = _logo_path()
    if not path:
        return ""
    try:
        return Path(os.path.abspath(path)).as_uri()
    except Exception:
        return path.replace("\\", "/")


def _logo_size(default_h=40, max_w=360):
    """Logo 统一等比缩放到默认高度 40px（超出最大宽度时按宽度收缩），返回 (宽, 高)"""
    path = _logo_path()
    try:
        from PIL import Image
        with Image.open(path) as im:
            w, h = im.size
    except Exception:
        return None
    if w <= 0 or h <= 0:
        return None
    scale = float(default_h) / h
    if w * scale > max_w:
        scale = float(max_w) / w
    return max(1, int(round(w * scale))), max(1, int(round(h * scale)))


def _title_html():
    """报告抬头：可配置标题 + 可选 Logo（等比缩放到默认高度）"""
    logo = _logo_src()
    if logo:
        size = _logo_size()
        attr = ' width="%d" height="%d"' % size if size else ' height="40"'
        return ('<h1><img src="%s"%s '
                'style="vertical-align:middle;margin-right:10px">%s</h1>'
                % (_e(logo), attr, _e(_report_title())))
    return "<h1>%s</h1>" % _e(_report_title())


def _score_grade(score):
    if score >= 90:
        return "优", "#22c55e"
    if score >= 75:
        return "良", "#3b82f6"
    if score >= 60:
        return "中", "#f59e0b"
    return "差", "#ef4444"


def _counts(rs):
    p = sum(1 for r in rs if r.status == STATUS_PASS)
    f = sum(1 for r in rs if r.status == STATUS_FAIL)
    w = sum(1 for r in rs if r.status == STATUS_WARN)
    m = sum(1 for r in rs if r.status in (STATUS_MANUAL, STATUS_ERROR))
    counted = p + f + w
    score = round((p * 100 + w * 50) / counted, 1) if counted else 0.0
    return p, f, w, m, score


def _by_layer(results):
    out = []
    for layer, _cats in LAYERS:
        rs = [r for r in results if CATEGORY_LAYER.get(r.category, layer) == layer]
        out.append((layer, rs))
    extra = [r for r in results if r.category not in CATEGORY_LAYER]
    if extra:
        out.append(("其他", extra))
    return out


def _layers_text(results):
    """目标涉及的等保层面（用于批量汇总表）"""
    names = [layer for layer, rs in _by_layer(results) if rs]
    return "、".join(names) or "无"


def _os_label(summary):
    # 仅网络/边界设备报告时，本机 OS 只是扫描平台，不应显示为被测对象的操作系统
    only_network = bool(summary.results) and all(
        CATEGORY_LAYER.get(r.category) == LAYER_NET for r in summary.results)
    return "设备型号" if only_network else "操作系统"


def _table_start(print_friendly=False):
    if print_friendly:
        return '<table border="1" cellspacing="0" cellpadding="6" width="100%">'
    return "<table>"


def _tech_rows(results, print_friendly=False):
    rows = []
    for r in results:
        color = STATUS_COLOR.get(r.status, "#94a3b8")
        status_text = STATUS_TEXT.get(r.status, r.status)
        if print_friendly:
            status_cell = "<td><font color=\"%s\">%s</font></td>" % (
                color, _e(status_text))
        else:
            status_cell = ("<td><span class='badge' style='background:%s'>%s</span></td>"
                           % (color, _e(status_text)))
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td>%s"
            "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _e(r.item_id), _e(r.name), _e(r.clause), status_cell,
                _e(r.expected), _e(r.evidence).replace("\n", "<br>"), _e(r.suggestion)))
    return "\n".join(rows)


def _layer_summary_rows(by_layer):
    rows = ""
    for layer, rs in by_layer:
        if not rs:
            continue
        p, f, w, m, score = _counts(rs)
        color = _score_grade(score)[1] if (p + f + w) else "#64748b"
        rows += ("<tr><td>%s</td><td>%d</td><td>%d</td>"
                 "<td style='color:#22c55e'>%d</td><td style='color:#ef4444'>%d</td>"
                 "<td style='color:#f59e0b'>%d</td><td style='color:#8b5cf6'>%d</td>"
                 "<td style='color:%s;font-weight:700'>%.1f</td></tr>" % (
                     _e(layer), len(rs), p + f + w, p, f, w, m, color, score))
    return rows


def _layer_details(by_layer, print_friendly=False, heading_level=3):
    html = ""
    tag = "h%d" % heading_level
    for layer, rs in by_layer:
        if not rs:
            continue
        p, f, w, m, score = _counts(rs)
        html += ("<%s>%s（得分 %.1f，符合 %d / 不符合 %d / 部分符合 %d / 人工核查 %d）</%s>"
                 % (tag, _e(layer), score, p, f, w, m, tag))
        html += (_table_start(print_friendly) +
                 "<thead><tr><th>编号</th><th>检测项</th><th>等保条款</th>"
                 "<th>结论</th><th>合规要求</th><th>检测结果/证据</th><th>整改建议</th>"
                 "</tr></thead><tbody>" + _tech_rows(rs, print_friendly) +
                 "</tbody></table>")
    return html


def _quiz_html(quiz_items, quiz_answers, heading="二、管理要求问卷评估结果",
               print_friendly=False):
    if not (quiz_items and quiz_answers):
        return ""
    qrows = ""
    for q in quiz_items:
        a = quiz_answers.get(q.qid, {})
        ans = a.get("answer", "")
        label = _ANSWER_TEXT.get(ans, "未作答")
        color = {"conform": "#22c55e", "partial": "#f59e0b",
                 "nonconform": "#ef4444", "na": "#94a3b8"}.get(ans, "#64748b")
        if print_friendly:
            status_cell = "<td><font color=\"%s\">%s</font></td>" % (color, _e(label))
        else:
            status_cell = ("<td><span class='badge' style='background:%s'>%s</span></td>"
                           % (color, _e(label)))
        qrows += ("<tr><td>%s</td><td>%s</td><td>%s</td>%s<td>%s</td></tr>" % (
            _e(q.qid), _e(q.category), _e(q.text), status_cell, _e(q.suggestion)))
    return ("<h2>%s</h2>" % _e(heading)) + _table_start(print_friendly) + \
        "<thead><tr><th>编号</th><th>类别</th><th>评估项</th>" \
        "<th>结论</th><th>整改建议</th></tr></thead><tbody>" + qrows + \
        "</tbody></table>"


def _meta_html(summary):
    """报告元信息：被测对象/平台/级别/时间/编制单位/检测人"""
    fields = [
        ("被测对象", summary.target),
        (_os_label(summary), summary.os_name),
        ("测评级别", "等保%s" % summary.level),
        ("测评时间", summary.started),
    ]
    org = _org_name()
    if org:
        fields.append(("编制单位", org))
    op = _operator()
    if op:
        fields.append(("检测人", op))

    rows = ""
    for i in range(0, len(fields), 2):
        chunk = fields[i:i + 2]
        cells = "".join(
            "<td style='border:none;background:transparent'><b>%s：%s</b></td>"
            % (_e(k), _e(v)) for k, v in chunk)
        if len(chunk) == 1:
            cells += "<td style='border:none;background:transparent'></td>"
        rows += "<tr>%s</tr>" % cells
    # 备注：权限提示 / 网络设备直连核查 / 数据库直连核查等
    note = getattr(summary, "note", "") or ""
    if note:
        rows += (
            "<tr><td colspan='2' style='border:none;background:transparent'>"
            "<b style='color:#d97706'>备注：</b>"
            "<span style='color:#d97706'>%s</span></td></tr>"
        ) % _e(note)
    return ('<table class="meta" border="0" cellspacing="0" cellpadding="6" '
            'width="100%%">%s</table>') % rows


def _score_block(score, grade, gcolor, print_friendly=False):
    note = "得分=Σ(符合100/部分符合50/不符合0)÷计入项数；“需人工核查”项不计分"
    if print_friendly:
        return ('<table border="0" cellspacing="0" cellpadding="6" width="100%%"><tr>'
                '<td width="28%%"><span style="font-size:26pt;font-weight:700;color:%s">%.1f</span>'
                '<span style="color:#666666"> / 100</span></td>'
                '<td><span style="font-size:14pt;font-weight:700;color:%s">综合评定：%s</span><br>'
                '<span style="font-size:8pt;color:#666666">%s</span></td></tr></table>') % (
            gcolor, score, gcolor, _e(grade), _e(note))
    # 表格布局：浏览器与内嵌 QTextBrowser 预览都能正确横向排列
    return ('<table border="0" cellspacing="0" cellpadding="0" width="100%%" '
            'style="margin:24px 0"><tr>'
            '<td style="vertical-align:middle">'
            '<span style="font-size:52px;font-weight:700;color:%s">%.1f</span>'
            '<span style="color:#64748b"> / 100</span></td>'
            '<td style="vertical-align:middle">'
            '<span class="grade" style="color:%s">综合评定：%s</span>'
            '<div style="color:#64748b;font-size:13px;margin-top:6px">%s</div>'
            '</td></tr></table>') % (
        gcolor, score, gcolor, _e(grade), _e(note))


def _cards_html(cards, print_friendly=False):
    """统计卡片：浏览器用 flex 色块，打印用表格 + 彩色文字（无背景色）"""
    if print_friendly:
        cells = ""
        for value, label, color in cards:
            cells += ('<td align="center"><font color="%s"><b style="font-size:14pt">%s</b></font>'
                      '<br>%s</td>') % (color, _e(value), _e(label))
        return ('<table border="1" cellspacing="0" cellpadding="6" width="100%%">'
                '<tr>%s</tr></table>') % cells
    # 表格布局：浏览器与内嵌 QTextBrowser 预览都能正确横向排列（bgcolor 兼容旧版 Qt）
    cells = ""
    for value, label, color in cards:
        cells += ('<td class="card" bgcolor="%s" width="25%%" align="center" '
                  'style="background:%s;color:#ffffff;border-radius:10px;padding:16px;">'
                  '<span style="font-size:30px;font-weight:700">%s</span><br>%s</td>'
                  % (color, color, _e(value), _e(label)))
    return ('<table border="0" cellspacing="10" cellpadding="0" width="100%%">'
            '<tr>%s</tr></table>') % cells


def _checksum(results):
    """报告防篡改校验码：检测项 item_id+status 稳定排序后取 sha256 前 16 位"""
    payload = "".join(sorted("%s%s" % (getattr(r, "item_id", ""),
                                       getattr(r, "status", "")) for r in results))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _signature_text(results, now=None):
    if not _sign_enabled():
        return ""
    now = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return "报告校验码：%s（生成时间：%s）" % (_checksum(results), now)


def build_html(summary, quiz_items=None, quiz_answers=None, print_friendly=False) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    grade, gcolor = _score_grade(summary.score)
    by_layer = _by_layer(summary.results)

    summary_rows = _layer_summary_rows(by_layer)
    details = _layer_details(by_layer, print_friendly)
    quiz_html = _quiz_html(quiz_items, quiz_answers, print_friendly=print_friendly)

    bad_items = [r for r in summary.results if r.status == STATUS_FAIL]
    rectify = ""
    for i, r in enumerate(bad_items, 1):
        rectify += "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            i, _e(r.name), _e(r.clause), _e(r.suggestion))
    if not rectify:
        rectify = "<tr><td colspan='4' style='text-align:center'>未发现“不符合”技术项</td></tr>"

    cards = _cards_html([
        (summary.total, "检测项总数", "#334155"),
        (summary.pass_count, "符合", "#22c55e"),
        (summary.fail_count, "不符合", "#ef4444"),
        (summary.warn_count, "部分符合", "#f59e0b"),
        (summary.manual_count, "需人工核查", "#8b5cf6"),
    ], print_friendly)

    footer_text = ("本报告由「勤加等保测评助手」自动生成 · 仅用于内部等保测试，"
                   "不作为等保评审依据 · 生成时间 %s" % now)
    org = _org_name()
    if org:
        footer_text = "编制单位：%s<br>%s" % (_e(org), footer_text)
    sig = _signature_text(summary.results, now)
    signature_html = ('<div class="signature">%s</div>' % _e(sig)) if sig else ""

    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{title} - {target}</title>
<style>{css}</style></head><body>
{title_html}
<div class="notice">使用范围说明：本报告由勤加等保测评助手生成，<b>仅用于内部等保测试与整改参考，不作为等保评审/测评依据</b>。检测结论需结合人工核查确认。</div>
{meta}
{score}
{cards}
<h2>一、技术检测结果</h2>
<h3>1.1 分层统计</h3>
{table_start}<thead><tr><th>等保层面</th><th>检测项</th><th>计入项</th><th>符合</th><th>不符合</th><th>部分符合</th><th>人工核查</th><th>层面得分</th></tr></thead>
<tbody>{summary_rows}</tbody></table>
<h3>1.2 分层检测明细</h3>
{details}
{quiz}
<h2>三、不符合项整改清单</h2>
{table_start}<thead><tr><th>#</th><th>不符合项</th><th>等保条款</th><th>整改建议</th></tr></thead>
<tbody>{rectify}</tbody></table>
<div class="footer">{footer}</div>
{signature}
</body></html>""".format(
        title=_e(_report_title()), target=_e(summary.target),
        css=_PRINT_CSS if print_friendly else _CSS,
        title_html=_title_html(),
        meta=_meta_html(summary),
        score=_score_block(summary.score, grade, gcolor, print_friendly),
        cards=cards,
        table_start=_table_start(print_friendly),
        summary_rows=summary_rows, details=details, quiz=quiz_html,
        rectify=rectify, footer=footer_text, signature=signature_html)


def export_html(summary, path, quiz_items=None, quiz_answers=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(summary, quiz_items, quiz_answers))


# ---------------- Word 导出 ----------------

def _add_docx_logo(doc):
    logo = _logo_path()
    if not logo:
        return
    try:
        from docx.shared import Inches
        # 与 HTML/PDF 一致：统一等比缩放到默认高度 40px（96dpi 下约 0.42 英寸）
        doc.add_picture(logo, height=Inches(40 / 96.0))
    except Exception:
        # Logo 损坏/格式不支持时不影响报告主体导出
        pass


def _add_docx_result_table(doc, rs):
    table = doc.add_table(rows=1, cols=6)
    table.style = "Light Grid Accent 1"
    for i, t in enumerate(["编号", "检测项", "条款", "结论", "检测结果", "整改建议"]):
        table.rows[0].cells[i].text = t
    for rr in rs:
        cells = table.add_row().cells
        cells[0].text = rr.item_id
        cells[1].text = rr.name
        cells[2].text = rr.clause
        cells[3].text = STATUS_TEXT.get(rr.status, rr.status)
        cells[4].text = (rr.evidence or "")[:500]
        cells[5].text = rr.suggestion


def _add_docx_layer_details(doc, by_layer, heading_level=3):
    for layer, rs in by_layer:
        if not rs:
            continue
        p, f, w, m, score = _counts(rs)
        doc.add_heading("%s（得分 %.1f，符合 %d / 不符合 %d / 部分符合 %d / 人工核查 %d）"
                        % (layer, score, p, f, w, m), heading_level)
        _add_docx_result_table(doc, rs)


def _add_docx_quiz(doc, quiz_items, quiz_answers, heading):
    if not (quiz_items and quiz_answers):
        return
    doc.add_heading(heading, 1)
    t2 = doc.add_table(rows=1, cols=4)
    t2.style = "Light Grid Accent 1"
    for i, t in enumerate(["编号", "类别", "评估项", "结论"]):
        t2.rows[0].cells[i].text = t
    for q in quiz_items:
        a = quiz_answers.get(q.qid, {})
        cells = t2.add_row().cells
        cells[0].text = q.qid
        cells[1].text = q.category
        cells[2].text = q.text
        cells[3].text = _ANSWER_TEXT.get(a.get("answer", ""), "未作答")


def _add_docx_footer(doc, results, now):
    org = _org_name()
    tail = "本报告由「勤加等保测评助手」自动生成，仅用于内部等保测试，不作为等保评审依据。"
    if org:
        tail = "编制单位：%s\n%s" % (org, tail)
    doc.add_paragraph(tail)
    sig = _signature_text(results, now)
    if sig:
        doc.add_paragraph(sig)


def export_docx(summary, path, quiz_items=None, quiz_answers=None):
    """导出 Word，需 python-docx；未安装则抛 ImportError"""
    from docx import Document
    from docx.shared import Pt

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = Document()
    _add_docx_logo(doc)
    doc.add_heading(_report_title(), 0)
    notice = doc.add_paragraph()
    nr = notice.add_run(
        "使用范围说明：本报告由勤加等保测评助手生成，仅用于内部等保测试与整改参考，"
        "不作为等保评审/测评依据。检测结论需结合人工核查确认。")
    nr.italic = True
    nr.font.size = Pt(9)
    doc.add_paragraph("被测对象：%s    %s：%s\n测评级别：等保%s    测评时间：%s" % (
        summary.target, _os_label(summary), summary.os_name,
        summary.level, summary.started))
    extra = []
    if _org_name():
        extra.append("编制单位：%s" % _org_name())
    if _operator():
        extra.append("检测人：%s" % _operator())
    if extra:
        doc.add_paragraph("    ".join(extra))
    # 备注：权限提示 / 网络设备直连核查 / 数据库直连核查等
    note = getattr(summary, "note", "") or ""
    if note:
        np = doc.add_paragraph()
        nr = np.add_run("备注：%s" % note)
        nr.bold = True
        nr.font.size = Pt(10)
    grade, _ = _score_grade(summary.score)
    h = doc.add_paragraph()
    r = h.add_run("综合得分：%.1f / 100（%s）" % (summary.score, grade))
    r.bold = True
    r.font.size = Pt(16)
    doc.add_paragraph("检测项 %d 项：符合 %d、不符合 %d、部分符合 %d、需人工核查 %d" % (
        summary.total, summary.pass_count, summary.fail_count,
        summary.warn_count, summary.manual_count))

    doc.add_heading("一、技术检测结果", 1)
    by_layer = _by_layer(summary.results)
    doc.add_heading("1.1 分层统计", 2)
    st = doc.add_table(rows=1, cols=7)
    st.style = "Light Grid Accent 1"
    for i, t in enumerate(["等保层面", "检测项", "符合", "不符合", "部分符合", "人工核查", "层面得分"]):
        st.rows[0].cells[i].text = t
    for layer, rs in by_layer:
        if not rs:
            continue
        p, f, w, m, score = _counts(rs)
        cells = st.add_row().cells
        for i, v in enumerate([layer, len(rs), p, f, w, m, "%.1f" % score]):
            cells[i].text = str(v)

    doc.add_heading("1.2 分层检测明细", 2)
    _add_docx_layer_details(doc, by_layer, heading_level=3)

    _add_docx_quiz(doc, quiz_items, quiz_answers, "二、管理要求问卷评估")

    doc.add_heading("三、不符合项整改清单", 1)
    bad = [r for r in summary.results if r.status == STATUS_FAIL]
    if bad:
        for i, r in enumerate(bad, 1):
            doc.add_paragraph("%d. [%s] %s\n   整改建议：%s" % (i, r.clause, r.name, r.suggestion))
    else:
        doc.add_paragraph("未发现“不符合”技术项。")
    _add_docx_footer(doc, summary.results, now)
    doc.save(path)


# ---------------- PDF 导出（QTextDocument + QPrinter） ----------------

_QT_APP = None


def _ensure_qapp():
    """确保进程内有 QApplication；无图形环境时抛出 RuntimeError"""
    global _QT_APP
    try:
        from PyQt5.QtWidgets import QApplication
    except Exception as exc:
        raise RuntimeError("PDF 导出需要图形环境") from exc
    app = QApplication.instance()
    if app is not None:
        return app
    try:
        _QT_APP = QApplication([])
    except Exception as exc:
        raise RuntimeError("PDF 导出需要图形环境") from exc
    return _QT_APP


def _write_pdf(html, path):
    _ensure_qapp()
    try:
        from PyQt5.QtGui import QTextDocument
        from PyQt5.QtPrintSupport import QPrinter
        from PyQt5.QtCore import QMarginsF
    except Exception as exc:
        raise RuntimeError("PDF 导出需要图形环境") from exc

    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(path))
    printer.setPageSize(QPrinter.A4)
    try:
        printer.setPageMargins(QMarginsF(12, 12, 12, 12), QPrinter.Millimeter)
    except TypeError:
        # 部分 PyQt5 版本只暴露 5 参数重载
        printer.setPageMargins(12, 12, 12, 12, QPrinter.Millimeter)

    doc = QTextDocument()
    doc.setHtml(html)
    doc.print_(printer)


def export_pdf(summary, path, quiz_items=None, quiz_answers=None):
    """导出 PDF：复用打印版 HTML，经 Qt 渲染，不新增第三方依赖"""
    html = build_html(summary, quiz_items, quiz_answers, print_friendly=True)
    _write_pdf(html, path)


# ---------------- 批量合并导出 ----------------

_FORMAT_BY_EXT = {".html": "html", ".htm": "html", ".docx": "docx", ".pdf": "pdf"}


def _resolve_format(path, fmt):
    """以 path 后缀优先确定实际格式；后缀无法识别时回退 fmt"""
    ext = os.path.splitext(os.fspath(path))[1].lower()
    if ext in _FORMAT_BY_EXT:
        return _FORMAT_BY_EXT[ext]
    fmt = str(fmt or "html").lower()
    return fmt if fmt in ("html", "docx", "pdf") else "html"


def _batch_stats(items):
    total = len(items)
    scores = [float(s.score or 0) for _name, s in items]
    avg = (sum(scores) / total) if total else 0.0
    passed = sum(1 for score in scores if score >= 75)
    return total, avg, passed, total - passed


def _batch_results(items):
    results = []
    for _name, summary in items:
        results.extend(getattr(summary, "results", []) or [])
    return results


def _fail_rows(items):
    """收集各系统的不合格项（不符合 + 检测异常），返回 [(目标名称, CheckResult)]"""
    from core.models import STATUS_FAIL, STATUS_ERROR
    rows = []
    for name, s in items:
        display = name or s.target or "未命名目标"
        for r in (getattr(s, "results", []) or []):
            if r.status in (STATUS_FAIL, STATUS_ERROR):
                rows.append((display, r))
    return rows


def _fail_section_html(items, print_friendly=False):
    """批量报告「不合格项汇总」小节：列出各系统不符合/异常项与整改建议"""
    rows = _fail_rows(items)
    if not rows:
        return ""
    trs = ""
    for display, r in rows:
        trs += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>") % (
            _e(display), _e(r.name), _e(r.clause), _e(r.suggestion))
    return ("<h3>1.2 不合格项汇总（各系统不符合 / 异常项，共 %d 条）</h3>" % len(rows)
            + _table_start(print_friendly)
            + "<thead><tr><th>目标名称</th><th>检测项</th><th>等保条款</th>"
              "<th>整改建议</th></tr></thead>"
            + "<tbody>" + trs + "</tbody></table>")


def build_batch_html(items, quiz_items=None, quiz_answers=None, print_friendly=False) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total, avg, passed, rectify = _batch_stats(items)
    grade, gcolor = _score_grade(avg)

    cards = _cards_html([
        (total, "目标总数", "#334155"),
        ("%.1f" % avg, "平均得分", gcolor),
        (passed, "达标（≥75分）", "#22c55e"),
        (rectify, "待整改", "#f59e0b"),
    ], print_friendly)

    summary_rows = ""
    for name, s in items:
        display = name or s.target or "未命名目标"
        color = _score_grade(s.score)[1]
        summary_rows += ("<tr><td>%s</td><td>%s</td>"
                         "<td style='color:%s;font-weight:700'>%.1f</td>"
                         "<td>%d</td></tr>") % (
            _e(display), _e(_layers_text(s.results)), color, s.score, s.total)

    details = ""
    for i, (name, s) in enumerate(items, 1):
        display = name or s.target or "未命名目标"
        details += ("<h3>2.%d 目标：%s（得分 %.1f，共 %d 项）</h3>"
                    % (i, _e(display), s.score, s.total))
        note = getattr(s, "note", "") or ""
        if note:
            details += ("<p style='color:#d97706;font-weight:600'>备注：%s</p>"
                        % _e(note))
        details += _layer_details(_by_layer(s.results), print_friendly, heading_level=4)

    quiz_html = _quiz_html(quiz_items, quiz_answers,
                           heading="三、管理要求问卷评估结果",
                           print_friendly=print_friendly)

    footer_text = ("本报告由「勤加等保测评助手」自动生成 · 仅用于内部等保测试，"
                   "不作为等保评审依据 · 生成时间 %s" % now)
    org = _org_name()
    if org:
        footer_text = "编制单位：%s<br>%s" % (_e(org), footer_text)
    op = _operator()
    if op:
        footer_text = "检测人：%s<br>%s" % (_e(op), footer_text)
    sig = _signature_text(_batch_results(items), now)
    signature_html = ('<div class="signature">%s</div>' % _e(sig)) if sig else ""

    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{title} - 批量汇总</title>
<style>{css}</style></head><body>
{title_html}
<div class="notice">使用范围说明：本报告由勤加等保测评助手批量生成，<b>仅用于内部等保测试与整改参考，不作为等保评审/测评依据</b>。检测结论需结合人工核查确认。</div>
<h2>一、批量检测汇总</h2>
{cards}
<h3>1.1 目标统计</h3>
{table_start}<thead><tr><th>目标名称</th><th>检测层面</th><th>得分</th><th>检测项数</th></tr></thead>
<tbody>{summary_rows}</tbody></table>
{fail_section}
<h2>二、各目标检测明细</h2>
{details}
{quiz}
<div class="footer">{footer}</div>
{signature}
</body></html>""".format(
        title=_e(_report_title()),
        css=_PRINT_CSS if print_friendly else _CSS,
        title_html=_title_html().replace("</h1>", "（批量汇总）</h1>"),
        cards=cards,
        table_start=_table_start(print_friendly),
        summary_rows=summary_rows, fail_section=_fail_section_html(items, print_friendly),
        details=details, quiz=quiz_html,
        footer=footer_text, signature=signature_html)


def _export_batch_docx(items, path, quiz_items=None, quiz_answers=None):
    from docx import Document

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total, avg, passed, rectify = _batch_stats(items)
    grade, _ = _score_grade(avg)
    doc = Document()
    _add_docx_logo(doc)
    doc.add_heading("%s（批量汇总）" % _report_title(), 0)
    doc.add_paragraph(
        "使用范围说明：本报告由勤加等保测评助手批量生成，仅用于内部等保测试与整改参考，"
        "不作为等保评审/测评依据。检测结论需结合人工核查确认。")
    doc.add_paragraph(
        "目标总数：%d    平均得分：%.1f / 100（%s）    达标（≥75分）：%d    待整改：%d\n"
        "生成时间：%s" % (total, avg, grade, passed, rectify, now))
    extra = []
    if _org_name():
        extra.append("编制单位：%s" % _org_name())
    if _operator():
        extra.append("检测人：%s" % _operator())
    if extra:
        doc.add_paragraph("    ".join(extra))

    doc.add_heading("一、批量检测汇总", 1)
    st = doc.add_table(rows=1, cols=4)
    st.style = "Light Grid Accent 1"
    for i, t in enumerate(["目标名称", "检测层面", "得分", "检测项数"]):
        st.rows[0].cells[i].text = t
    for name, s in items:
        cells = st.add_row().cells
        cells[0].text = name or s.target or "未命名目标"
        cells[1].text = _layers_text(s.results)
        cells[2].text = "%.1f" % s.score
        cells[3].text = str(s.total)

    fail_rows = _fail_rows(items)
    if fail_rows:
        doc.add_heading("1.2 不合格项汇总（各系统不符合 / 异常项，共 %d 条）" % len(fail_rows), 2)
        ft = doc.add_table(rows=1, cols=4)
        ft.style = "Light Grid Accent 1"
        for i, t in enumerate(["目标名称", "检测项", "等保条款", "整改建议"]):
            ft.rows[0].cells[i].text = t
        for display, r in fail_rows:
            cells = ft.add_row().cells
            cells[0].text = display
            cells[1].text = r.name
            cells[2].text = r.clause
            cells[3].text = r.suggestion

    doc.add_heading("二、各目标检测明细", 1)
    for i, (name, s) in enumerate(items, 1):
        display = name or s.target or "未命名目标"
        doc.add_heading("%d. %s（得分 %.1f，共 %d 项）" % (i, display, s.score, s.total), 2)
        note = getattr(s, "note", "") or ""
        if note:
            np = doc.add_paragraph()
            nr = np.add_run("备注：%s" % note)
            nr.bold = True
        _add_docx_layer_details(doc, _by_layer(s.results), heading_level=3)

    _add_docx_quiz(doc, quiz_items, quiz_answers, "三、管理要求问卷评估")
    _add_docx_footer(doc, _batch_results(items), now)
    doc.save(path)


def export_batch(items, path, fmt="html", quiz_items=None, quiz_answers=None):
    """批量合并导出：items 为 [(目标名称, RunSummary)]，支持 html/docx/pdf"""
    actual = _resolve_format(path, fmt)
    if actual == "docx":
        _export_batch_docx(items, path, quiz_items, quiz_answers)
    elif actual == "pdf":
        _write_pdf(build_batch_html(items, quiz_items, quiz_answers,
                                    print_friendly=True), path)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(build_batch_html(items, quiz_items, quiz_answers))
