"""Report generator: PDF, JSON, CSV and SARIF (GitHub code scanning) exports."""
import csv
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from ..agents.rules import RULES, SEVERITY_ORDER

FIELDS = ["severity", "category", "rule_id", "title", "file", "line", "confidence", "cwe", "owasp", "agent",
          "sources", "snippet", "description", "explanation", "remediation", "fixed_code"]
SEV_COLORS = {"Critical": "#B42318", "High": "#D9480F", "Medium": "#B08800", "Low": "#2563EB", "Info": "#6B7280"}


def build_report(meta: dict, findings: list[dict]) -> dict:
    """meta: project, scan_id, scores, summary text, severity counts, codebase info, gate, timings."""
    return {
        "tool": {"name": "CodeGuardian AI", "version": meta.get("version", "1.0.0")},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **meta,
        "findings": findings,
    }


def to_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, default=str).encode()


def to_csv(report: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in report["findings"]:
        row = dict(f)
        row["sources"] = ", ".join(f.get("sources") or [])
        writer.writerow(row)
    return buf.getvalue().encode("utf-8-sig")


def to_sarif(report: dict) -> bytes:
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    security_severity = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "0.0"}
    rule_ids = sorted({f["rule_id"] for f in report["findings"]})
    rules = []
    for rid in rule_ids:
        meta = RULES.get(rid, {})
        sample = next(f for f in report["findings"] if f["rule_id"] == rid)
        tags = [t for t in (meta.get("cwe") or sample.get("cwe"), sample.get("category", "").lower()) if t]
        rules.append({"id": rid, "name": rid,
                      "shortDescription": {"text": meta.get("title") or sample["title"]},
                      "fullDescription": {"text": meta.get("description") or sample.get("description", "")},
                      "help": {"text": meta.get("remediation") or sample.get("remediation", "")},
                      "properties": {"tags": tags, "security-severity": security_severity.get(sample["severity"], "5.0")}})
    results = []
    for f in report["findings"]:
        results.append({
            "ruleId": f["rule_id"], "level": level.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']}. {f.get('explanation') or f.get('description', '')}"[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "properties": {"severity": f["severity"], "confidence": f.get("confidence")},
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "CodeGuardian AI", "version": "1.0.0",
                                           "informationUri": "https://github.com/", "rules": rules}},
                       "results": results}]}
    return json.dumps(sarif, indent=2).encode()


def to_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"CodeGuardian AI report - {report.get('project', '')}")
    ss = getSampleStyleSheet()
    navy = colors.HexColor("#0B2545")
    h1 = ParagraphStyle("h1", parent=ss["Title"], textColor=navy, fontSize=18, leading=22, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=navy, spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#4B5563"))
    code = ParagraphStyle("code", parent=ss["Code"], fontSize=7.5, leading=9.5, backColor=colors.HexColor("#F3F4F6"),
                          borderPadding=4, leftIndent=2)
    center = ParagraphStyle("c", parent=body, alignment=TA_CENTER, leading=14)
    score_style = ParagraphStyle("sc", parent=center, leading=24)

    scores = report.get("scores", {})
    counts = report.get("severity_counts", {})
    gate = report.get("gate", {})
    info = report.get("codebase", {})
    story = [Paragraph("CodeGuardian AI — Security &amp; Code Review Report", h1),
             Paragraph(f"Project: <b>{escape(str(report.get('project', '')))}</b> &nbsp;|&nbsp; Scan #{report.get('scan_id', '-')}"
                       f" &nbsp;|&nbsp; {escape(report.get('generated_at', '')[:19].replace('T', ' '))} UTC", small),
             Spacer(1, 8)]

    def score_cell(label, value, grade):
        return Paragraph(f"<font size=8 color='#4B5563'>{label}</font><br/><font size=20><b>{value:.0f}</b></font>"
                         f"<font size=9>/100</font><br/><font size=9>Grade {grade}</font>", score_style)
    score_table = Table([[score_cell("SECURITY SCORE", scores.get("security_score", 0), scores.get("security_grade", "-")),
                          score_cell("CODE QUALITY SCORE", scores.get("quality_score", 0), scores.get("quality_grade", "-")),
                          score_cell("OVERALL", scores.get("overall_score", 0), scores.get("overall_grade", "-")),
                          Paragraph(f"<font size=8 color='#4B5563'>QUALITY GATE</font><br/><font size=16 color="
                                    f"'{'#067647' if gate.get('passed') else '#B42318'}'><b>{'PASSED' if gate.get('passed') else 'FAILED'}</b></font>"
                                    f"<br/><font size=7>{escape('; '.join(gate.get('reasons', [])) or 'No blocking issues')}</font>", score_style)]],
                        colWidths=[44 * mm] * 4)
    score_table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                                     ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                                     ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                                     ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [score_table, Spacer(1, 6)]

    sev_row = [Paragraph(f"<font color='{SEV_COLORS[s]}'><b>{counts.get(s, 0)}</b></font><br/><font size=8>{s}</font>", center)
               for s in SEVERITY_ORDER]
    sev_table = Table([sev_row], colWidths=[35.2 * mm] * 5)
    sev_table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                                   ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB"))]))
    story += [sev_table, Paragraph("Executive summary", h2), Paragraph(escape(report.get("summary", "")), body)]

    langs = ", ".join(f"{k} ({v['lines']} lines)" for k, v in list(info.get("languages", {}).items())[:6])
    story += [Paragraph("Scope", h2),
              Paragraph(f"{info.get('files', 0)} files, {info.get('lines', 0)} lines, {info.get('dependencies', 0)} dependencies. "
                        f"Languages: {escape(langs) or '-'}.", body)]

    findings = report["findings"]
    if findings:
        story.append(Paragraph("Findings overview", h2))
        rows = [["#", "Severity", "Category", "Issue", "Location"]]
        for i, f in enumerate(findings[:200], 1):
            rows.append([Paragraph(str(i), small), Paragraph(f"<font color='{SEV_COLORS.get(f['severity'], '#000')}'><b>{f['severity']}</b></font>", small),
                         Paragraph(f["category"], small), Paragraph(escape(f["title"][:140]), small),
                         Paragraph(escape(f"{f['file']}:{f['line']}"), small)])
        t = Table(rows, colWidths=[8 * mm, 18 * mm, 22 * mm, 82 * mm, 46 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("FONTSIZE", (0, 0), (-1, 0), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E5E7EB"))]))
        story += [t, PageBreak(), Paragraph("Detailed findings &amp; recommended fixes", h2)]
        for i, f in enumerate([f for f in findings if f["severity"] != "Info"][:120], 1):
            block = [Paragraph(f"<font color='{SEV_COLORS.get(f['severity'], '#000')}'><b>[{f['severity']}]</b></font> "
                               f"<b>{i}. {escape(f['title'][:160])}</b>", body),
                     Paragraph(escape(f"{f['file']}:{f['line']}  ·  {f['category']}  ·  {f.get('cwe') or ''} "
                                      f"{f.get('owasp') or ''}  ·  confidence {float(f.get('confidence') or 0):.0%}  ·  "
                                      f"detected by {', '.join(f.get('sources') or [])}"), small)]
            if f.get("snippet"):
                block.append(Preformatted(f["snippet"][:400], code, maxLineLength=110))
            block.append(Paragraph("<b>Why it matters:</b> " + escape(f.get("explanation") or f.get("description", "")), body))
            block.append(Paragraph("<b>How to fix:</b> " + escape(f.get("remediation", "")).replace("\n", "<br/>"), body))
            if f.get("fixed_code"):
                block += [Paragraph("<b>Suggested secure code:</b>", body), Preformatted(f["fixed_code"][:800], code, maxLineLength=110)]
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.drawString(16 * mm, 9 * mm, "Generated by CodeGuardian AI — Multi-Agent Secure Code Review")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {_doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


EXPORTERS = {
    "json": (to_json, "application/json"),
    "csv": (to_csv, "text/csv"),
    "pdf": (to_pdf, "application/pdf"),
    "sarif": (to_sarif, "application/sarif+json"),
}


def sort_key(f: dict):
    return (-SEVERITY_ORDER.get(f["severity"], 0), -float(f.get("confidence") or 0), f["file"], f["line"])
