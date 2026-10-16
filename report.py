"""
PDF-rapport för en genomförd leverantörssäkerhetsbedömning.
Bygger rapporten från samma resultat som visas på webbsidan.
"""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from classification import CLASSIFICATION_LEVELS

FONT_DIR = Path(__file__).parent / "fonts"
pdfmetrics.registerFont(TTFont("Noto", str(FONT_DIR / "NotoSans-Regular.ttf")))
pdfmetrics.registerFont(TTFont("Noto-Bold", str(FONT_DIR / "NotoSans-Bold.ttf")))
pdfmetrics.registerFontFamily("Noto", normal="Noto", bold="Noto-Bold")

BLUE = colors.HexColor("#005aa0")
BLUE_DARK = colors.HexColor("#00427a")
BLUE_LIGHT = colors.HexColor("#e3f4fc")
RED = colors.HexColor("#e40523")
GREEN = colors.HexColor("#2e7d32")
AMBER = colors.HexColor("#b26a00")
INK = colors.HexColor("#292929")
MUTED = colors.HexColor("#666666")
LINE = colors.HexColor("#d6d6d6")
PAPER = colors.HexColor("#f5f5f5")

STATUS = {
    "found": ("Uppfyllt", GREEN),
    "partial": ("Delvis uppfyllt", AMBER),
    "not_found": ("Ej uppfyllt", RED),
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
HEADER_H = 46 * mm
MAX_SNIPPET = 320

MONTHS = ["januari", "februari", "mars", "april", "maj", "juni", "juli",
          "augusti", "september", "oktober", "november", "december"]


def _style(name: str, **kw) -> ParagraphStyle:
    base = dict(fontName="Noto", fontSize=9.5, leading=13.5, textColor=INK)
    base.update(kw)
    return ParagraphStyle(name, **base)


S_BODY = _style("body")
S_SMALL = _style("small", fontSize=8, leading=11, textColor=MUTED)
S_H2 = _style("h2", fontName="Noto-Bold", fontSize=13, leading=17, textColor=BLUE_DARK,
              spaceBefore=14, spaceAfter=8)
S_H3 = _style("h3", fontName="Noto-Bold", fontSize=10.5, leading=14, textColor=INK)
S_LABEL = _style("label", fontName="Noto-Bold", fontSize=7.5, leading=10, textColor=MUTED)
S_SNIPPET = _style("snippet", fontSize=8.5, leading=12, textColor=colors.HexColor("#444444"),
                   leftIndent=8, borderPadding=(0, 0, 0, 6))
S_SCORE = _style("score", fontName="Noto-Bold", fontSize=40, leading=44, alignment=TA_CENTER)
S_CENTER = _style("center", alignment=TA_CENTER)
S_STAT = _style("stat", fontName="Noto-Bold", fontSize=20, leading=24, alignment=TA_CENTER)
S_STAT_LABEL = _style("statlabel", fontSize=8, leading=10, textColor=MUTED, alignment=TA_CENTER)


def _p(text: str, style: ParagraphStyle = S_BODY) -> Paragraph:
    return Paragraph(text, style)


def _hex(color) -> str:
    return "#" + color.hexval()[2:]


def _esc(value) -> str:
    return escape(str(value or ""))


def _link(url: str) -> str:
    safe = _esc(url)
    return f'<link href="{safe}" color="#005aa0">{safe}</link>'


def _truncate(text: str, limit: int = MAX_SNIPPET) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _swedish_date(dt: datetime) -> str:
    return f"{dt.day} {MONTHS[dt.month - 1]} {dt.year}"


def _hostname(url: str) -> str:
    return urlparse(url).netloc.replace("www.", "") or url


def report_filename(data: dict) -> str:
    host = _hostname(data.get("vendor_url", "")).replace(":", "-") or "leverantor"
    date = datetime.now(ZoneInfo("Europe/Stockholm")).strftime("%Y-%m-%d")
    return f"sakerhetsbedomning-{host}-{date}.pdf"


def _draw_page(canvas, doc, *, first: bool, vendor: str, level_text: str, date_text: str):
    canvas.saveState()
    if first:
        canvas.setFillColor(BLUE)
        canvas.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, stroke=0, fill=1)
        canvas.setFillColor(RED)
        canvas.rect(0, PAGE_H - HEADER_H - 1.5 * mm, PAGE_W, 1.5 * mm, stroke=0, fill=1)

        canvas.setFillColor(BLUE_LIGHT)
        canvas.setFont("Noto-Bold", 7.5)
        canvas.drawString(MARGIN, PAGE_H - 14 * mm, "RAPPORT  ·  NIS2  ·  DORA  ·  K1–K4")
        canvas.setFillColor(colors.white)
        canvas.setFont("Noto-Bold", 21)
        canvas.drawString(MARGIN, PAGE_H - 25 * mm, "Leverantörssäkerhetsbedömning")
        canvas.setFont("Noto", 11)
        canvas.drawString(MARGIN, PAGE_H - 33 * mm, vendor)
        canvas.setFillColor(BLUE_LIGHT)
        canvas.setFont("Noto", 9)
        canvas.drawString(MARGIN, PAGE_H - 39.5 * mm, f"{level_text}  ·  {date_text}")
    else:
        canvas.setFillColor(BLUE)
        canvas.setFont("Noto-Bold", 8)
        canvas.drawString(MARGIN, PAGE_H - 11 * mm, "Leverantörssäkerhetsbedömning")
        canvas.setFillColor(MUTED)
        canvas.setFont("Noto", 8)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 11 * mm, vendor)
        canvas.setStrokeColor(RED)
        canvas.setLineWidth(1.2)
        canvas.line(MARGIN, PAGE_H - 13.5 * mm, PAGE_W - MARGIN, PAGE_H - 13.5 * mm)

    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Noto", 7.5)
    canvas.drawString(MARGIN, 9.5 * mm,
                      "Automatiserad bedömning baserad på NIS2 (EU 2022/2555) och DORA (EU 2022/2554)")
    canvas.drawRightString(PAGE_W - MARGIN, 9.5 * mm, f"Sida {doc.page}")
    canvas.restoreState()


def _score_block(data: dict) -> list:
    score = float(data.get("score_percent", 0) or 0)
    tone = GREEN if score >= 70 else AMBER if score >= 40 else RED
    score_text = f"{score:.1f}".replace(".", ",")

    score_cell = [
        _p(f'<font color="{_hex(tone)}">{score_text} %</font>', S_SCORE),
        Spacer(1, 4),
        _p(_esc(data.get("summary", "")), S_CENTER),
    ]

    def stat(value, label, color):
        return [_p(f'<font color="{_hex(color)}">{int(value or 0)}</font>', S_STAT),
                _p(label, S_STAT_LABEL)]

    stats = Table(
        [[stat(data.get("requirements_met"), "UPPFYLLDA", GREEN),
          stat(data.get("requirements_partial"), "DELVIS", AMBER),
          stat(data.get("requirements_not_met"), "EJ UPPFYLLDA", RED)]],
        colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3,
    )
    stats.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    box = Table([[score_cell]], colWidths=[PAGE_W - 2 * MARGIN])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PAPER),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("LEFTPADDING", (0, 0), (-1, -1), 24),
        ("RIGHTPADDING", (0, 0), (-1, -1), 24),
    ]))
    return [box, Spacer(1, 8), stats]


def _meta_table(data: dict, level_text: str, date_text: str) -> Table:
    rows = [
        ("Leverantör", _link(data.get("vendor_url", ""))),
        ("Informationsklass", _esc(level_text)),
        ("Datum för rapport", _esc(date_text)),
        ("Analyserade sidor", str(len(data.get("pages_scanned") or []))),
        ("Granskade tredjepartskällor", str(int(data.get("review_sources_scanned") or 0))),
    ]
    table = Table([[_p(k.upper(), S_LABEL), _p(v)] for k, v in rows],
                  colWidths=[52 * mm, PAGE_W - 2 * MARGIN - 52 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def _status_badge(status: str) -> Paragraph:
    label, color = STATUS.get(status, ("Okänt", MUTED))
    return _p(f'<font name="Noto-Bold" color="{_hex(color)}">• {label}</font>',
              _style("badge", fontSize=8.5, leading=12))


def _overview_table(findings: list[dict]) -> Table:
    header = [_p("KRAVOMRÅDE", S_LABEL), _p("REGELVERK", S_LABEL), _p("STATUS", S_LABEL)]
    rows = [header] + [
        [_p(_esc(f.get("area"))), _p(_esc(f.get("regulatory_ref")), S_SMALL),
         _status_badge(f.get("status", ""))]
        for f in findings
    ]
    width = PAGE_W - 2 * MARGIN
    table = Table(rows, colWidths=[width * 0.46, width * 0.30, width * 0.24], repeatRows=1)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, 0), 1, BLUE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(2, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), PAPER))
    table.setStyle(TableStyle(style))
    return table


def _finding_block(f: dict) -> KeepTogether:
    parts = [
        Table([[_p(_esc(f.get("area")), S_H3), _status_badge(f.get("status", ""))]],
              colWidths=[(PAGE_W - 2 * MARGIN) * 0.72, (PAGE_W - 2 * MARGIN) * 0.28],
              style=TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE")])),
        _p(_esc(f.get("regulatory_ref")), S_SMALL),
        Spacer(1, 3),
        _p(_esc(f.get("description"))),
    ]

    evidence = (f.get("evidence") or [])[:2]
    if evidence:
        parts += [Spacer(1, 6), _p("UNDERLAG FRÅN LEVERANTÖRENS WEBBPLATS", S_LABEL)]
        parts += [_p(_esc(_truncate(e)), S_SNIPPET) for e in evidence]

    reviews = (f.get("review_evidence") or [])[:2]
    if reviews:
        parts += [Spacer(1, 6), _p("UNDERLAG FRÅN TREDJEPARTSKÄLLOR", S_LABEL)]
        for rv in reviews:
            parts.append(_p(f'<font name="Noto-Bold">{_esc(rv.get("source"))}</font> – '
                            f'{_esc(_truncate(rv.get("snippet"), 240))}', S_SNIPPET))

    terms = list(f.get("matched_keywords") or []) + list(f.get("matched_certifications") or [])
    if terms:
        parts += [Spacer(1, 4),
                  _p(f'<font name="Noto-Bold">Träffade sökord:</font> {_esc(", ".join(terms))}', S_SMALL)]

    sources = (f.get("source_urls") or [])[:3]
    if sources:
        parts.append(_p("<font name=\"Noto-Bold\">Källor:</font> " +
                        "<br/>".join(_link(u) for u in sources), S_SMALL))

    if not (evidence or reviews or terms):
        parts += [Spacer(1, 4), _p("Inget underlag hittades för detta krav.", S_SMALL)]

    _, color = STATUS.get(f.get("status", ""), ("", MUTED))
    wrapper = Table([[parts]], colWidths=[PAGE_W - 2 * MARGIN])
    wrapper.setStyle(TableStyle([
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return KeepTogether([wrapper, Spacer(1, 10)])


def build_report(data: dict) -> bytes:
    now = datetime.now(ZoneInfo("Europe/Stockholm"))
    date_text = _swedish_date(now)
    level = data.get("classification_level", "")
    level_name = CLASSIFICATION_LEVELS.get(level, {}).get("name", "")
    level_text = f"{level} – {level_name}" if level_name else level
    vendor = _hostname(data.get("vendor_url", ""))
    findings = data.get("findings") or []

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=22 * mm, bottomMargin=20 * mm,
        title=f"Leverantörssäkerhetsbedömning – {vendor}",
        author="Leverantörssäkerhetsbedömning",
        subject=f"Bedömning enligt informationsklass {level}",
        lang="sv-SE",
    )

    story: list = [Spacer(1, HEADER_H - 22 * mm + 6 * mm)]
    story += [_p("Sammanfattning", S_H2)]
    story += _score_block(data)
    story += [Spacer(1, 12), _meta_table(data, level_text, date_text)]

    story += [_p("Översikt per krav", S_H2), _overview_table(findings)]

    story += [_p("Detaljerad analys", S_H2)]
    order = {"not_found": 0, "partial": 1, "found": 2}
    for f in sorted(findings, key=lambda f: order.get(f.get("status"), 3)):
        story.append(_finding_block(f))

    pages = data.get("pages_scanned") or []
    if pages:
        story += [_p("Analyserade sidor", S_H2)]
        story += [_p(_link(u), S_SMALL) for u in pages]

    story += [
        _p("Om bedömningen", S_H2),
        _p("Rapporten är framtagen automatiskt genom att leverantörens webbplats och offentliga "
           "tredjepartskällor har sökts igenom efter tecken på att kraven för vald informationsklass "
           "uppfylls. Resultatet är vägledande och ersätter inte en formell granskning, till exempel "
           "genom att begära certifikat, revisionsrapporter och avtal direkt från leverantören. "
           "Citat från webbplatser återges på originalspråk.", S_BODY),
    ]

    def first(canvas, d):
        _draw_page(canvas, d, first=True, vendor=vendor, level_text=level_text, date_text=date_text)

    def later(canvas, d):
        _draw_page(canvas, d, first=False, vendor=vendor, level_text=level_text, date_text=date_text)

    doc.build(story, onFirstPage=first, onLaterPages=later)
    return buf.getvalue()
