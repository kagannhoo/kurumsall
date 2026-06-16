import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas.api import DashboardSummary


def export_dashboard_csv(dashboard: DashboardSummary) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["KurSal — Yönetici Raporu"])
    writer.writerow(["Organizasyon", dashboard.organization_name])
    writer.writerow(["Tarih", datetime.now(timezone.utc).isoformat()])
    writer.writerow(["Risk Skoru", dashboard.risk_score])
    writer.writerow(["Toplam Asset", dashboard.total_assets])
    writer.writerow(["Risk Delta %", dashboard.risk_delta_percent or ""])
    writer.writerow([])
    writer.writerow(["Özet", dashboard.executive_summary or ""])
    writer.writerow([])
    writer.writerow(["Envanter", "Tip", "Adet", "Açıklama"])
    for item in dashboard.asset_inventory:
        writer.writerow(["", item.label, item.count, item.description])
    writer.writerow([])
    writer.writerow(["Değişiklikler", "Tip", "Asset", "Özet", "Risk"])
    for change in dashboard.recent_changes:
        writer.writerow([
            "",
            change.change_type.value,
            change.asset_type.value,
            change.summary,
            change.risk_level.value,
        ])
    if dashboard.ai_insight:
        writer.writerow([])
        writer.writerow(["AI Özet", dashboard.ai_insight.summary])
        writer.writerow(["AI Yorum", dashboard.ai_insight.risk_commentary])
        writer.writerow([])
        writer.writerow(["Saldırı Senaryoları"])
        for scenario in dashboard.ai_insight.attack_scenarios:
            writer.writerow(["", scenario.get("title", ""), scenario.get("severity", "")])
        writer.writerow([])
        writer.writerow(["Aksiyon Planı", "Öncelik", "Başlık", "Sorumlu", "Süre"])
        for action in dashboard.ai_insight.action_items:
            writer.writerow([
                "",
                action.get("priority", ""),
                action.get("title", ""),
                action.get("owner", ""),
                action.get("timeframe", ""),
            ])
    return buf.getvalue()


def export_dashboard_pdf(dashboard: DashboardSummary) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm, topMargin=2 * cm)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("KurSal — Yönetici Raporu", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Organizasyon:</b> {dashboard.organization_name}", styles["Normal"]))
    story.append(Paragraph(f"<b>Risk skoru:</b> {dashboard.risk_score}/10", styles["Normal"]))
    story.append(Paragraph(f"<b>Toplam asset:</b> {dashboard.total_assets}", styles["Normal"]))
    if dashboard.executive_summary:
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"<b>Özet:</b> {dashboard.executive_summary}", styles["Normal"]))

    if dashboard.recent_changes:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Son Değişiklikler", styles["Heading2"]))
        rows = [["Tip", "Asset", "Özet", "Risk"]]
        for c in dashboard.recent_changes[:15]:
            rows.append([c.change_type.value, c.asset_type.value, c.summary[:60], c.risk_level.value])
        table = Table(rows, colWidths=[2.5 * cm, 2.5 * cm, 9 * cm, 2 * cm])
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(table)

    if dashboard.ai_insight and dashboard.ai_insight.action_items:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Önerilen Aksiyonlar", styles["Heading2"]))
        rows = [["Öncelik", "Başlık", "Sorumlu"]]
        for a in dashboard.ai_insight.action_items[:10]:
            rows.append([a.get("priority", ""), a.get("title", "")[:50], a.get("owner", "")])
        table = Table(rows, colWidths=[2.5 * cm, 10 * cm, 3.5 * cm])
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(table)

    doc.build(story)
    return buf.getvalue()
