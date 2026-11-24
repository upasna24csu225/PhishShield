


from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)


def safe_text(value):
    if value is None:
        return "Not available"
    return escape(str(value))


def generate_pdf_report(data, risk, header_result, correlation=None):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#17365D"),
        fontSize=20,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = styles["BodyText"]

    story = []

    story.append(Paragraph("PhishShield X", title_style))
    story.append(Paragraph(
        "Email Threat Investigation Report",
        styles["Heading2"]
    ))
    story.append(Spacer(1, 15))

    story.append(Paragraph("1. Email Information", heading_style))

    email_info = [
        ["Field", "Details"],
        ["Sender", safe_text(data.get("sender"))],
        ["Subject", safe_text(data.get("subject"))],
        ["URLs Found", safe_text(len(data.get("urls", [])))],
        ["Attachments Found", safe_text(len(data.get("attachments", [])))]
    ]

    table = Table(email_info, colWidths=[150, 330])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(table)

    story.append(Paragraph("2. Threat Risk Assessment", heading_style))

    story.append(Paragraph(
        f"Risk Level: <b>{safe_text(risk.get('risk_level'))}</b>",
        body_style
    ))

    story.append(Paragraph(
        f"Risk Score: <b>{safe_text(risk.get('risk_score'))}</b>",
        body_style
    ))

    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Evidence:", styles["Heading3"]))

    for item in risk.get("evidence", []):
        story.append(Paragraph(
            "• " + safe_text(item),
            body_style
        ))

    story.append(Paragraph(
        "3. Threat Intelligence Correlation",
        heading_style
    ))

    if correlation:

        story.append(Paragraph(
            f"Correlation Score: {safe_text(correlation.get('correlation_score'))}",
            body_style
        ))

        story.append(Paragraph(
            f"Overall Status: {safe_text(correlation.get('overall_status'))}",
            body_style
        ))

        for finding in correlation.get("findings", []):

            story.append(Paragraph(
                f"<b>{safe_text(finding.get('category'))}</b>: "
                f"{safe_text(finding.get('finding'))} "
                f"(Severity: {safe_text(finding.get('severity'))})",
                body_style
            ))

    story.append(Paragraph(
        "4. Email Authentication Analysis",
        heading_style
    ))

    authentication = data.get("authentication", {})

    for mechanism in ["SPF", "DKIM", "DMARC"]:

        story.append(Paragraph(
            f"{mechanism}: {safe_text(authentication.get(mechanism))}",
            body_style
        ))

    story.append(Paragraph(
        "5. Header Spoofing Analysis",
        heading_style
    ))

    story.append(Paragraph(
        f"Possible Spoofing Indicator: "
        f"{safe_text(header_result.get('spoofing_indicator'))}",
        body_style
    ))

    story.append(Paragraph(
        f"Sender Domain: {safe_text(header_result.get('sender_domain'))}",
        body_style
    ))

    story.append(Paragraph(
        f"Reply-To Domain: {safe_text(header_result.get('reply_domain'))}",
        body_style
    ))

    story.append(Paragraph("6. URL Intelligence", heading_style))

    urls = data.get("urls", [])

    if urls:
        for url in urls:
            story.append(Paragraph(
                safe_text(url),
                body_style
            ))
    else:
        story.append(Paragraph("No URLs found.", body_style))

    story.append(Paragraph("7. Attachment Analysis", heading_style))

    attachments = data.get("attachments", [])

    if attachments:

        for attachment in attachments:

            story.append(Paragraph(
                f"Filename: {safe_text(attachment.get('filename'))}",
                body_style
            ))

            story.append(Paragraph(
                f"File Type: {safe_text(attachment.get('file_type'))}",
                body_style
            ))

            story.append(Paragraph(
                f"Size: {safe_text(attachment.get('size'))}",
                body_style
            ))

            story.append(Spacer(1, 5))

    else:
        story.append(Paragraph("No attachments found.", body_style))

    story.append(Paragraph("8. Disclaimer", heading_style))

    story.append(Paragraph(
        "This report contains automated heuristic indicators and "
        "machine learning classifications. These findings do not "
        "prove malicious activity. Authentication results are "
        "extracted from available email headers and are not "
        "independently verified. Attachments are not malware-scanned.",
        body_style
    ))

    document.build(story)

    return buffer.getvalue()
