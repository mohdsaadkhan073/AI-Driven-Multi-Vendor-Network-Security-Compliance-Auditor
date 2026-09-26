import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from models import AuditResult

def generate_pdf_report(audit_result: AuditResult) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A')
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#2563EB')
    )
    
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )
    
    elements = []
    
    # 1. Header Banner
    elements.append(Paragraph("EliteCore Autonomous Network Security Compliance Auditor", title_style))
    elements.append(Paragraph("EXECUTIVE SECURITY COMPLIANCE & REMEDIATION AUDIT REPORT • SIH 2026-27", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Classification: Internal Restricted", body_style))
    elements.append(Spacer(1, 14))
    
    # 2. Device Metadata Table
    dev = audit_result.device_info
    dev_data = [
        [
            Paragraph("<b>Target Hostname:</b> " + dev.get("hostname", "N/A"), body_style),
            Paragraph("<b>Hardware Vendor:</b> " + dev.get("vendor", "N/A"), body_style),
        ],
        [
            Paragraph("<b>Hardware Model:</b> " + dev.get("model", "N/A"), body_style),
            Paragraph("<b>Firmware/OS:</b> " + dev.get("os_version", "N/A"), body_style),
        ],
        [
            Paragraph("<b>Device Serial:</b> " + dev.get("serial_number", "N/A"), body_style),
            Paragraph(f"<b>Overall Compliance:</b> <font color='#2563EB'><b>{audit_result.overall_compliance_score}%</b></font>", body_style),
        ]
    ]
    t_dev = Table(dev_data, colWidths=[270, 270])
    t_dev.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t_dev)
    elements.append(Spacer(1, 14))
    
    # 3. Framework Breakdown Table
    elements.append(Paragraph("1. Framework Compliance Scores Breakdown", h2_style))
    fw_table_data = [["Compliance Framework", "Score", "Passed", "Failed", "Critical Gaps", "High Gaps"]]
    for fw in audit_result.framework_scores:
        fw_table_data.append([
            fw.framework,
            f"{fw.score_percentage}%",
            str(fw.passed_controls),
            str(fw.failed_controls),
            str(fw.critical_findings),
            str(fw.high_findings)
        ])
    t_fw = Table(fw_table_data, colWidths=[180, 60, 60, 60, 90, 90])
    t_fw.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(t_fw)
    elements.append(Spacer(1, 14))
    
    # 4. Detailed Findings & Remediation Section
    elements.append(Paragraph("2. Actionable Findings & Device-Specific Remediation Paths", h2_style))
    elements.append(Paragraph("The following security findings were identified. Each item provides the exact configuration evidence, risk rationale, and immediate copy-paste CLI remediation commands.", body_style))
    elements.append(Spacer(1, 10))
    
    for idx, f in enumerate(audit_result.findings):
        # Color coding for severity
        sev_color = "#DC2626" if f.severity == "CRITICAL" else \
                    "#EA580C" if f.severity == "HIGH" else \
                    "#CA8A04" if f.severity == "MEDIUM" else "#2563EB"
                    
        status_color = "#16A34A" if f.status == "PASS" else "#DC2626"
        
        card_content = [
            [
                Paragraph(f"<b>[{f.control_id}] {f.title}</b>", ParagraphStyle('FTitle', parent=body_style, fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0F172A'))),
                Paragraph(f"<font color='{sev_color}'><b>{f.severity}</b></font> | <font color='{status_color}'><b>{f.status}</b></font>", ParagraphStyle('FStatus', parent=body_style, alignment=2))
            ],
            [
                Paragraph(f"<b>Framework:</b> {f.framework} | <b>Config Evidence:</b> Line {f.evidence_line or 'N/A'} (<code>{f.evidence_text or 'Missing'}</code>)", body_style),
                ""
            ],
            [
                Paragraph(f"<b>Why It Matters:</b> {f.why_it_matters}", body_style),
                ""
            ]
        ]
        
        if f.status != "PASS":
            card_content.append([
                Paragraph(f"<b>Device-Specific CLI Remediation Command:</b><br/><font color='#047857'><code>{f.remediation_cmd.replace(chr(10), '<br/>')}</code></font>", code_style),
                ""
            ])
            card_content.append([
                Paragraph(f"<b>Action:</b> {f.remediation_explanation}", body_style),
                ""
            ])
            
        t_card = Table(card_content, colWidths=[400, 140])
        t_card.setStyle(TableStyle([
            ('SPAN', (0,1), (1,1)),
            ('SPAN', (0,2), (1,2)),
            ('SPAN', (0,3), (1,3)) if len(card_content) > 3 else ('SPAN', (0,0), (0,0)),
            ('SPAN', (0,4), (1,4)) if len(card_content) > 4 else ('SPAN', (0,0), (0,0)),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FFFFFF' if f.status == 'PASS' else '#FFFBEB')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1' if f.status == 'PASS' else '#FCD34D')),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        
        elements.append(KeepTogether([t_card, Spacer(1, 8)]))
        
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
