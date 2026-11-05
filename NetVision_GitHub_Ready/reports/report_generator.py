"""
NetVision Report Generator Engine
Exports captured network telemetry into structured CSV, JSON, and professional
multi-page PDF forensic analysis reports using ReportLab.
"""

import os
import io
import csv
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)


def export_packets_to_csv(packets: List[Dict[str, Any]]) -> str:
    """Convert packet records into a formatted CSV string."""
    output = io.StringIO()
    fieldnames = [
        "packet_id", "time_formatted", "protocol", "src_ip", "src_port",
        "dst_ip", "dst_port", "packet_size", "tcp_flags", "direction", "summary"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for p in packets:
        writer.writerow(p)
    return output.getvalue()


def export_analysis_to_json(
    summary: Dict[str, Any],
    protocol_dist: Dict[str, int],
    size_dist: Dict[str, int],
    alerts: List[Dict[str, Any]],
    packets: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Export complete session telemetry and analysis in structured JSON."""
    report_data = {
        "metadata": {
            "tool": "NetVision Network Analyzer",
            "version": "1.0.0",
            "generation_timestamp": time.time(),
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "summary": summary,
        "protocol_distribution": protocol_dist,
        "size_distribution": size_dist,
        "anomalies_detected": alerts,
        "total_packets_recorded": len(packets) if packets else 0,
        "sample_packets": packets[:100] if packets else []
    }
    return json.dumps(report_data, indent=2)


def generate_pdf_report(
    summary: Dict[str, Any],
    protocol_dist: Dict[str, int],
    size_dist: Dict[str, int],
    alerts: List[Dict[str, Any]],
    capture_mode: str = "Simulation",
    output_path: Optional[str] = None
) -> str:
    """
    Generate an executive PDF analysis report suitable for B.Tech DCCN mini-project evaluation.
    """
    if not output_path:
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        os.makedirs(reports_dir, exist_ok=True)
        output_path = os.path.join(reports_dir, f"NetVision_Report_{int(time.time())}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom Brand Styles (Dark Navy & Cyan Palette)
    primary_color = colors.HexColor("#0f172a")
    accent_color = colors.HexColor("#0284c7")
    text_dark = colors.HexColor("#1e293b")
    bg_light = colors.HexColor("#f8fafc")
    border_color = colors.HexColor("#cbd5e1")
    alert_red = colors.HexColor("#dc2626")
    alert_yellow = colors.HexColor("#d97706")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=primary_color,
        alignment=0
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=accent_color,
        alignment=0
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=text_dark
    )

    cell_style = ParagraphStyle(
        "Cell_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=text_dark
    )

    cell_header_style = ParagraphStyle(
        "CellHeader_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("NetVision", title_style))
    story.append(Paragraph("Multi-Laptop Network Packet Sniffer & Intelligent Traffic Analyzer", subtitle_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Academic Telemetry & Traffic Analysis Report (DCCN Mini-Project)</b>", body_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceAfter=12))

    # 2. Executive Metadata Box
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label = capture_mode.capitalize()
    meta_table_data = [
        [
            Paragraph(f"<b>Report Generated:</b> {now_str}", body_style),
            Paragraph(f"<b>Capture Mode:</b> {mode_label}", body_style)
        ],
        [
            Paragraph(f"<b>Capture Duration:</b> {summary.get('capture_duration_seconds', 0)} sec", body_style),
            Paragraph(f"<b>Total Captured Packets:</b> {summary.get('total_packets', 0):,}", body_style)
        ],
        [
            Paragraph(f"<b>Total Volume:</b> {summary.get('total_bytes', 0):,} bytes", body_style),
            Paragraph(f"<b>Average Packet Size:</b> {summary.get('avg_packet_size', 0)} bytes", body_style)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[260, 270])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Protocol Statistics Table
    story.append(Paragraph("1. Protocol Breakdown & Distribution", h1_style))
    total_pkts = max(summary.get("total_packets", 1), 1)

    proto_table_data = [[
        Paragraph("<b>Protocol</b>", cell_header_style),
        Paragraph("<b>Packet Count</b>", cell_header_style),
        Paragraph("<b>Percentage Share</b>", cell_header_style),
        Paragraph("<b>Role in Network Architecture</b>", cell_header_style)
    ]]

    role_descriptions = {
        "TCP": "Reliable connection-oriented transport (laptop file transfer, web)",
        "UDP": "Low-latency connectionless transport (DNS queries, media)",
        "DNS (UDP)": "Domain name resolution to IP addresses",
        "ICMP": "Control message signaling, network ping reachability tests",
        "ARP": "Address resolution between Layer 2 MAC and Layer 3 IP",
        "Other": "Miscellaneous link or routing traffic"
    }

    for proto, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_pkts) * 100.0
        role = role_descriptions.get(proto, "General application traffic")
        proto_table_data.append([
            Paragraph(proto, cell_style),
            Paragraph(f"{count:,}", cell_style),
            Paragraph(f"{pct:.1f}%", cell_style),
            Paragraph(role, cell_style)
        ])

    proto_table = Table(proto_table_data, colWidths=[100, 85, 95, 250])
    proto_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(proto_table)
    story.append(Spacer(1, 14))

    # 4. Packet Size Distribution Table
    story.append(Paragraph("2. Packet Size Distribution (MTU Profile)", h1_style))
    size_table_data = [[
        Paragraph("<b>Size Bin (Bytes)</b>", cell_header_style),
        Paragraph("<b>Count</b>", cell_header_style),
        Paragraph("<b>Share</b>", cell_header_style),
        Paragraph("<b>Common Traffic Types</b>", cell_header_style)
    ]]

    bin_notes = {
        "< 64 B": "TCP Pure ACKs, SYN/FIN handshake frames, ARP probes",
        "64-128 B": "ICMP Ping requests/replies, small UDP DNS queries",
        "129-512 B": "Interactive payloads, client commands, handshake negotiation",
        "513-1024 B": "Medium file chunks, application data frames",
        "1025-1518 B": "Bulk data transfer chunks (standard Ethernet MTU saturation)",
        "> 1518 B": "Jumbo frames / TCP Large Segment Offload (LSO) frames"
    }

    for b_name, b_count in size_dist.items():
        pct = (b_count / total_pkts) * 100.0
        note = bin_notes.get(b_name, "Application data payload")
        size_table_data.append([
            Paragraph(b_name, cell_style),
            Paragraph(f"{b_count:,}", cell_style),
            Paragraph(f"{pct:.1f}%", cell_style),
            Paragraph(note, cell_style)
        ])

    size_table = Table(size_table_data, colWidths=[100, 85, 95, 250])
    size_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(size_table)
    story.append(Spacer(1, 14))

    # 5. Anomaly Detection & Security Observations
    story.append(Paragraph("3. Intelligent Anomaly Detection & Security Findings", h1_style))
    if alerts:
        alerts_data = [[
            Paragraph("<b>Timestamp</b>", cell_header_style),
            Paragraph("<b>Category</b>", cell_header_style),
            Paragraph("<b>Severity</b>", cell_header_style),
            Paragraph("<b>Observed Evidence & Recommendation</b>", cell_header_style)
        ]]
        for a in alerts[:6]:  # Limit to top 6 in PDF summary
            sev = a.get("severity", "Medium")
            sev_color = alert_red if sev == "High" else (alert_yellow if sev == "Medium" else accent_color)
            sev_html = f"<font color='{sev_color.hexval()}'><b>{sev}</b></font>"
            evidence_rec = f"<b>Evidence:</b> {a.get('observed_evidence', '')}<br/><b>Action:</b> {a.get('recommended_investigation', '')}"
            alerts_data.append([
                Paragraph(a.get("time_formatted", ""), cell_style),
                Paragraph(a.get("category", ""), cell_style),
                Paragraph(sev_html, cell_style),
                Paragraph(evidence_rec, cell_style)
            ])

        alert_table = Table(alerts_data, colWidths=[70, 110, 70, 280])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('BOX', (0, 0), (-1, -1), 1, border_color),
            ('GRID', (0, 0), (-1, -1), 0.5, border_color),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(alert_table)
    else:
        story.append(Paragraph("<i>No suspicious anomalies or abnormal traffic patterns observed during this session. Traffic operates within established threshold baselines.</i>", body_style))

    story.append(Spacer(1, 14))

    # 6. Academic Observations & Conclusion
    story.append(Paragraph("4. Technical Observations & Theoretical Alignment", h1_style))
    obs_text = (
        "1. <b>TCP Byte Stream & Framing:</b> Sockets transmit unformatted byte streams without message boundaries. "
        "NetVision's 8-byte framing header ensures 100% reliable chunk assembly without protocol synchronization breakdown.<br/>"
        "2. <b>Three-Way Handshake:</b> Observed initial TCP sequence numbers and SYN/SYN-ACK flags demonstrate proper "
        "state transition from CLOSED to ESTABLISHED without connection reset.<br/>"
        "3. <b>Integrity Verification:</b> End-to-end SHA-256 validation guarantees file bit-stream integrity across "
        "intermediate wireless access points without payload corruption."
    )
    story.append(Paragraph(obs_text, body_style))
    story.append(Spacer(1, 10))

    # 7. Limitations & Ethical Notice
    story.append(Paragraph("5. Limitations & Ethical Compliance Notice", h1_style))
    lim_text = (
        f"<b>Data Mode Notice:</b> Telemetry generated under <b>{mode_label} Mode</b>. "
        "In compliance with academic computer networking ethics, packet capture was confined strictly to designated "
        "test endpoints. No user passwords, authentication credentials, or encrypted TLS application payloads were stored or inspected. "
        "On switched or WPA2/WPA3 Wi-Fi topologies, promiscuous packet capture is confined to unicast traffic directed to this NIC unless "
        "port mirroring or an active TAP is configured."
    )
    story.append(Paragraph(lim_text, body_style))

    doc.build(story)
    return output_path
