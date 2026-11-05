"""
Unit Tests for Telemetry Exporting and PDF Report Compilation
"""

import os
import json
import tempfile
import pytest
from reports.report_generator import export_packets_to_csv, export_analysis_to_json, generate_pdf_report


def test_csv_export():
    packets = [{
        "packet_id": 1,
        "time_formatted": "12:00:00.000",
        "protocol": "TCP",
        "src_ip": "192.168.1.10",
        "src_port": 50000,
        "dst_ip": "192.168.1.25",
        "dst_port": 65432,
        "packet_size": 1024,
        "tcp_flags": "ACK",
        "direction": "Outbound",
        "summary": "Sample ACK"
    }]
    csv_str = export_packets_to_csv(packets)
    assert "packet_id,time_formatted" in csv_str
    assert "192.168.1.10" in csv_str
    assert "65432" in csv_str


def test_json_export():
    summary = {"total_packets": 50, "total_bytes": 10000}
    proto_dist = {"TCP": 40, "UDP": 10}
    size_dist = {"< 64 B": 20, "64-128 B": 30}
    alerts = [{"category": "High Rate", "severity": "Low"}]

    json_str = export_analysis_to_json(summary, proto_dist, size_dist, alerts)
    parsed = json.loads(json_str)

    assert parsed["metadata"]["tool"] == "NetVision Network Analyzer"
    assert parsed["summary"]["total_packets"] == 50
    assert parsed["protocol_distribution"]["TCP"] == 40


def test_pdf_report_compilation():
    summary = {
        "total_packets": 100,
        "total_bytes": 45000,
        "avg_packet_size": 450.0,
        "capture_duration_seconds": 10.0
    }
    proto_dist = {"TCP": 80, "UDP": 20}
    size_dist = {"< 64 B": 30, "64-128 B": 70}
    alerts = []

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
        pdf_path = f.name

    try:
        out = generate_pdf_report(summary, proto_dist, size_dist, alerts, "Simulation", pdf_path)
        assert os.path.exists(out)
        assert os.path.getsize(out) > 1000  # Generated valid PDF document
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
