"""
Unit Tests for Rule-Based Anomaly Detection Heuristics
Verifies detection of port scans, SYN floods, traffic spikes, and non-alarmist phrasing.
"""

import time
import pytest
from analyzer.anomaly_detector import AnomalyDetector


def test_port_scan_detection():
    """Verify that probing multiple ports within window triggers a Port Scan alert."""
    detector = AnomalyDetector(time_window=2.0, port_scan_threshold=5)
    now = time.time()
    scanner_ip = "192.168.1.88"
    target_ip = "192.168.1.10"

    alerts = []
    # Probe 7 distinct ports
    for p in [21, 22, 23, 80, 443, 8080, 65432]:
        pkt = {
            "timestamp": now,
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": p,
            "packet_size": 60,
            "tcp_flags": "SYN"
        }
        new_alerts = detector.evaluate_packet(pkt)
        alerts.extend(new_alerts)

    assert len(alerts) >= 1
    scan_alert = alerts[0]
    assert scan_alert["category"] == "Port Scan Indicator"
    assert scan_alert["severity"] == "High"
    assert "Potentially suspicious network activity detected" in scan_alert["explanation"]


def test_syn_burst_detection():
    """Verify that excessive SYN packets trigger SYN flood indicator alert."""
    detector = AnomalyDetector(time_window=2.0, syn_burst_threshold=10)
    now = time.time()
    attacker = "192.168.1.99"

    alerts = []
    for _ in range(12):
        pkt = {
            "timestamp": now,
            "src_ip": attacker,
            "dst_ip": "192.168.1.20",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
            "packet_size": 64,
            "tcp_flags": "SYN"
        }
        alerts.extend(detector.evaluate_packet(pkt))

    assert len(alerts) >= 1
    syn_alert = alerts[0]
    assert syn_alert["category"] == "SYN Flood Indicator"
    assert "Potentially suspicious network activity detected" in syn_alert["explanation"]


def test_high_packet_rate_detection():
    """Verify packet rate threshold alert."""
    detector = AnomalyDetector(time_window=1.0, pps_threshold=20)
    now = time.time()

    alerts = []
    for _ in range(25):
        pkt = {
            "timestamp": now,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "packet_size": 100
        }
        alerts.extend(detector.evaluate_packet(pkt))

    assert len(alerts) >= 1
    rate_alert = next((a for a in alerts if a["category"] == "High Packet Rate"), None)
    assert rate_alert is not None
