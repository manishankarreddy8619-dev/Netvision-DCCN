"""
Unit Tests for Packet Parsing, Protocol Classification, and Statistics
"""

import time
import pytest
from analyzer.packet_parser import parse_packet, parse_tcp_flags, determine_direction
from analyzer.traffic_statistics import TrafficStatistics
from analyzer.protocol_analyzer import ProtocolAnalyzer


def test_parse_tcp_flags():
    """Test TCP flag decoding."""
    assert parse_tcp_flags("S") == "SYN"
    assert "SYN" in parse_tcp_flags("SA") and "ACK" in parse_tcp_flags("SA")
    assert parse_tcp_flags("F") == "FIN"
    assert parse_tcp_flags("R") == "RST"
    assert parse_tcp_flags(None) == "None"


def test_determine_direction():
    """Test direction classification relative to local IP."""
    local_ip = "192.168.1.10"
    assert determine_direction(local_ip, local_ip, local_ip) == "Loopback"
    assert determine_direction(local_ip, "192.168.1.25", local_ip) == "Outbound"
    assert determine_direction("192.168.1.25", local_ip, local_ip) == "Inbound"
    assert determine_direction("10.0.0.1", "10.0.0.2", local_ip) == "Transit / External"


def test_packet_parser_and_statistics():
    """Test packet parsing into unified records and aggregation in TrafficStatistics."""
    stats = TrafficStatistics()

    pkt_record = {
        "timestamp": time.time(),
        "time_formatted": "12:00:00.123",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.25",
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 65432,
        "packet_size": 1400,
        "tcp_flags": "PSH-ACK",
        "summary": "TCP data payload"
    }

    parsed = parse_packet(pkt_record, packet_id=1, local_ip="192.168.1.10")
    assert parsed["packet_id"] == 1
    assert parsed["protocol"] == "TCP"
    assert parsed["direction"] == "Outbound"

    stats.update(parsed)
    summary = stats.get_summary()

    assert summary["total_packets"] == 1
    assert summary["total_bytes"] == 1400
    assert summary["tcp_count"] == 1
    assert summary["avg_packet_size"] == 1400.0


def test_protocol_analyzer_handshake_tracking():
    """Test TCP 3-way handshake detection."""
    proto_eng = ProtocolAnalyzer()
    client_ip, srv_ip = "192.168.1.10", "192.168.1.25"
    c_port, s_port = 55100, 65432
    base_t = time.time()

    # 1. Client SYN
    syn_pkt = {
        "timestamp": base_t,
        "protocol": "TCP",
        "src_ip": client_ip, "dst_ip": srv_ip,
        "src_port": c_port, "dst_port": s_port,
        "tcp_flags": "SYN", "packet_size": 60
    }
    proto_eng.process_packet(syn_pkt)

    # 2. Server SYN-ACK
    syn_ack_pkt = {
        "timestamp": base_t + 0.015,
        "protocol": "TCP",
        "src_ip": srv_ip, "dst_ip": client_ip,
        "src_port": s_port, "dst_port": c_port,
        "tcp_flags": "SYN-ACK", "packet_size": 60
    }
    proto_eng.process_packet(syn_ack_pkt)

    # 3. Client ACK (Establishes connection)
    ack_pkt = {
        "timestamp": base_t + 0.020,
        "protocol": "TCP",
        "src_ip": client_ip, "dst_ip": srv_ip,
        "src_port": c_port, "dst_port": s_port,
        "tcp_flags": "ACK", "packet_size": 54
    }
    event = proto_eng.process_packet(ack_pkt)

    assert event is not None
    assert event["type"] == "tcp_handshake_completed"
    assert event["latency_ms"] == pytest.approx(20.0, rel=0.1)
    assert len(proto_eng.completed_handshakes) == 1
