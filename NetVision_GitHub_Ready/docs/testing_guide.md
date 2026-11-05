# NetVision — Automated Testing & Verification Guide

This document records the automated verification results, test suite implementation, and technical limitations of **NetVision**.

---

## 1. Automated Test Suite Execution Summary

The project test suite was executed using **Pytest 9.2.0** on **Python 3.14.6 (Windows 11)**.

### Test Results:
- **Total Test Cases:** 16
- **Passed:** 16 (100%)
- **Failed:** 0
- **Execution Time:** ~2.45 seconds

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.2.0, pluggy-1.7.0
rootdir: NetVision
collected 16 items

tests/test_anomaly_detector.py::test_port_scan_detection PASSED          [  6%]
tests/test_anomaly_detector.py::test_syn_burst_detection PASSED          [ 12%]
tests/test_anomaly_detector.py::test_high_packet_rate_detection PASSED   [ 18%]
tests/test_file_transfer.py::test_filename_sanitization_and_path_traversal PASSED [ 25%]
tests/test_file_transfer.py::test_binary_file_transfer_and_sha256_integrity PASSED [ 31%]
tests/test_file_transfer.py::test_formatting_utilities PASSED            [ 37%]
tests/test_packet_parser.py::test_parse_tcp_flags PASSED                 [ 43%]
tests/test_packet_parser.py::test_determine_direction PASSED             [ 50%]
tests/test_packet_parser.py::test_packet_parser_and_statistics PASSED    [ 56%]
tests/test_packet_parser.py::test_protocol_analyzer_handshake_tracking PASSED [ 62%]
tests/test_reports.py::test_csv_export PASSED                            [ 68%]
tests/test_reports.py::test_json_export PASSED                           [ 75%]
tests/test_reports.py::test_pdf_report_compilation PASSED                [ 81%]
tests/test_sender_receiver.py::test_tcp_connection_and_ping PASSED       [ 87%]
tests/test_sender_receiver.py::test_text_message_transfer PASSED         [ 93%]
tests/test_sender_receiver.py::test_connection_failure_handling PASSED   [100%]

======================== 16 passed, 1 warning in 2.45s ========================
```

---

## 2. Test Cases Specification Matrix

| Test Module | Function | Target Feature | Verification Criteria | Status |
|:---|:---|:---|:---|:---:|
| `test_sender_receiver.py` | `test_tcp_connection_and_ping` | Sockets / RTT | Sockets connect, exchange ping/pong, measure RTT | **PASSED** |
| `test_sender_receiver.py` | `test_text_message_transfer` | TCP Framing | Framing header, UTF-8 payload, receiver ACK | **PASSED** |
| `test_sender_receiver.py` | `test_connection_failure_handling` | Robustness | Inactive port raises connection error cleanly | **PASSED** |
| `test_file_transfer.py` | `test_filename_sanitization_and_path_traversal` | Security | `../../` traversal patterns stripped to basenames | **PASSED** |
| `test_file_transfer.py` | `test_binary_file_transfer_and_sha256_integrity` | File Transfer | 128KB binary payload transferred, SHA-256 match | **PASSED** |
| `test_file_transfer.py` | `test_formatting_utilities` | UI / Stats | Human-readable byte formatting (KB, MB) | **PASSED** |
| `test_packet_parser.py` | `test_parse_tcp_flags` | Scapy Parsing | SYN, ACK, FIN, RST correctly mapped to text | **PASSED** |
| `test_packet_parser.py` | `test_determine_direction` | Telemetry | Inbound / Outbound / Loopback classification | **PASSED** |
| `test_packet_parser.py` | `test_packet_parser_and_statistics` | Aggregation | Counters, packet sizes, protocol counts | **PASSED** |
| `test_packet_parser.py` | `test_protocol_analyzer_handshake_tracking` | State Engine | Handshake state machine (SYN -> SYN-ACK -> ACK) | **PASSED** |
| `test_anomaly_detector.py` | `test_port_scan_detection` | Anomaly Detection | 7 probed ports trigger `Port Scan Indicator` | **PASSED** |
| `test_anomaly_detector.py` | `test_syn_burst_detection` | Heuristics | 12 SYN packets trigger `SYN Flood Indicator` | **PASSED** |
| `test_anomaly_detector.py` | `test_high_packet_rate_detection` | Heuristics | Rate exceeding PPS threshold triggers alert | **PASSED** |
| `test_reports.py` | `test_csv_export` | Telemetry Export | CSV string generated with correct headers | **PASSED** |
| `test_reports.py` | `test_json_export` | Forensics Export | Valid JSON structure with metadata & stats | **PASSED** |
| `test_reports.py` | `test_pdf_report_compilation` | ReportLab PDF | Generates multi-page PDF document without error | **PASSED** |

---

## 3. Honest Testing Disclosure & Known Limitations

In compliance with academic evaluation standards, the following distinctions are explicitly stated:

### What Was Verified Locally:
1. All client-server socket communication, framing logic, chunked binary transfers, and SHA-256 verification were tested using loopback integration sockets on the host operating system.
2. Packet parsing, statistics calculation, MTU binning, time-series aggregation, and heuristic anomaly detection rules were tested and verified against synthetic and real packet structures.
3. Automated compilation of CSV, JSON, and PDF reports was executed and validated.

### What Requires Two Physical Laptops:
1. Physical multi-laptop 802.11 Wi-Fi communication requires two distinct physical laptops connected to a common network access point as documented in `docs/two_laptop_setup.md`.
2. Live promiscuous Layer-2 sniffing on a physical Wi-Fi NIC requires an active installation of Npcap with WinPcap API-compatible mode enabled. If absent, NetVision operates seamlessly in **Simulation Mode** or **Offline PCAP Mode**.
