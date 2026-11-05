# NetVision — Multi-Laptop Network Packet Sniffer and Intelligent Traffic Analyzer

[![Python](https://img.shields.io/badge/Python-3.12%20|%203.13%20|%203.14-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-FF4B4B.svg)](https://streamlit.io)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-red.svg)](https://scapy.net)
[![Tests](https://img.shields.io/badge/Tests-16%20Passed%20(100%25)-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20VS%20Code-0078D6.svg)]()
[![Course](https://img.shields.io/badge/Subject-Data%20Communication%20%26%20Networks%20(DCCN)-purple.svg)]()

> **NetVision** is a production-grade, educational network monitoring and traffic analysis system designed for B.Tech computer networking curricula, student demonstrations, and network engineering learners.

---

## 🌟 Executive Overview

NetVision bridges the gap between abstract textbook network concepts and real-world network packets. Built for a **two-laptop local Wi-Fi topology**, it allows students to actively transmit text messages and large binary files from **Laptop A** to **Laptop B**, monitor live packet exchanges over physical Network Interface Cards (NICs), observe TCP three-way handshakes, analyze bandwidth timelines, detect suspicious traffic patterns through transparent heuristics, and export formal forensic PDF reports.

```
+----------------------------------------------------------------------------------------------------+
|                                     NETVISION SYSTEM ARCHITECTURE                                   |
+----------------------------------------------------------------------------------------------------+
|  [Laptop A: Client / Analyzer / Sniffer]                    [Laptop B: Dedicated Server]           |
|  +-------------------------------------+                    +------------------------------------+ |
|  | Streamlit Cybersecurity Dashboard   |                    | ReceiverServer (Daemon)            | |
|  | - Live Packet Monitor & Inspector   |                    | - Listening on Port 65432          | |
|  | - 6 Interactive Plotly Charts       |                    | - Binary Chunk Assembler           | |
|  | - Anomaly Heuristics (Port Scan/SYN)|                    | - SHA-256 Cryptographic Hash Check | |
|  | - PDF/CSV/JSON Report Generator     |                    | - Path Traversal Sandbox Defense   | |
|  +------------------+------------------+                    +------------------+-----------------+ |
|                     |                                                          |                   |
|  +------------------v------------------+       Direct TCP Unicast Stream       |                   |
|  | SenderClient Module                 | -------------------------------------->                   |
|  | - 8-Byte Binary Framing Header      |   (Text Messages / 64KB Binary Blocks)|                   |
|  | - End-to-End SHA-256 Hasher         | <-------------------------------------+                   |
|  +------------------^------------------+       Framed Status ACK & Speed Metrics                   |
|                     |                                                                              |
|  +------------------+------------------+                                                           |
|  | PacketSnifferEngine (Scapy / Npcap) |                                                           |
|  | - Live Wi-Fi Sniffing               |                                                           |
|  | - Offline PCAP File Parser          |                                                           |
|  | - Zero-Privilege Simulation Engine  |                                                           |
|  +-------------------------------------+                                                           |
|                     |                                                                              |
|  +------------------v----------------------------------------------------------------------------+ |
|  | Wi-Fi 802.11 Access Point / Mobile Hotspot (Common Local Subnet e.g. 192.168.1.0/24)          | |
|  +-----------------------------------------------------------------------------------------------+ |
+----------------------------------------------------------------------------------------------------+
```

---

## 🚀 Key Features

### 1. Robust Multi-Laptop TCP Sockets
- **Length-Prefixed Binary Framing:** Fixed 8-byte header (`MAGIC` b'NV', `Type` uint16, `Length` uint32) guarantees zero byte-stream fragmentation or delimiter collision issues.
- **Cryptographic File Integrity:** End-to-end streaming **SHA-256 hashing** confirms 100% bit-level transmission validity.
- **Real-Time Throughput Measurement:** Measures transfer duration and dynamically computes speeds in KB/s and MB/s.
- **Path Traversal Defense:** Sanitizes filenames and enforces strict sandboxed folder boundaries.

### 2. Live Packet Sniffing & Header Dissection
- Captures IPv4/IPv6, TCP (SYN, ACK, FIN, RST, PSH, URG), UDP (DNS queries), and ICMP (Echo Request/Reply) frames.
- **Strict Payload Privacy:** Strips and discards sensitive application payloads, passwords, and tokens; captures only protocol header metadata.
- **TCP Three-Way Handshake Engine:** Automatically tracks state machines (`SYN` -> `SYN-ACK` -> `ACK`) and records round-trip handshake latency in milliseconds.

### 3. Modern Dark Cybersecurity Dashboard
- **Dark Navy Theme:** Designed with dark navy backgrounds (`#0b0f19`) and vibrant cyan/blue highlights (`#00f0ff`, `#38bdf8`).
- **Live Tabular Packet Stream:** Dynamic search, protocol filtering, port matching, and deep packet inspector modal.
- **6 Plotly Visualizations:**
  1. Protocol Distribution Donut Chart.
  2. Packets Per Second (PPS) Timeline.
  3. Bandwidth Rate (KB/s) Throughput Graph.
  4. Packet Size Distribution (MTU Profile) Histogram.
  5. Top Communicating IP Talkers.
  6. TCP Flags Breakdown Bar Graph.

### 4. Transparent Rule-Based Anomaly Detection
- Flags unusual network traffic with clear educational evidence and recommended investigations:
  - **High Packet Rate:** Instantaneous rate exceeding operating limits.
  - **Sudden Traffic Spike:** Surge exceeding 3.5x moving baseline average.
  - **SYN Flood Indicator:** Burst of half-open SYN packets without handshakes.
  - **Port Scan Indicator:** Single source probing multiple distinct ports in a short window.
- **Classroom Safe Anomaly Injections:** Single-click simulation triggers to safely demonstrate anomaly alerts during college vivas.

### 5. Multi-Mode Resilience
- **Mode A (Live Capture):** Scapy + Npcap sniffing on physical Wi-Fi/Ethernet adapters.
- **Mode B (Offline PCAP):** Upload and parse `.pcap` and `.pcapng` files.
- **Mode C (Simulation Mode):** Generates realistic, clearly labeled synthetic traffic for classroom presentations without administrative privileges.

### 6. Automated Forensics & Report Generation
- Instant download of raw **CSV** packet tables.
- Hierarchical **JSON** telemetry sessions.
- Multi-page, executive **PDF Analysis Reports** compiled via ReportLab.

---

## 📂 Project Structure

```
NetVision/
├── app.py                      # Main Streamlit Dashboard Application
├── requirements.txt            # Project Dependencies
├── README.md                   # GitHub Repository Guide
├── .gitignore                  # Git Ignore Configuration
├── config.example.json         # Example Configuration File
├── config.json                 # Active Engine Configuration
│
├── network/                    # Core Networking Subsystem
│   ├── __init__.py
│   ├── file_transfer.py        # 8-Byte Framing, SHA-256, & Path Traversal Security
│   ├── receiver.py             # TCP Server Daemon (Laptop B)
│   ├── sender.py               # TCP Client & Throughput Calculator (Laptop A)
│   └── packet_sniffer.py       # Live Sniffer, PCAP Loader, & Simulation Engine
│
├── analyzer/                   # Traffic Analysis & Intelligence
│   ├── __init__.py
│   ├── packet_parser.py        # Scapy Dissection & Privacy Sanitization
│   ├── protocol_analyzer.py    # TCP 3-Way Handshake & ICMP Latency Tracking
│   ├── traffic_statistics.py   # Aggregation Engine (PPS, BPS, MTU Bins)
│   └── anomaly_detector.py     # Rule-Based Anomaly Detection Heuristics
│
├── dashboard/                  # Full-Stack Streamlit UI Components
│   ├── __init__.py
│   ├── styles.py               # Cybersecurity Dark Navy & Cyan CSS
│   ├── overview.py             # Operational Overview & KPI Cards
│   ├── packet_monitor.py       # Live Packet Table & Deep Inspector
│   ├── analytics.py            # 6 Interactive Plotly Visualizations
│   ├── file_transfer_view.py   # Interactive Transmission Controls
│   ├── alerts.py               # Anomaly Alerts & Simulation Injections
│   └── reports_view.py         # Forensic Export Controls
│
├── reports/                    # Forensic Document Compilation
│   ├── __init__.py
│   ├── report_generator.py     # CSV, JSON, and ReportLab PDF Generators
│   ├── generate_academic_pdf.py# B.Tech Project Report PDF Generator
│   ├── generate_academic_docx.py# Editable Project Report DOCX Generator
│   ├── NetVision_Project_Report.pdf  # Compiled Academic Report (PDF)
│   └── NetVision_Project_Report.docx # Editable Academic Report (DOCX)
│
├── presentation/               # PowerPoint Slide Deck
│   ├── generate_presentation.py# python-pptx 14-Slide Presentation Builder
│   └── NetVision_Presentation.pptx   # 14-Slide Widescreen Presentation (.pptx)
│
├── data/                       # Telemetry & File Repository
│   ├── sample_data/
│   │   ├── generate_sample_pcap.py   # Offline PCAP Generator
│   │   └── sample_traffic.pcap       # 20-Packet Trace File
│   └── received_files/         # Sandboxed Directory for Received Files
│
├── tests/                      # Automated Test Suite (Pytest)
│   ├── __init__.py
│   ├── test_sender_receiver.py # Sockets, Text Framing, & RTT
│   ├── test_file_transfer.py   # Binary Chunks, SHA-256, & Path Traversal
│   ├── test_packet_parser.py   # Dissection, Direction, & Handshake Engine
│   ├── test_anomaly_detector.py# Heuristic Detection Rules
│   └── test_reports.py         # CSV, JSON, & PDF Validation
│
└── docs/                       # Comprehensive Academic Documentation
    ├── architecture.md         # System Architecture & Threat Model
    ├── installation_guide.md   # Windows 11 & VS Code Setup
    ├── two_laptop_setup.md     # Multi-Laptop Execution Guide
    ├── user_manual.md          # Complete Dashboard User Manual
    ├── demonstration_guide.md  # 7-Step College Demonstration Script
    ├── testing_guide.md        # Test Verification Matrix
    ├── viva_questions.md       # 35 DCCN Viva Voce Questions & Answers
    └── academic_report.md      # Full 20-Section Academic Report (Markdown)
```

---

## ⚡ Quickstart Installation (Windows 11 & VS Code)

### 1. Clone or Extract the Repository
```powershell
cd NetVision
```

### 2. Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Run Automated Tests
```powershell
$env:PYTHONPATH="."
python -m pytest tests -v
```
*(All 16 test cases will execute with 100% pass status)*

### 5. Launch NetVision Dashboard
```powershell
python -m streamlit run app.py
```
Open your browser to `http://localhost:8501`.

---

## 🌐 Running on Two Laptops

| Laptop | Role | Execution Command |
|:---:|:---|:---|
| **Laptop B** | TCP Receiver Server | `python network/receiver.py --port 65432` |
| **Laptop A** | Sender & Sniffer Dashboard | `python -m streamlit run app.py` |

1. Connect both laptops to the same **Wi-Fi or smartphone mobile hotspot** (recommended to bypass campus Wi-Fi Client Isolation).
2. Discover Laptop B's IPv4 address with `ipconfig` (e.g., `192.168.1.25`).
3. On Laptop A's dashboard, enter Laptop B's IP and transmit files or messages!

---

## 🧪 Automated Testing Verification Matrix

```
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

======================== 16 passed in 2.45s ========================
```

---

## 🛡️ Security & Ethical Guidelines

- **Defensive Focus:** NetVision is strictly intended for educational demonstration, internal laboratory instruction, and authorized network auditing.
- **Privacy Enforcement:** NetVision strips all application payloads, passwords, and tokens.
- **Promiscuous Scope:** NetVision respects the physical limitations of switched and WPA2/WPA3 Wi-Fi networks and does not implement unauthorized packet interception.

---

## 📤 Git Commands for Uploading to GitHub

When you are ready to upload the project to your GitHub repository:

```powershell
cd NetVision
git init
git add .
git commit -m "Initial commit: NetVision complete DCCN mini-project"
git branch -M main
git remote add origin https://github.com/<your-username>/NetVision.git
git push -u origin main
```

---

## 📄 License
This project is licensed under the **MIT License**.
