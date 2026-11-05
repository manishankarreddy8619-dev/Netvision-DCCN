# NetVision — Complete User Manual

Welcome to **NetVision**, a network packet sniffer and intelligent traffic analyzer designed for network engineering students and cybersecurity learners.

---

## 1. Navigating the Dashboard

NetVision features a dark cybersecurity interface accessible via web browser on `http://localhost:8501`.

The left sidebar contains:
- **Capture Mode Selection:** Live Capture, Simulation Mode, Offline PCAP.
- **Engine Controls:** Start Capture, Stop Capture, Reset Buffer, Live UI Sync.
- **Page Navigation:** Overview, Live Packet Monitor, Network Analytics, File & Message Transfer, Anomaly Alerts, Reports & Export.

---

## 2. Overview Page

The **Overview Page** presents immediate high-level telemetry:
- **Total Captured Packets:** Cumulative count of all parsed frames in memory.
- **Network Volume:** Cumulative bytes transferred.
- **TCP, UDP, and ICMP Counters:** Categorical count of transport and network layer protocols.
- **Protocol Distribution Donut Chart:** Visual breakdown of protocol percentages.
- **Traffic Activity Line Graph:** Packets per second (PPS) over time.
- **Hardware Architecture Reference:** Clarifies the multi-laptop topology.

---

## 3. Live Packet Monitor & Deep Inspector

The **Live Packet Monitor** presents a scrolling tabular stream of all network frames.

### Filter Toolbar:
- **Protocol Filter:** Select All, TCP, UDP, ICMP, or DNS.
- **Source / Destination IP Filter:** Substring matching on IP endpoints.
- **Port Filter:** Match source or destination port number.
- **Size Slider:** Filter frames within a specific byte size range.
- **Free-Text Search:** Instant filter by keywords, flag names, or summaries.
- **Pause / Resume:** Freeze table updates without stopping background packet ingestion.
- **Clear:** Empty rolling buffer.

### Deep Packet Inspector:
- Input any Packet ID into the inspector box.
- Inspect detailed dissected headers: IP Version, TTL, Frame Size, TCP Flags, Direction, and Protocol Summary.

---

## 4. Network Analytics Page

Visualizes network behavior through six specialized interactive Plotly charts:
1. **Packets Per Second (PPS):** Instantaneous packet throughput over elapsed seconds.
2. **Bandwidth Rate (KB/s):** Data throughput graph showing volume bursts.
3. **Packet Size Distribution:** Histogram categorized into standard MTU bins (<64B, 64-128B, 129-512B, 513-1024B, 1025-1518B, >1518B).
4. **TCP Flags Breakdown:** Bar graph of SYN, ACK, FIN, RST, and PSH flags.
5. **Top Communicating IP Endpoints:** Horizontal bar chart of the most active talkers.
6. **TCP Three-Way Handshake Records:** Table listing detected TCP handshakes, client/server sockets, and round-trip handshake latency in milliseconds.

---

## 5. File & Message Transfer Monitor

Perform socket tests directly from the dashboard:
1. **Receiver Daemon Box:** Start or stop the local TCP listener on port 65432.
2. **Target Node Configuration:** Enter destination IP address and port.
3. **Ping / Link Test:** Probe target socket and measure RTT.
4. **Send Text Message:** Enter text and verify length-prefixed delivery.
5. **Send File:** Drag and drop any binary or text file; track real-time progress, transfer speed, and end-to-end SHA-256 hash match.
6. **Transfer Log:** View session transfer records.

---

## 6. Anomaly Alerts Page

Monitors for potentially suspicious network activity using multi-point behavioral rules:
- **High Packet Rate:** Triggers when instantaneous rate exceeds configured threshold.
- **Sudden Traffic Spike:** Detects sudden bursts exceeding 3.5x running average.
- **SYN Flood Indicator:** Detects excessive TCP SYN packets without completed handshakes.
- **Port Scan Indicator:** Flags single sources probing multiple destination ports in a short window.
- **Classroom Anomaly Injections:** Single-click buttons to inject safe simulated port scans, SYN floods, or traffic spikes to demonstrate detection capabilities during viva reviews.

---

## 7. Reports & Export Page

Download forensic session reports:
- **CSV Packet Log:** Tabular spreadsheet of all captured packets.
- **JSON Telemetry:** Hierarchical telemetry record containing aggregate stats and alerts.
- **Executive PDF Report:** Formatted academic report containing tables, protocol breakdowns, observations, and conclusion.
