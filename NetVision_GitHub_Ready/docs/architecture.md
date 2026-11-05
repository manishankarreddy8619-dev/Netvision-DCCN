# NetVision — System & Network Architecture Specification

## 1. Executive Architecture Summary

**NetVision** is an intelligent, dual-node computer network monitoring, packet sniffing, and traffic analysis platform engineered specifically for Data Communication and Computer Networks (DCCN) educational environments and academic evaluation.

```
+----------------------------------------------------------------------------------------------------+
|                                     NETVISION SYSTEM ARCHITECTURE                                   |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  |                              PRESENTATION LAYER (Streamlit UI)                              |  |
|  |  [Overview KPIs] [Live Packet Monitor] [Analytics & Graphs] [File Transfer] [Alerts] [Export]|  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                |                                                   |
|  +----------------------------------------------------------------------------------------------+  |
|  |                           ANALYSIS & INTELLIGENCE LAYER (Core Engine)                        |  |
|  |  +---------------------+  +----------------------+  +------------------+  +----------------+ |  |
|  |  | Packet Parser       |  | Traffic Statistics   |  | Protocol Engine  |  | Anomaly Engine | |  |
|  |  | (Headers/Dissection)|  | (PPS/BPS/Histograms) |  | (State/Handshake)|  | (Heuristics)   | |  |
|  |  +---------------------+  +----------------------+  +------------------+  +----------------+ |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                |                                                   |
|  +----------------------------------------------------------------------------------------------+  |
|  |                             TRANSPORT & CAPTURE LAYER (Hardware)                             |  |
|  |  +---------------------+  +----------------------+  +-------------------------------------+  |  |
|  |  | TCP Sender Client   |  | TCP Receiver Server  |  | Scapy / Npcap / Simulation Engine   |  |  |
|  |  | (Chunking/SHA-256)  |  | (Daemon/Validation)  |  | (Live NIC / PCAP / Zero-Privilege)  |  |  |
|  |  +---------------------+  +----------------------+  +-------------------------------------+  |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                |                                                   |
|  +----------------------------------------------------------------------------------------------+  |
|  |                                  PHYSICAL NETWORK TOPOLOGY                                   |  |
|  |         Laptop A (192.168.1.10) <==== [802.11 Wi-Fi / Switch] ====> Laptop B (192.168.1.25) |  |
|  +----------------------------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Multi-Laptop Hardware Roles

### Laptop A (Sender & Analyzer Node)
- **Role:** Initiates network communications, transfers text/binary payloads, runs the packet sniffer engine, and hosts the visual Streamlit dashboard.
- **Components:**
  - `network/sender.py`: TCP client initiating transfers and timing throughput.
  - `network/packet_sniffer.py`: Captures inbound/outbound NIC frames.
  - `app.py`: Streamlit dashboard on `localhost:8501`.

### Laptop B (Receiver Node)
- **Role:** Dedicated server daemon listening on a configured port, receiving byte streams, writing validated files, and returning cryptographic acknowledgements.
- **Components:**
  - `network/receiver.py`: Multi-threaded TCP socket daemon on port `65432`.
  - `data/received_files/`: Isolated file repository.

---

## 3. Network Topology & Promiscuous Sniffing Principles

### Two-Laptop Star Topology
Laptop A and Laptop B associate with a common Wireless Access Point (WAP) or Ethernet switch:
```
[ Laptop A ] ----(unicast 802.11)----> [ Wi-Fi AP / Switch ] ----(unicast 802.11)----> [ Laptop B ]
```
In an IEEE 802.11 Infrastructure BSS or an 802.3 Ethernet switched fabric:
1. **Unicast Isolation:** Switched network hardware directs frames strictly to the destination MAC address.
2. **Promiscuous Mode Scope:** Laptop A can capture all packets where its NIC is either the source or destination.
3. **The Three-Laptop Limitation:** An unprivileged third laptop (Laptop C) connected to the same Wi-Fi cannot capture unicast frames exchanged between Laptop A and Laptop B due to:
   - Dynamic MAC filtering at the switch/AP.
   - WPA2/WPA3 pairwise transient key (PTK) encryption isolating per-station traffic.
4. **Legitimate Enterprise Capture:** To capture multi-node traffic on a third node, legitimate configurations require:
   - Switch Port Mirroring (SPAN - Switched Port Analyzer).
   - Network Test Access Points (TAPs).
   - Routed gateway capture at the router/firewall level.

---

## 4. Custom Application Framing Protocol (`NetVision Frame`)

TCP is a continuous byte-stream protocol devoid of application message boundaries. If two messages are transmitted back-to-back, TCP may deliver them in a single merged `recv()` call or fragment one message across multiple calls. 

To guarantee framing integrity, NetVision implements an **8-byte binary header**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic Bytes ('NV')      |       Frame Type (uint16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Payload Data ...                        |
|                     (Length bytes total)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Frame Types:
- `0x0001` (`MSG`): UTF-8 text message.
- `0x0002` (`FILE_META`): JSON metadata containing `filename`, `size`, and `sha256`.
- `0x0003` (`FILE_CHUNK`): Raw binary block (default 64 KB).
- `0x0004` (`FILE_END`): End-of-file transmission sentinel.
- `0x0005` (`ACK`): Structured acknowledgement with duration, verified hash, and transfer speed.
- `0x0006` (`ERROR`): Error notification payload.
- `0x0007` (`PING`) / `0x0008` (`PONG`): Round-trip latency probe.

---

## 5. Security & Threat Model

1. **Path Traversal Defense:** All filenames received in `FILE_META` are passed through `sanitize_filename()` which strips directory separators (`/`, `\`, `..`), replaces unsafe characters with underscores, and strictly validates that destination paths resolve within `data/received_files/`.
2. **Payload Protection:** NetVision parses packet headers (IP, TCP, UDP, ICMP) but **never stores raw payload bytes or credentials** to respect privacy and compliance standards.
3. **Defensive Wording:** Detected anomalies are classified as *"Potentially suspicious network activity detected"* rather than definitive attacks.
