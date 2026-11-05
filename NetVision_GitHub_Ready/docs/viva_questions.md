# NetVision — 35 Comprehensive DCCN Viva Voce Questions & Answers

This preparation guide covers essential Data Communication and Computer Networks (DCCN) viva questions, theoretical foundations, and implementation details of the NetVision project.

---

### Q1: What is a network packet?
**Answer:** A network packet is the fundamental formatted unit of data transmitted over a packet-switched network. It comprises three primary sections:
1. **Header:** Contains control metadata such as Source IP, Destination IP, protocol type, and sequence numbers.
2. **Payload:** The actual application data being conveyed.
3. **Trailer/Checksum:** Error-checking bits (such as CRC or Frame Check Sequence) to detect corruption in transit.

---

### Q2: What is packet sniffing?
**Answer:** Packet sniffing (or packet capture) is the process of intercepting, logging, and inspecting data packets traversing a network interface card (NIC). By capturing packets at Layer 2 or Layer 3, network administrators can analyze protocol behaviors, monitor bandwidth, troubleshoot transmission faults, and detect anomalous patterns.

---

### Q3: What is the Transmission Control Protocol (TCP)?
**Answer:** TCP is a connection-oriented, reliable transport layer protocol operating at Layer 4 of the OSI model. It guarantees in-order delivery of data, provides flow control (via sliding windows), implements error detection and retransmission (via ACKs and sequence numbers), and manages congestion control.

---

### Q4: What is the User Datagram Protocol (UDP)?
**Answer:** UDP is a connectionless, lightweight transport layer protocol. Unlike TCP, UDP does not establish a connection before sending, does not guarantee delivery, and does not provide sequencing or retransmission. It offers minimal overhead and low latency, making it ideal for DNS, DHCP, VoIP, and live video streaming.

---

### Q5: What is the Internet Control Message Protocol (ICMP)?
**Answer:** ICMP operates at the Network Layer (Layer 3) alongside IP. It is not used for exchanging application data; rather, it reports network operational information, diagnostic messages, and transmission errors (e.g., Destination Unreachable, Time-to-Live Exceeded in transit). Utilities like `ping` (Echo Request/Reply) and `traceroute` rely on ICMP.

---

### Q6: What is an IP address?
**Answer:** An Internet Protocol (IP) address is a unique numerical identifier assigned to each device connected to a computer network participating in IP communication. IPv4 uses 32-bit addresses (e.g., `192.168.1.10`), while IPv6 uses 128-bit hexadecimal addresses to expand the address space.

---

### Q7: What is a port number?
**Answer:** A port number is a 16-bit integer (0 to 65535) used at the Transport Layer to identify a specific application or process endpoint running on a host. Well-known ports (0–1023) identify standard services (e.g., HTTP on 80, HTTPS on 443, DNS on 53), while registered/ephemeral ports (1024–65535) are utilized by client applications and custom services.

---

### Q8: What is socket programming?
**Answer:** Socket programming is an API mechanism that allows software applications on different networked hosts (or the same host) to establish bidirectional communication channels. In Python, the `socket` module provides direct interfaces to OS-level transport primitives (`socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()`).

---

### Q9: Explain the TCP Three-Way Handshake.
**Answer:** The TCP three-way handshake establishes a synchronized, reliable connection before data exchange:
1. **SYN:** Client selects an initial sequence number `x` and sends a packet with flag `SYN=1` to the server. (Client state: `SYN_SENT`).
2. **SYN-ACK:** Server responds with flag `SYN=1, ACK=1`, acknowledging sequence `x+1` and presenting its own sequence number `y`. (Server state: `SYN_RECEIVED`).
3. **ACK:** Client sends `ACK=1` acknowledging sequence `y+1`. (Both states transition to `ESTABLISHED`). Data transfer can now commence.

---

### Q10: What are TCP Control Flags?
**Answer:** TCP flags are 1-bit flags in the TCP header that manage connection states:
- **SYN (Synchronize):** Initiates a connection.
- **ACK (Acknowledge):** Confirms receipt of packets.
- **FIN (Finish):** Initiates a graceful connection teardown.
- **RST (Reset):** Abruptly aborts a connection due to an error or rejected port.
- **PSH (Push):** Directs the receiving buffer to push data immediately to the application.
- **URG (Urgent):** Indicates payload contains urgent data.

---

### Q11: What is packet switching vs circuit switching?
**Answer:**
- **Circuit Switching:** Allocates a dedicated physical communication path between sender and receiver for the duration of the session (e.g., traditional PSTN telephone networks). Resources are reserved and cannot be shared.
- **Packet Switching:** Divides messages into independent packets that traverse dynamic routes across shared network infrastructure (e.g., the Internet). Packets share transmission capacity, improving efficiency.

---

### Q12: What is Scapy?
**Answer:** Scapy is a powerful Python library capable of forging, decoding, sniffing, and manipulating network packets across Layer 2 (Ethernet/ARP) to Layer 7. NetVision leverages Scapy for packet sniffing, header dissection, and offline PCAP file parsing.

---

### Q13: How does packet capture work at the OS level?
**Answer:** Normally, an operating system's network driver filters out all packets whose destination MAC address does not match the local NIC. When packet capture is initiated, the driver enables **Promiscuous Mode** (via Npcap on Windows or libpcap on Linux). This causes the NIC to pass all observable electrical/radio frames up to the capture buffer without kernel filtering.

---

### Q14: What is the difference between Wireshark and NetVision?
**Answer:**
- **Wireshark:** A heavy, C-based packet analyzer providing microscopic packet dissection across thousands of proprietary and standard protocols.
- **NetVision:** A modular, educational full-stack Python application combining:
  1. Active multi-laptop TCP socket transmission (sender/receiver with SHA-256 integrity).
  2. Targeted packet sniffing and real-time Plotly visualizations.
  3. Built-in heuristic anomaly detection.
  4. Zero-privilege synthetic simulation mode specifically tailored for college viva demonstrations.

---

### Q15: Why are the sender and receiver on the same local network?
**Answer:** Both laptops reside on the same local subnet (e.g., `192.168.1.0/24`) so that direct private IP communication can take place without requiring public IP addresses, NAT traversal (Network Address Translation), or port forwarding on edge routers.

---

### Q16: Can a third laptop capture unicast traffic between two other laptops on Wi-Fi?
**Answer:** Ordinarily, **no**. In a standard IEEE 802.11 Wi-Fi network:
1. The Wireless Access Point acts as a Layer 2 switch, transmitting unicast frames directly to the intended destination station.
2. Under WPA2/WPA3 Personal, each laptop negotiates a unique pairwise key (PTK), encrypting frames over the air so other stations cannot decode them.
Capturing another laptop's traffic requires legitimate administrative configurations such as **Switch Port Mirroring (SPAN)** or a network TAP.

---

### Q17: What is TCP stream fragmentation and how did NetVision solve it?
**Answer:** TCP is a continuous byte-stream protocol without message boundaries. High volumes of data or network buffers can coalesce multiple `send()` calls into one, or split a single message across several `recv()` chunks. NetVision solves this using **Length-Prefixed Binary Framing** (`MAGIC` + `Type` + `Length`), ensuring the receiver reads exact byte counts before parsing messages or chunks.

---

### Q18: What is SHA-256 and why is it used in file transfers?
**Answer:** SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a unique 64-character hexadecimal digest from input data. NetVision computes the hash on the sender before transmission and on the receiver after assembly. If both hashes match, it mathematically proves the file was transmitted without bit-level corruption.

---

### Q19: What is Path Traversal and how does NetVision prevent it?
**Answer:** A path traversal attack occurs when an attacker includes directory traversal characters (e.g., `../../Windows/System32`) in a filename to overwrite sensitive files outside the destination directory. NetVision prevents this by:
1. Calling `os.path.basename()` to strip all directory prefixes.
2. Sanitizing filename characters using regular expressions.
3. Checking `Path.resolve().is_relative_to(target_dir)` to ensure the target path cannot escape the sandbox.

---

### Q20: What is Network Anomaly Detection?
**Answer:** Network anomaly detection is the identification of traffic patterns that deviate significantly from established normal operating baselines. It helps flag potential network scans, misconfigured hosts, device failures, or DoS floods.

---

### Q21: What heuristic rules does NetVision implement for anomaly detection?
**Answer:**
1. **High Packet Rate:** Instantaneous PPS exceeding configured operating limits.
2. **Sudden Traffic Spike:** Moving average multiplier detecting throughput surges.
3. **SYN Flood Indicator:** High concentration of TCP SYN packets without completed handshakes.
4. **Port Scan Indicator:** A single source probing multiple distinct destination ports within a short time window.
5. **ICMP Flood Indicator:** Abnormal percentage share of ICMP echo requests dominating bandwidth.

---

### Q22: Why does NetVision avoid calling anomalies "Cyberattacks"?
**Answer:** In educational and network monitoring tools, heuristic deviations can be caused by benign activities (e.g., a fast file download, an authorized vulnerability audit, or automated backup scripts). Labeling events as *"Potentially suspicious network activity detected"* maintains scientific objectivity and avoids false panic.

---

### Q23: How is transfer speed calculated?
**Answer:**
$$\text{Transfer Speed} = \frac{\text{Bytes Transferred}}{\text{Duration in Seconds}}$$
It is then converted to human-readable units (e.g., KB/s or MB/s) by dividing by $1024$ or $1024^2$.

---

### Q24: What is Maximum Transmission Unit (MTU)?
**Answer:** MTU is the largest packet or frame size (in bytes) that can be transmitted over a physical network medium without fragmentation. On standard Ethernet and Wi-Fi networks, the default MTU is **1500 bytes**.

---

### Q25: What happens when an IP packet exceeds the MTU?
**Answer:** If an IP packet is larger than the outgoing interface's MTU and the `DF` (Don't Fragment) bit is not set, intermediate routers or the host IP stack must fragment the packet into smaller segments, reassembled by the receiving host. If `DF=1`, the packet is dropped, and an ICMP "Fragmentation Needed" message is returned.

---

### Q26: What is Round-Trip Time (RTT)?
**Answer:** RTT is the duration (in milliseconds) required for a network packet to travel from the sender to the destination and for the acknowledgement or response to return. NetVision measures RTT during TCP ping tests and ICMP echo handshakes.

---

### Q27: What is Time To Live (TTL)?
**Answer:** TTL is an 8-bit field in the IPv4 header (Hop Limit in IPv6) designed to prevent packets from looping endlessly due to routing loops. Each router decrement the TTL by 1; if TTL reaches 0, the packet is discarded, and an ICMP Time Exceeded message is sent back to the source.

---

### Q28: What is Address Resolution Protocol (ARP)?
**Answer:** ARP maps a dynamic Layer 3 IP address to a physical Layer 2 MAC address within a local broadcast domain. Before Laptop A can send IP packets to Laptop B, it broadcasts an ARP request (`Who has 192.168.1.25?`) and receives an ARP reply containing Laptop B's MAC address.

---

### Q29: What is the purpose of Npcap on Windows?
**Answer:** The standard Windows network stack does not grant user-space Python programs raw Layer-2 packet sniffing access. Npcap is a specialized Windows kernel driver that captures raw frame bytes directly from the network adapter and provides a WinPcap-compatible API for Scapy.

---

### Q30: What is the advantage of NetVision's Simulation Mode?
**Answer:** In many college labs, students lack Administrator privileges to install drivers like Npcap, or the college Wi-Fi blocks peer-to-peer traffic. Simulation Mode generates synthetically accurate, labeled packets and protocol handshakes in Python memory, allowing complete demonstration of charts, filters, and anomaly detection without special privileges.

---

### Q31: What is Berkeley Packet Filter (BPF) syntax?
**Answer:** BPF is a syntax used by capture drivers to filter packets in kernel space before copying them to user memory. Examples include:
- `tcp port 65432` (Captures only TCP frames on port 65432).
- `ip host 192.168.1.10` (Captures only traffic involving IP 192.168.1.10).
- `icmp` (Captures only ICMP echo and error messages).

---

### Q32: What is Flow Control vs Congestion Control in TCP?
**Answer:**
- **Flow Control:** Prevents the sender from overwhelming the **receiver's** buffer (managed via the TCP Receive Window size in the header).
- **Congestion Control:** Prevents the sender from overwhelming the **intermediate network links and routers** (managed via congestion window, Slow Start, Congestion Avoidance, and Fast Retransmit).

---

### Q33: How does NetVision respect user privacy during packet analysis?
**Answer:** In strict compliance with network security guidelines:
1. NetVision only parses protocol headers (IP addresses, ports, flags, packet lengths).
2. It **strips and never records** application payloads, passwords, cookies, or decrypted messages.
3. Telemetry reports export only statistical summaries and header fields.

---

### Q34: What are the real-world applications of this project?
**Answer:**
1. **Educational Instruction:** Visualizing abstract protocol handshakes and byte streams for computer networking students.
2. **Network Performance Monitoring:** Tracking internal subnet throughput, packet loss, and MTU distribution.
3. **Cybersecurity Education:** Demonstrating heuristic detection of port scans and DoS signatures.
4. **LAN Troubleshooting:** Identifying misconfigured IP endpoints or unauthorized broadcast storms.

---

### Q35: What future enhancements could be added to NetVision?
**Answer:**
1. Machine-learning-based classification using unsupervised clustering (e.g., Isolation Forests) trained on historical network baselines.
2. Deep packet inspection for TLS 1.3 handshake parameters (SNI, cipher suites) without decrypting payloads.
3. Distributed agents: Running lightweight telemetry probes across multiple college classrooms reporting to a centralized dashboard.
