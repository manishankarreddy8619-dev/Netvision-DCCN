# NetVision — College Demonstration & Viva Script

A structured 7-step demonstration script for presenting **NetVision** during B.Tech DCCN project evaluations and lab examinations.

---

## 1. Demonstration Checklist & Setup

| Step | Action | Laptop | Command / Action |
|:---:|:---|:---:|:---|
| 1 | Connect to Wi-Fi / Hotspot | Both | Associate both laptops to smartphone mobile hotspot |
| 2 | Find IP addresses | Both | Run `ipconfig` (e.g., Laptop A = `192.168.1.10`, Laptop B = `192.168.1.25`) |
| 3 | Start Receiver Daemon | Laptop B | `python network/receiver.py --port 65432` |
| 4 | Launch Dashboard | Laptop A | `python -m streamlit run app.py` |

---

## 2. Demonstration 1 — TCP Connection Establishment & RTT

### Objective:
Demonstrate reliable socket initialization and measure round-trip time between laptops.

### Action on Laptop A:
1. Open the NetVision Dashboard (`http://localhost:8501`).
2. Go to **"📁 File & Message Transfer"**.
3. In **Target Laptop IP**, enter Laptop B's IP address (`192.168.1.25`).
4. Click **"🔌 Ping / Test Link"**.

### Expected Result:
- Green success notification: `Connection OK! RTT: 2.14 ms`.
- Demonstrates active socket handshake and baseline latency.

---

## 3. Demonstration 2 — Capture the TCP Three-Way Handshake

### Objective:
Prove proper TCP state transitions (`SYN` -> `SYN-ACK` -> `ACK`).

### Action on Laptop A:
1. In sidebar, ensure capture is active (or click "Start Capture").
2. Transmit a message or small file.
3. Open **"📈 Network Analytics"** and scroll to **"🤝 TCP Three-Way Handshake Records"**.

### Expected Result:
- Table lists:
  - Client socket: `192.168.1.10:51234`
  - Server socket: `192.168.1.25:65432`
  - Handshake RTT: `~2 to 5 ms`
  - Summary: `TCP 3-Way Handshake established: 192.168.1.10:51234 ➔ 192.168.1.25:65432`

---

## 4. Demonstration 3 — Transmit Text Messages with Byte-Stream Framing

### Objective:
Demonstrate length-prefixed application framing over TCP byte streams.

### Action on Laptop A:
1. Under **"File & Message Transfer"**, select the **"💬 Send Text Message"** tab.
2. Enter: `"Hello Laptop B! NetVision Framing Test."`
3. Click **"🚀 Transmit Message"**.

### Expected Result:
- Laptop A UI displays: `Message delivered! Ack: Message received successfully. (Elapsed: 0.008s)`.
- Laptop B terminal logs: `[Receiver] Message from 192.168.1.10: Hello Laptop B! NetVision Framing Test.`
- Live Packet Monitor records frames with flag `PSH-ACK`.

---

## 5. Demonstration 4 — Binary File Transfer, Speed, & SHA-256 Integrity

### Objective:
Transfer a binary file, compute real-time throughput, and verify cryptographic integrity.

### Action on Laptop A:
1. Select the **"📁 Send Binary File"** tab.
2. Upload a PDF, image, or ZIP file (e.g., 2 MB).
3. Click **"🚀 Upload & Stream File"**.

### Expected Result:
- Progress bar fills smoothly from 0% to 100%.
- UI reports:
  - Duration: `~0.35s`
  - Average Speed: `~5.7 MB/s`
  - SHA-256 Match: `✅ Matched (True)`
- Click **"🔒 SHA-256 Details"** to show matching hashes:
  - Sender Hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - Receiver Hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- File appears intact in Laptop B's `data/received_files/` folder!

---

## 6. Demonstration 5 — Real-Time Telemetry & Protocol Visualizations

### Objective:
Demonstrate visual packet statistics and MTU profile.

### Action on Laptop A:
1. Navigate to **"📈 Network Analytics"**.
2. Explain the charts to the evaluator:
   - **Protocol Donut:** Shows proportions of TCP vs UDP vs ICMP.
   - **Throughput & PPS Lines:** Highlights the spike during the file transfer.
   - **Size Distribution Histogram:** Shows MTU saturation (packets grouped at 1460 bytes for data chunks and 54-66 bytes for pure ACKs).

---

## 7. Demonstration 6 — Anomaly Detection Heuristics

### Objective:
Demonstrate transparent rule-based anomaly detection without running dangerous exploit tools.

### Action on Laptop A:
1. Navigate to **"🚨 Anomaly Alerts"**.
2. Under **"Classroom Demonstration: Safe Anomaly Injections"**, click:
   - `⚡ Inject Port Scan (10 Ports)`
3. Observe instant alert generation:
   - **Category:** `Port Scan Indicator`
   - **Severity:** `HIGH`
   - **Evidence:** `Host probed 10 distinct destination ports within 2.0s`
   - **Language:** *"Potentially suspicious network activity detected: sequential or distributed port probing."*
4. Click `🌊 Inject SYN Burst` to show SYN flood detection.

---

## 8. Demonstration 7 — Academic Report Compilation

### Objective:
Download formal forensic session documentation.

### Action on Laptop A:
1. Navigate to **"📑 Reports & Export"**.
2. Click **"📝 Compile PDF Report"** -> **"⬇️ Download Report (PDF)"**.
3. Open the PDF in Acrobat / Edge to show:
   - Formatted tables with exact packet counts, protocol percentages, detected alerts, and DCCN conclusions.

---

## 9. Troubleshooting During Demonstration

| Problem | Cause | Quick Fix |
|:---|:---|:---|
| **Ping times out between laptops** | College Wi-Fi Client Isolation or Windows Firewall | 1. Switch both laptops to Mobile Hotspot.<br/>2. Allow ICMP in Windows Firewall. |
| **Sender gives `Connection refused`** | Receiver daemon not started on Laptop B | Start `receiver.py` on Laptop B before sending. |
| **Npcap capture permission error** | Terminal not run as Administrator | Run PowerShell as Admin, OR switch to **Simulation Mode** (which works 100% without admin rights!). |
| **Streamlit web page won't open** | Port 8501 blocked | Open browser to `http://localhost:8501` or check terminal output. |
