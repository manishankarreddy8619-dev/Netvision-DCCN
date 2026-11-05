# NetVision — Two-Laptop Setup & Multi-Node Execution Guide

This document provides exact, terminal-by-terminal instructions for running a live multi-laptop demonstration between **Laptop A** (Sender & Sniffer) and **Laptop B** (Receiver).

---

## 1. Network Preparation (Avoiding Wi-Fi Client Isolation)

> ⚠️ **College Wi-Fi Warning (AP Client Isolation):**
> Many university Wi-Fi networks enable **Client Isolation**, which blocks wireless laptops from talking directly to one another.
>
> **Best Practice for College Demos:**
> Turn on a **Mobile Hotspot** on your smartphone and connect both Laptop A and Laptop B to this hotspot. This ensures unhindered peer-to-peer unicast traffic!

---

## 2. Step 1: Find IPv4 Addresses

On **both Laptop A and Laptop B**, open PowerShell and run:

```powershell
ipconfig
```

Look for the **Wireless LAN adapter Wi-Fi** section:
```
IPv4 Address. . . . . . . . . . . : 192.168.137.45  <-- Note this IP!
Subnet Mask . . . . . . . . . . . : 255.255.255.0
Default Gateway . . . . . . . . . : 192.168.137.1
```

*For this guide, let us assume:*
- **Laptop A (Sender / Dashboard):** `192.168.137.10`
- **Laptop B (Receiver Daemon):** `192.168.137.25`

---

## 3. Step 2: Verify Basic Connectivity (Ping)

On **Laptop A**, test reachability to Laptop B:

```powershell
ping 192.168.137.25
```

If ping requests time out, ensure Windows Firewall ICMP Echo is allowed on Laptop B:
```powershell
# Run on Laptop B as Admin:
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
```

---

## 4. Step 3: Start the Receiver Server on Laptop B

On **Laptop B**, navigate to the project directory and launch the standalone receiver daemon:

```powershell
cd NetVision
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="."

python network/receiver.py --host 0.0.0.0 --port 65432
```

**Expected Console Output on Laptop B:**
```
=================================================================
🚀 NetVision TCP Receiver Server Running
📡 Listening Interface: 0.0.0.0:65432
📁 Destination Folder: C:\...\NetVision\data\received_files
Press Ctrl+C to shut down.
=================================================================
```

Laptop B is now actively listening for incoming TCP frames.

---

## 5. Step 4: Launch the Dashboard & Sniffer on Laptop A

On **Laptop A**, open PowerShell as Administrator (required for Scapy live sniffing):

```powershell
cd NetVision
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="."

python -m streamlit run app.py
```

The browser will open to `http://localhost:8501`.

### Configure Capture on Laptop A:
1. In the sidebar, select **"📡 Live Capture (Npcap / Scapy)"**.
2. Under **"Select Network Interface"**, select your Wi-Fi adapter (e.g., `Wi-Fi` or `Intel(R) Wi-Fi 6`).
3. (Optional) Set BPF filter to `tcp port 65432` to isolate NetVision project traffic.
4. Click **"▶ Start Capture"**.

---

## 6. Step 5: Transmit Messages and Files from Laptop A

### Option 1: Via the Dashboard UI
1. Navigate to the **"📁 File & Message Transfer"** page in the dashboard.
2. In **"Target Laptop IP Address"**, enter Laptop B's IP: `192.168.137.25`.
3. Click **"🔌 Ping / Test Link"** to measure round-trip time (RTT).
4. Type a message and click **"🚀 Transmit Message"**.
5. Upload a document or image file and click **"🚀 Upload & Stream File"**.

### Option 2: Via the Terminal (Sender CLI)
Open a second PowerShell window on **Laptop A**:

```powershell
# Send text message
python network/sender.py --host 192.168.137.25 --port 65432 --msg "Hello Laptop B from NetVision!"

# Send binary file
python network/sender.py --host 192.168.137.25 --port 65432 --file "sample_presentation.pdf"
```

---

## 7. Step 6: Verify Delivery & SHA-256 Integrity

### On Laptop A:
- Observe transfer duration and real-time speed in KB/s or MB/s.
- Confirm **"SHA-256 Integrity: Verified (Match: True)"**.

### On Laptop B:
- Inspect terminal logs showing file reception and matching hash.
- Open `data/received_files/` on Laptop B to see the received file intact!

---

## 8. Step 7: Observe Telemetry in Dashboard

Return to **Laptop A's Dashboard**:
- **Live Packet Monitor:** See the SYN, SYN-ACK, ACK handshake frames, followed by PSH-ACK file chunks.
- **Network Analytics:** View throughput spikes and protocol distribution.
- **Reports & Export:** Download the session PDF and CSV report summarizing the transfer.
