# NetVision — Complete Deployment Guide

This guide covers all deployment options for **NetVision**, from local dual-laptop college lab setups to free public cloud hosting and containerized Docker deployments.

---

## Deployment Strategy Overview

Depending on your objective, choose the appropriate deployment model:

| Deployment Option | Best For | Prerequisites | Cost | Publicly Accessible? |
|:---|:---|:---|:---|:---:|
| **Option 1: Two-Laptop Local LAN** | Live College Viva & Lab Evaluation | 2 Windows Laptops, Wi-Fi / Hotspot | Free | Local Subnet Only |
| **Option 2: Streamlit Community Cloud** | Sharing a public link with professors | GitHub Account | Free | ✅ Yes (Global Web URL) |
| **Option 3: Containerized Docker** | Portable Linux/Mac/Windows hosting | Docker / Docker Desktop | Free | Host Network |
| **Option 4: Cloud VM (AWS / DigitalOcean)** | 24/7 Remote Lab Server | Linux VPS / Ubuntu 22.04+ | ~$4-5/mo | ✅ Yes (Public Static IP) |
| **Option 5: Windows Background Service** | Persistent lab station deployment | Windows 10/11 PowerShell | Free | Local Subnet Only |

---

## Option 1: Two-Laptop Local LAN Deployment (College Viva Standard)

This is the primary evaluation architecture for B.Tech DCCN mini-projects.

```
[ Laptop A: 192.168.1.10 ] <==== (Local Wi-Fi / Hotspot) ====> [ Laptop B: 192.168.1.25 ]
* Runs Streamlit UI (Port 8501)                                 * Runs Receiver (Port 65432)
* Runs SenderClient & Sniffer                                   * Verifies SHA-256 Hashes
```

### Steps on Laptop B (Receiver Node):
```powershell
# 1. Open PowerShell and activate virtual environment
cd NetVision
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="."

# 2. Allow port 65432 through Windows Firewall (Run as Admin once)
New-NetFirewallRule -DisplayName "NetVision Receiver" -Direction Inbound -LocalPort 65432 -Protocol TCP -Action Allow

# 3. Start the Receiver Daemon
python network/receiver.py --host 0.0.0.0 --port 65432
```

### Steps on Laptop A (Sender & Dashboard Node):
```powershell
# 1. Open PowerShell as Administrator (required for Scapy live sniffing)
cd NetVision
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="."

# 2. Launch the Streamlit Dashboard
python -m streamlit run app.py --server.port 8501
```
- Open `http://localhost:8501`.
- Go to **File & Message Transfer**, enter Laptop B's IP, and transmit files.

---

## Option 2: Free 1-Click Cloud Deployment (Streamlit Community Cloud)

Deploy NetVision to a public URL (e.g. `https://netvision-analyzer.streamlit.app`) so evaluators and professors can test the UI and Simulation Mode directly from any browser.

### Steps:
1. **Push your code to GitHub**:
   ```powershell
   cd NetVision
   git init
   git add .
   git commit -m "NetVision production release"
   git branch -M main
   git remote add origin https://github.com/<your-username>/NetVision.git
   git push -u origin main
   ```
2. Go to **[https://share.streamlit.io](https://share.streamlit.io)** and log in with your GitHub account.
3. Click **"New app"**.
4. Configure the deployment settings:
   - **Repository:** `<your-username>/NetVision`
   - **Branch:** `main`
   - **Main file path:** `app.py`
5. Click **"Deploy!"**.
6. Within 2 minutes, your dashboard will be live at a public URL with SSL (`https://...`).
   *(Note: Cloud deployments automatically run in **Simulation Mode** or **Offline PCAP Mode** since cloud containers do not attach to physical campus Wi-Fi).*

---

## Option 3: Containerized Docker Deployment

NetVision includes a multi-stage `Dockerfile` and a `docker-compose.yml` to run the entire stack in isolated containers.

### Single Container Deployment:
```bash
# 1. Build the Docker image
docker build -t netvision:latest .

# 2. Run the container with host port mapping
docker run -d -p 8501:8501 -p 65432:65432 --name netvision-app netvision:latest
```
Access at `http://localhost:8501`.

### Multi-Container Deployment with Docker Compose:
Runs the dashboard and the receiver daemon as two coordinated microservices:
```bash
# Start both Dashboard and Receiver
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

---

## Option 4: Linux Cloud VM Deployment (AWS EC2 / DigitalOcean)

Deploy NetVision on an Ubuntu 22.04 / 24.04 cloud server:

### 1. Connect to VPS via SSH:
```bash
ssh ubuntu@<your-vps-ip>
```

### 2. Install Python & Dependencies:
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv libpcap-dev
git clone https://github.com/<your-username>/NetVision.git
cd NetVision
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run with systemd Service (Production 24/7):
Create a systemd unit file:
```bash
sudo nano /etc/systemd/system/netvision.service
```

Add the following configuration:
```ini
[Unit]
Description=NetVision Network Analyzer Streamlit Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/NetVision
Environment="PATH=/home/ubuntu/NetVision/venv/bin"
Environment="PYTHONPATH=/home/ubuntu/NetVision"
ExecStart=/home/ubuntu/NetVision/venv/bin/streamlit run app.py --server.port 8501 --server.address 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable netvision
sudo systemctl start netvision
```

---

## Option 5: Running as a Persistent Windows Service

If you want the Receiver Daemon on Laptop B to start automatically upon Windows boot:

```powershell
# Create a Windows Scheduled Task running receiver.py silently on startup:
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "network\receiver.py --port 65432" -WorkingDirectory "C:\Users\user\.gemini\antigravity\scratch\NetVision"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "NetVisionReceiver" -Action $action -Trigger $trigger -Description "NetVision TCP Receiver Daemon"
```
