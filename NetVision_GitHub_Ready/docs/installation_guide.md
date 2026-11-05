# NetVision — Windows 11 Installation & Setup Guide

This guide walks you through setting up **NetVision** on Windows 11 using VS Code and PowerShell.

---

## 1. Prerequisites

1. **Operating System:** Windows 10 or Windows 11 (64-bit).
2. **Python:** Python 3.12 or newer (Ensure "Add python.exe to PATH" is checked during installation).
3. **IDE:** Visual Studio Code (Recommended).
4. **Network:** Two Windows laptops connected to the same Wi-Fi network (or mobile hotspot).

---

## 2. Installing Npcap (For Live Packet Sniffing)

Live network packet capture on Windows requires the **Npcap** packet capture driver.

1. Download the official installer from: [https://npcap.com/#download](https://npcap.com/#download)
2. Run the `npcap-x.xx.exe` installer with Administrator privileges.
3. **CRITICAL STEP:** During setup, ensure you **check**:
   - `[x] Install Npcap in WinPcap API-compatible Mode`
   - `[x] Support raw 802.11 traffic (and monitor mode) for wireless adapters`
4. Complete installation and restart your terminal.

> **Note on Zero-Privilege Simulation Mode:**
> If you do not have Administrator permissions to install Npcap on a college lab computer, NetVision features a built-in **Simulation Mode** that runs 100% without Npcap or admin rights!

---

## 3. Setting Up the Project in VS Code

Open PowerShell in the project directory:

```powershell
# 1. Navigate to project root
cd C:\Users\user\.gemini\antigravity\scratch\NetVision

# 2. Create a Python Virtual Environment
python -m venv venv

# 3. Activate the Virtual Environment
.\venv\Scripts\Activate.ps1

# If PowerShell blocks script execution, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install all required dependencies
pip install -r requirements.txt
```

---

## 4. Configuring Windows Firewall

To allow Laptop A and Laptop B to communicate over port `65432` and `8501`, run PowerShell as **Administrator** on both laptops:

```powershell
# Allow inbound TCP connections on NetVision Transfer Port (65432)
New-NetFirewallRule -DisplayName "NetVision TCP Transfer" -Direction Inbound -LocalPort 65432 -Protocol TCP -Action Allow

# Allow inbound TCP connections on Streamlit Web UI (8501)
New-NetFirewallRule -DisplayName "NetVision Streamlit UI" -Direction Inbound -LocalPort 8501 -Protocol TCP -Action Allow
```

To remove these rules after your college demonstration:
```powershell
Remove-NetFirewallRule -DisplayName "NetVision TCP Transfer"
Remove-NetFirewallRule -DisplayName "NetVision Streamlit UI"
```

---

## 5. Verifying the Installation

Run the automated test suite to verify all modules:

```powershell
$env:PYTHONPATH="."
python -m pytest tests -v
```

All 16 test cases should pass.

---

## 6. Launching NetVision

To start the interactive dashboard:

```powershell
python -m streamlit run app.py
```

The web browser will automatically open to `http://localhost:8501`.
