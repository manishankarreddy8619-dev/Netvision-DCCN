"""
NetVision - Real-Time Network Packet Sniffer & Intelligent Traffic Analyzer
Main Streamlit Application Entrypoint.
"""

import os
import sys
import time
import tempfile
from pathlib import Path
import streamlit as st

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from network.packet_sniffer import PacketSnifferEngine
from dashboard.styles import CYBER_THEME_CSS, render_header
from dashboard.overview import render_overview
from dashboard.packet_monitor import render_packet_monitor
from dashboard.analytics import render_analytics
from dashboard.file_transfer_view import render_file_transfer
from dashboard.alerts import render_alerts
from dashboard.reports_view import render_reports_view

# Page Config
st.set_page_config(
    page_title="NetVision — Real-Time Packet Sniffer & Analyzer",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Dark Cybersecurity Theme
st.markdown(CYBER_THEME_CSS, unsafe_allow_html=True)

# Initialize Engine in session_state
if "engine" not in st.session_state:
    engine = PacketSnifferEngine()
    # Default to simulation mode with 12 packets/sec for immediate demonstration
    engine.start_simulation(traffic_rate=12, inject_anomalies=True)
    st.session_state.engine = engine

engine: PacketSnifferEngine = st.session_state.engine

# Top Banner
st.markdown(
    render_header(
        capture_mode=engine.capture_mode,
        status_msg=engine.status_message,
        is_capturing=engine.is_capturing
    ),
    unsafe_allow_html=True
)

if engine.error_message:
    st.error(f"⚠️ {engine.error_message}")

# Sidebar Controls
with st.sidebar:
    st.markdown("### 🎛️ NetVision Engine Controls")

    # Mode Selector
    mode_choice = st.radio(
        "Capture Mode",
        [
            "⚡ Simulation Mode (Demo / Zero-Privilege)",
            "📡 Live Capture (Npcap / Scapy)",
            "📁 Offline PCAP Analysis"
        ],
        index=0 if engine.capture_mode == "simulation" else (1 if engine.capture_mode == "live" else 2)
    )

    st.markdown("---")

    # Mode specific options
    if "Live Capture" in mode_choice:
        interfaces = engine.get_interfaces()
        selected_iface = st.selectbox("Select Network Interface", interfaces)
        bpf_filter = st.text_input("BPF Filter (e.g. 'tcp port 65432')", value="")

        c_start, c_stop = st.columns(2)
        with c_start:
            if st.button("▶ Start Capture", disabled=engine.is_capturing, use_container_width=True):
                success = engine.start_live_capture(interface=selected_iface, bpf_filter=bpf_filter)
                st.rerun()
        with c_stop:
            if st.button("⏹ Stop Capture", disabled=not engine.is_capturing, use_container_width=True):
                engine.stop_capture()
                st.rerun()

    elif "Simulation Mode" in mode_choice:
        sim_rate = st.slider("Traffic Generation Rate (pkts/sec)", 2, 50, 15)
        inject_anomalies = st.checkbox("Inject Periodic Anomalies", value=True)

        c_start, c_stop = st.columns(2)
        with c_start:
            if st.button("▶ Start Sim", disabled=engine.is_capturing, use_container_width=True):
                engine.start_simulation(traffic_rate=sim_rate, inject_anomalies=inject_anomalies)
                st.rerun()
        with c_stop:
            if st.button("⏹ Stop Sim", disabled=not engine.is_capturing, use_container_width=True):
                engine.stop_capture()
                st.rerun()

    elif "Offline PCAP" in mode_choice:
        uploaded_pcap = st.file_uploader("Upload .pcap or .pcapng file", type=["pcap", "pcapng"])
        if uploaded_pcap is not None:
            if st.button("📂 Parse PCAP File", use_container_width=True):
                temp_pcap = os.path.join(tempfile.gettempdir(), uploaded_pcap.name)
                with open(temp_pcap, "wb") as f:
                    f.write(uploaded_pcap.getbuffer())
                try:
                    count = engine.load_pcap_file(temp_pcap)
                    st.success(f"Loaded {count} packets successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to parse PCAP: {e}")
                finally:
                    if os.path.exists(temp_pcap):
                        try:
                            os.remove(temp_pcap)
                        except Exception:
                            pass

        sample_pcap_path = os.path.join(os.path.dirname(__file__), "data", "sample_data", "sample_traffic.pcap")
        if os.path.exists(sample_pcap_path):
            if st.button("🧪 Load Built-In Sample PCAP", use_container_width=True):
                count = engine.load_pcap_file(sample_pcap_path)
                st.success(f"Loaded {count} sample packets!")
                st.rerun()

    st.markdown("---")

    # Global Engine Buffer Controls
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if st.button("🗑 Reset Buffer", use_container_width=True):
            engine.clear()
            st.rerun()
    with col_c2:
        auto_refresh = st.checkbox("Live UI Sync", value=True)

    st.markdown("---")

    # Navigation Menu
    nav_selection = st.radio(
        "Navigation",
        [
            "📊 Overview",
            "📡 Live Packet Monitor",
            "📈 Network Analytics",
            "📁 File & Message Transfer",
            "🚨 Anomaly Alerts",
            "📑 Reports & Export"
        ],
        index=0
    )

    st.markdown("---")
    st.caption("NetVision v1.0.0 — DCCN B.Tech Mini-Project")

# Page Routing
if nav_selection == "📊 Overview":
    render_overview(engine)
elif nav_selection == "📡 Live Packet Monitor":
    render_packet_monitor(engine)
elif nav_selection == "📈 Network Analytics":
    render_analytics(engine)
elif nav_selection == "📁 File & Message Transfer":
    render_file_transfer(engine)
elif nav_selection == "🚨 Anomaly Alerts":
    render_alerts(engine)
elif nav_selection == "📑 Reports & Export":
    render_reports_view(engine)

# Optional live auto-refresh if capture is active
if auto_refresh and engine.is_capturing and not engine.is_paused:
    time.sleep(1.0)
    st.rerun()
