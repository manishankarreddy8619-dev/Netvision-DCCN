"""
NetVision Overview Dashboard View
High-level operational metrics, protocol breakdown preview, and network topology overview.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from dashboard.styles import render_kpi
from network.file_transfer import format_bytes


def render_overview(engine):
    st.markdown("### 📊 Operational Overview & Telemetry")

    summary = engine.stats.get_summary()
    total_pkts = summary.get("total_packets", 0)
    total_bytes = summary.get("total_bytes", 0)
    avg_size = summary.get("avg_packet_size", 0.0)
    duration = summary.get("capture_duration_seconds", 0.0)
    pps = summary.get("avg_packets_per_sec", 0.0)

    # 1. KPI Metric Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(render_kpi("Total Captured Packets", f"{total_pkts:,}", f"{duration:.1f}s elapsed", "#38bdf8"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi("Network Volume", format_bytes(total_bytes), f"{pps:.1f} pkts/sec", "#00f0ff"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi("TCP Protocols", f"{summary.get('tcp_count', 0):,}", "Reliable stream transport", "#3b82f6"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi("UDP & ICMP", f"{summary.get('udp_count', 0) + summary.get('icmp_count', 0):,}", f"UDP: {summary.get('udp_count', 0)} | ICMP: {summary.get('icmp_count', 0)}", "#a855f7"), unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    # 2. Charts Preview Row
    col_chart1, col_chart2 = st.columns([1, 1])

    with col_chart1:
        st.markdown("##### 🥧 Protocol Distribution")
        proto_dist = engine.stats.get_protocol_distribution()
        if proto_dist:
            labels = list(proto_dist.keys())
            values = list(proto_dist.values())
            fig_pie = px.pie(
                names=labels,
                values=values,
                hole=0.45,
                color_discrete_sequence=["#00f0ff", "#38bdf8", "#3b82f6", "#818cf8", "#c084fc"]
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                margin=dict(t=10, b=10, l=10, r=10),
                height=260,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No packets captured yet. Start capture or simulation to view charts.")

    with col_chart2:
        st.markdown("##### 📈 Traffic Activity (Packets / Second)")
        ts_data = engine.stats.get_time_series_data()
        if ts_data["seconds"]:
            fig_line = go.Figure()
            fig_line.add_trace(go.Scatter(
                x=ts_data["seconds"],
                y=ts_data["pps"],
                mode="lines+markers",
                name="Packets/s",
                line=dict(color="#00f0ff", width=2),
                fill="tozeroy",
                fillcolor="rgba(0, 240, 255, 0.1)"
            ))
            fig_line.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(title="Relative Time (seconds)", gridcolor="#1e293b"),
                yaxis=dict(title="Packets/s", gridcolor="#1e293b"),
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("Awaiting traffic telemetry to plot time-series rate.")

    # 3. Hardware Architecture & DCCN Academic Banner
    st.markdown("---")
    st.markdown("##### 🌐 DCCN Multi-Laptop Hardware Architecture")
    c_arch1, c_arch2 = st.columns([2, 1])
    with c_arch1:
        st.markdown("""
        ```
        +----------------------------+             Wi-Fi Access Point / Router            +----------------------------+
        |   LAPTOP A (Sender Node)   | <------------------------------------------------> |  LAPTOP B (Receiver Node)  |
        |  * NetVision Sniffer       |                    192.168.1.1                     |  * NetVision Server Daemon |
        |  * Interactive Dashboard   |                                                    |  * Port 65432 Listener     |
        |  * Packet Telemetry & File |          (Direct Unicast TCP Stream)               |  * SHA-256 Hash Verifier   |
        +----------------------------+                                                    +----------------------------+
        ```
        """)
    with c_arch2:
        st.markdown("""
        **Operational Node Roles:**
        - **Laptop A:** Runs the interactive NetVision dashboard, initiates file transfers, sniffs local NIC packets.
        - **Laptop B:** Runs the lightweight `receiver.py` socket daemon to accept files and send ACK responses.
        - **Wi-Fi Switched Topology:** Standard access points isolate unicast frames between stations; promiscuous sniffing on a 3rd laptop requires port mirroring or an active TAP.
        """)
