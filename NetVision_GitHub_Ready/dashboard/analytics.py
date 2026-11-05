"""
NetVision Network Analytics View
Comprehensive telemetry charts, protocol breakdowns, bandwidth timelines,
and TCP connection state analysis.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def render_analytics(engine):
    st.markdown("### 📈 Comprehensive Network Analytics")

    # Time series data
    ts_data = engine.stats.get_time_series_data()

    # Row 1: Throughput and Packet Rate over time
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        st.markdown("##### ⚡ Packets Per Second (PPS)")
        if ts_data["seconds"]:
            fig_pps = go.Figure()
            fig_pps.add_trace(go.Scatter(
                x=ts_data["seconds"],
                y=ts_data["pps"],
                mode="lines",
                line=dict(color="#00f0ff", width=2.5),
                name="PPS"
            ))
            fig_pps.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(title="Elapsed Seconds", gridcolor="#1e293b"),
                yaxis=dict(title="Packets/s", gridcolor="#1e293b"),
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_pps, use_container_width=True)
        else:
            st.info("No time series data available yet.")

    with col_t2:
        st.markdown("##### 🌊 Bandwidth Rate (KB / Second)")
        if ts_data["seconds"]:
            fig_kbps = go.Figure()
            fig_kbps.add_trace(go.Scatter(
                x=ts_data["seconds"],
                y=ts_data["kbps"],
                mode="lines",
                line=dict(color="#38bdf8", width=2.5),
                name="KB/s",
                fill="tozeroy",
                fillcolor="rgba(56, 189, 248, 0.15)"
            ))
            fig_kbps.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(title="Elapsed Seconds", gridcolor="#1e293b"),
                yaxis=dict(title="KB/s", gridcolor="#1e293b"),
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_kbps, use_container_width=True)
        else:
            st.info("No bandwidth metrics available yet.")

    # Row 2: Packet Size Distribution & TCP Flags
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        st.markdown("##### 📦 Packet Size Distribution (MTU Profile)")
        size_dist = engine.stats.get_size_distribution()
        if any(v > 0 for v in size_dist.values()):
            df_size = pd.DataFrame(list(size_dist.items()), columns=["Bin", "Count"])
            fig_size = px.bar(
                df_size,
                x="Bin",
                y="Count",
                text="Count",
                color="Count",
                color_continuous_scale="Viridis"
            )
            fig_size.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(title="Size Range", gridcolor="#1e293b"),
                yaxis=dict(title="Packet Count", gridcolor="#1e293b"),
                coloraxis_showscale=False,
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_size, use_container_width=True)
        else:
            st.info("Awaiting packets to calculate size histogram.")

    with col_c2:
        st.markdown("##### 🚩 TCP Flags Breakdown")
        flags_dist = engine.stats.get_tcp_flags_distribution()
        if flags_dist:
            df_flags = pd.DataFrame(list(flags_dist.items()), columns=["Flag", "Count"]).sort_values("Count", ascending=False)
            fig_flags = px.bar(
                df_flags,
                x="Flag",
                y="Count",
                text="Count",
                color="Flag",
                color_discrete_sequence=["#0284c7", "#0ea5e9", "#38bdf8", "#00f0ff", "#a855f7", "#ec4899"]
            )
            fig_flags.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                xaxis=dict(title="TCP Control Flag", gridcolor="#1e293b"),
                yaxis=dict(title="Observed Count", gridcolor="#1e293b"),
                showlegend=False,
                margin=dict(t=10, b=10, l=10, r=10),
                height=260
            )
            st.plotly_chart(fig_flags, use_container_width=True)
        else:
            st.info("No TCP flags detected yet.")

    # Row 3: Top Communicating Endpoints
    st.markdown("##### 👥 Top Communicating IP Endpoints")
    top_talkers = engine.stats.get_top_talkers(limit=6)
    if top_talkers:
        df_talkers = pd.DataFrame(top_talkers, columns=["IP Address", "Total Packets"])
        fig_talkers = px.bar(
            df_talkers,
            x="Total Packets",
            y="IP Address",
            orientation="h",
            text="Total Packets",
            color="Total Packets",
            color_continuous_scale="Blues"
        )
        fig_talkers.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8"),
            xaxis=dict(gridcolor="#1e293b"),
            yaxis=dict(categoryorder="total ascending", gridcolor="#1e293b"),
            coloraxis_showscale=False,
            margin=dict(t=10, b=10, l=10, r=10),
            height=240
        )
        st.plotly_chart(fig_talkers, use_container_width=True)
    else:
        st.info("No endpoint communications recorded.")

    # Row 4: TCP 3-Way Handshake & State Tracking
    st.markdown("---")
    st.markdown("##### 🤝 TCP Three-Way Handshake Records & Connection Latency")
    handshakes = engine.protocol_analyzer.get_handshake_records()
    if handshakes:
        df_hs = pd.DataFrame(handshakes)[["client", "server", "latency_ms", "summary"]]
        df_hs.columns = ["Client Socket", "Server Socket", "Handshake RTT (ms)", "Handshake Summary"]
        st.dataframe(df_hs, use_container_width=True, hide_index=True)
    else:
        st.info("No completed TCP 3-way handshakes captured yet. Initiate a file transfer or run simulation to observe handshakes.")
