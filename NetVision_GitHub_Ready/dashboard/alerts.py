"""
NetVision Alerts & Anomaly Detection View
Displays detected network anomalies, severity classifications, and investigative advice.
Includes interactive triggers to safely demonstrate anomaly detection in viva sessions.
"""

import streamlit as st
import pandas as pd


def render_alerts(engine):
    st.markdown("### 🚨 Network Anomaly & Security Intelligence")
    st.markdown(
        "NetVision monitors network streams in real time using multi-point behavioral heuristics. "
        "Flags potential port sweeps, SYN flood indicators, and sudden traffic spikes."
    )

    # Threshold configuration expander
    with st.expander("⚙️ Detection Threshold Configuration", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            pps_th = st.number_input("Max PPS Threshold", 50, 2000, engine.anomaly_detector.pps_threshold, step=25)
        with c2:
            syn_th = st.number_input("SYN Burst Threshold", 5, 200, engine.anomaly_detector.syn_burst_threshold, step=5)
        with c3:
            scan_th = st.number_input("Port Scan Threshold", 3, 50, engine.anomaly_detector.port_scan_threshold, step=1)
        with c4:
            spike_mul = st.number_input("Spike Multiplier", 1.5, 10.0, float(engine.anomaly_detector.spike_multiplier), step=0.5)

        if st.button("Apply Thresholds"):
            engine.anomaly_detector.set_thresholds(
                pps_threshold=pps_th,
                syn_burst_threshold=syn_th,
                port_scan_threshold=scan_th,
                spike_multiplier=spike_mul
            )
            st.success("Anomaly detection thresholds updated!")

    # Live Demonstration Anomaly Injection Box
    st.markdown("#### 🧪 Classroom Demonstration: Safe Anomaly Injections")
    st.caption("Click any button below to inject a safe, labeled synthetic pattern and observe real-time detection.")
    s_col1, s_col2, s_col3 = st.columns(3)
    with s_col1:
        if st.button("⚡ Inject Port Scan (10 Ports)", use_container_width=True):
            engine.trigger_anomaly_simulation("port_scan")
            st.toast("Injected simulated TCP port scan pattern.")
            st.rerun()
    with s_col2:
        if st.button("🌊 Inject SYN Burst (35 Packets)", use_container_width=True):
            engine.trigger_anomaly_simulation("syn_flood")
            st.toast("Injected simulated SYN burst pattern.")
            st.rerun()
    with s_col3:
        if st.button("💥 Inject Traffic Spike (160 Frames)", use_container_width=True):
            engine.trigger_anomaly_simulation("traffic_spike")
            st.toast("Injected simulated throughput surge.")
            st.rerun()

    st.markdown("---")

    # Display Alerts
    alerts = engine.anomaly_detector.get_all_alerts()
    summary = engine.anomaly_detector.get_alert_summary()

    # Alert Metrics Bar
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Alerts", summary.get("total_alerts", 0))
    with m2:
        st.metric("High Severity", summary["severity_breakdown"].get("High", 0))
    with m3:
        st.metric("Medium Severity", summary["severity_breakdown"].get("Medium", 0))
    with m4:
        st.metric("Low Severity", summary["severity_breakdown"].get("Low", 0))

    if not alerts:
        st.info("✅ No unusual network traffic detected. Network metrics are operating normally within baseline thresholds.")
        return

    st.markdown("##### 📋 Observed Anomaly Event Log")
    for a in reversed(alerts):
        sev = a.get("severity", "Medium")
        sev_class = "severity-high" if sev == "High" else ("severity-med" if sev == "Medium" else "severity-low")

        st.markdown(f"""
        <div class="alert-box">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-size: 1.05rem; font-weight: 700; color: #f1f5f9;">
                    ⚠️ {a.get('category')}
                </span>
                <div>
                    <span class="{sev_class}">{sev.upper()}</span>
                    <span style="color: #94a3b8; font-size: 0.8rem; margin-left: 8px;">{a.get('time_formatted')}</span>
                </div>
            </div>
            <div style="font-size: 0.9rem; color: #cbd5e1; margin-bottom: 4px;">
                <b>Evidence:</b> {a.get('observed_evidence')}
            </div>
            <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 4px;">
                <b>Explanation:</b> {a.get('explanation')}
            </div>
            <div style="font-size: 0.85rem; color: #38bdf8;">
                <b>Recommended Investigation:</b> {a.get('recommended_investigation')}
            </div>
        </div>
        """, unsafe_allow_html=True)
