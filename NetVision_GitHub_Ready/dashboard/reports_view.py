"""
NetVision Report Generation View
Allows users to generate, preview, and download CSV, JSON, and professional
multi-page PDF analysis reports for college project submission and evaluation.
"""

import os
import tempfile
import streamlit as st
from reports.report_generator import export_packets_to_csv, export_analysis_to_json, generate_pdf_report


def render_reports_view(engine):
    st.markdown("### 📑 Telemetry & Forensics Report Generation")
    st.markdown(
        "Generate comprehensive network analysis reports based on captured session measurements. "
        "Export raw packet streams to CSV, structured session metrics to JSON, or generate a formal B.Tech PDF report."
    )

    summary = engine.stats.get_summary()
    proto_dist = engine.stats.get_protocol_distribution()
    size_dist = engine.stats.get_size_distribution()
    alerts = engine.anomaly_detector.get_all_alerts()
    all_packets = list(engine.packets)

    c1, c2, c3 = st.columns(3)

    # 1. CSV Download
    with c1:
        st.markdown("#### 📊 CSV Packet Log")
        st.caption("Raw tabulated packet stream containing timestamps, IPs, ports, and flags.")
        if all_packets:
            csv_data = export_packets_to_csv(all_packets)
            st.download_button(
                label="⬇️ Download Packets (CSV)",
                data=csv_data,
                file_name=f"NetVision_Packets_{engine.capture_mode}.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.button("CSV (No Packets)", disabled=True, use_container_width=True)

    # 2. JSON Download
    with c2:
        st.markdown("#### 🗄️ JSON Telemetry")
        st.caption("Hierarchical JSON structure containing aggregate metrics, anomaly alerts, and distributions.")
        if summary.get("total_packets", 0) > 0:
            json_data = export_analysis_to_json(summary, proto_dist, size_dist, alerts, all_packets)
            st.download_button(
                label="⬇️ Download Telemetry (JSON)",
                data=json_data,
                file_name=f"NetVision_Session_{engine.capture_mode}.json",
                mime="application/json",
                use_container_width=True
            )
        else:
            st.button("JSON (No Packets)", disabled=True, use_container_width=True)

    # 3. PDF Academic Report
    with c3:
        st.markdown("#### 📄 Executive PDF Report")
        st.caption("Formatted multi-page forensic report with tables, protocol breakdowns, and conclusions.")
        if summary.get("total_packets", 0) > 0:
            if st.button("📝 Compile PDF Report", use_container_width=True):
                with st.spinner("Compiling academic PDF document via ReportLab..."):
                    pdf_tmp = os.path.join(tempfile.gettempdir(), f"NetVision_Report_{engine.capture_mode}.pdf")
                    generate_pdf_report(
                        summary=summary,
                        protocol_dist=proto_dist,
                        size_dist=size_dist,
                        alerts=alerts,
                        capture_mode=engine.capture_mode,
                        output_path=pdf_tmp
                    )
                    with open(pdf_tmp, "rb") as f:
                        pdf_bytes = f.read()

                    st.download_button(
                        label="⬇️ Download Report (PDF)",
                        data=pdf_bytes,
                        file_name=f"NetVision_Forensic_Report_{engine.capture_mode}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
        else:
            st.button("PDF (No Packets)", disabled=True, use_container_width=True)

    st.markdown("---")
    st.markdown("##### 📌 Report Summary Preview")
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
    with p2:
        st.metric("Total Volume", f"{summary.get('total_bytes', 0):,} B")
    with p3:
        st.metric("Duration", f"{summary.get('capture_duration_seconds', 0)}s")
    with p4:
        st.metric("Anomalies Flagged", len(alerts))

    st.markdown("""
    > [!NOTE]
    > **Academic Assessment Transparency**:
    > All metrics generated in exported reports represent empirical measurements captured during the active session.
    > When operating in Simulation Mode, the report clearly identifies the dataset as synthetic demonstration data.
    """)
