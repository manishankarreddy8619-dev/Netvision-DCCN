"""
NetVision File & Message Transfer View
Interactive interface for Laptop A <-> Laptop B communication,
measuring transfer speed, verifying SHA-256 integrity, and inspecting transfer logs.
"""

import os
import tempfile
import time
import streamlit as st
import pandas as pd
from network.sender import SenderClient
from network.receiver import ReceiverServer
from network.file_transfer import format_bytes, format_speed


def render_file_transfer(engine):
    st.markdown("### 📁 Multi-Laptop File & Message Transfer Monitor")
    st.markdown(
        "Establish direct TCP client-server connections between laptops over local Wi-Fi. "
        "Test reliable stream delivery, calculate transfer speeds, and confirm cryptographic SHA-256 integrity."
    )

    # Initialize session state transfer logs if not present
    if "transfer_records" not in st.session_state:
        st.session_state.transfer_records = []
    if "local_receiver_server" not in st.session_state:
        st.session_state.local_receiver_server = None

    # Receiver Daemon Control Box
    with st.expander("📡 Laptop B: Local Receiver Daemon Controls", expanded=False):
        r_col1, r_col2, r_col3 = st.columns([2, 1, 1])
        with r_col1:
            recv_port = st.number_input("Receiver Listen Port", min_value=1024, max_value=65535, value=65432, step=1)
        with r_col2:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            srv = st.session_state.local_receiver_server
            is_srv_running = srv is not None and srv.is_running
            if not is_srv_running:
                if st.button("🚀 Start Local Receiver", use_container_width=True):
                    try:
                        new_srv = ReceiverServer(host="0.0.0.0", port=recv_port)
                        new_srv.start()
                        st.session_state.local_receiver_server = new_srv
                        st.success(f"Receiver listening on port {recv_port}!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to start receiver: {e}")
            else:
                if st.button("⏹ Stop Local Receiver", use_container_width=True):
                    srv.stop()
                    st.session_state.local_receiver_server = None
                    st.warning("Receiver stopped.")
                    st.rerun()
        with r_col3:
            srv = st.session_state.local_receiver_server
            srv_status = "🟢 ACTIVE" if (srv and srv.is_running) else "⚪ STOPPED"
            st.markdown(f"<div style='margin-top: 34px;'><b>Status:</b> {srv_status}</div>", unsafe_allow_html=True)

    # Sender Controls
    st.markdown("#### 📤 Laptop A: Outbound Transmission Controls")
    c_tgt1, c_tgt2, c_tgt3 = st.columns([2, 1, 1])
    with c_tgt1:
        target_ip = st.text_input("Target Laptop IP Address", value="127.0.0.1", help="Enter IPv4 address of Laptop B on the local Wi-Fi")
    with c_tgt2:
        target_port = st.number_input("Target Port", min_value=1024, max_value=65535, value=65432, step=1)
    with c_tgt3:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🔌 Ping / Test Link", use_container_width=True):
            try:
                client = SenderClient(target_host=target_ip, target_port=target_port, timeout=5.0)
                res = client.test_connection()
                st.success(f"Connection OK! RTT: {res['rtt_ms']} ms")
            except Exception as e:
                st.error(f"Link failed: {e}")

    tab_msg, tab_file = st.tabs(["💬 Send Text Message", "📁 Send Binary File"])

    with tab_msg:
        msg_text = st.text_area("Message Payload", value="Hello Laptop B! Testing NetVision TCP framing and socket stream.")
        if st.button("🚀 Transmit Message", key="btn_send_msg"):
            if not msg_text.strip():
                st.warning("Please enter a message to send.")
            else:
                try:
                    with st.spinner("Transmitting message frame..."):
                        client = SenderClient(target_host=target_ip, target_port=target_port)
                        res = client.send_message(msg_text)
                        st.success(f"Message delivered! Ack: {res['ack']['message']} (Elapsed: {res['duration_seconds']}s)")
                        st.session_state.transfer_records.append({
                            "Type": "Text Message",
                            "Filename": "N/A",
                            "Size": format_bytes(res["bytes_sent"]),
                            "Target": f"{target_ip}:{target_port}",
                            "Duration": f"{res['duration_seconds']}s",
                            "Speed": "N/A",
                            "SHA-256 Match": "N/A",
                            "Status": "Delivered"
                        })
                except Exception as e:
                    st.error(f"Transmission failed: {e}")

    with tab_file:
        uploaded_file = st.file_uploader("Select File to Transfer", type=None)
        if uploaded_file is not None:
            st.info(f"Selected file: **{uploaded_file.name}** ({format_bytes(uploaded_file.size)})")
            if st.button("🚀 Upload & Stream File", key="btn_send_file"):
                # Save temporarily
                temp_dir = tempfile.gettempdir()
                temp_path = os.path.join(temp_dir, uploaded_file.name)
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                try:
                    progress_bar = st.progress(0.0)
                    speed_display = st.empty()

                    def on_progress(cur, tot, speed_bps):
                        pct = min(cur / max(tot, 1), 1.0)
                        progress_bar.progress(pct)
                        speed_display.markdown(f"**Transferred:** {format_bytes(cur)} / {format_bytes(tot)} ({format_speed(cur, cur/max(speed_bps, 0.001))})")

                    client = SenderClient(target_host=target_ip, target_port=target_port)
                    res = client.send_file(temp_path, progress_callback=on_progress)

                    progress_bar.progress(1.0)
                    st.success(
                        f"File '{res['filename']}' transferred successfully! "
                        f"Speed: {res['speed']} | Duration: {res['duration_seconds']}s | "
                        f"SHA-256 Verified: {res['integrity_verified']}"
                    )

                    with st.expander("🔒 SHA-256 Cryptographic Verification Details"):
                        st.code(f"Sender Hash   : {res['local_sha256']}\nReceiver Hash : {res['remote_sha256']}\nIntegrity Pass: {res['integrity_verified']}")

                    st.session_state.transfer_records.append({
                        "Type": "File Transfer",
                        "Filename": res["filename"],
                        "Size": res["file_size_formatted"],
                        "Target": f"{target_ip}:{target_port}",
                        "Duration": f"{res['duration_seconds']}s",
                        "Speed": res["speed"],
                        "SHA-256 Match": "✅ Matched" if res["integrity_verified"] else "❌ Mismatch",
                        "Status": "Completed" if res["integrity_verified"] else "Corrupted"
                    })

                except Exception as e:
                    st.error(f"File transfer failed: {e}")
                finally:
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass

    # Transfer History Table
    st.markdown("---")
    st.markdown("##### 📜 Session File & Message Transfer Log")
    if st.session_state.transfer_records:
        df_trans = pd.DataFrame(st.session_state.transfer_records)
        st.dataframe(df_trans, use_container_width=True, hide_index=True)
    else:
        st.info("No transfers performed in this session yet.")
