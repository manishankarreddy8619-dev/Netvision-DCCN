"""
NetVision Live Packet Monitor View
Interactive tabular packet stream with dynamic protocol, IP, port, and size filtering,
search capabilities, and deep inspection modal.
"""

import streamlit as st
import pandas as pd


def render_packet_monitor(engine):
    st.markdown("### 📡 Live Packet Stream & Deep Inspector")

    # Filter Toolbar
    with st.expander("🔍 Filter & Search Controls", expanded=True):
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            proto_filter = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP", "DNS (UDP)"], index=0)
        with f_col2:
            src_filter = st.text_input("Source IP", placeholder="e.g. 192.168.1.10")
        with f_col3:
            dst_filter = st.text_input("Destination IP", placeholder="e.g. 192.168.1.25")
        with f_col4:
            port_filter_val = st.number_input("Port (Src or Dst)", min_value=0, max_value=65535, value=0, step=1)

        f_col5, f_col6, f_col7 = st.columns([2, 1, 1])
        with f_col5:
            search_query = st.text_input("Free-Text Search", placeholder="Filter by flag, summary, or keyword...")
        with f_col6:
            min_sz, max_sz = st.slider("Packet Size Range (Bytes)", 0, 15000, (0, 15000), step=50)
        with f_col7:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            b_c1, b_c2 = st.columns(2)
            with b_c1:
                pause_label = "▶ Resume" if engine.is_paused else "⏸ Pause"
                if st.button(pause_label, use_container_width=True):
                    engine.toggle_pause()
                    st.rerun()
            with b_c2:
                if st.button("🗑 Clear", use_container_width=True):
                    engine.clear()
                    st.rerun()

    # Query filtered packets
    port_val = port_filter_val if port_filter_val > 0 else None
    packets = engine.get_packets(
        protocol=proto_filter,
        src_ip=src_filter,
        dst_ip=dst_filter,
        port=port_val,
        min_size=min_sz,
        max_size=max_sz,
        search_query=search_query,
        limit=500
    )

    st.markdown(f"**Displaying {len(packets)} packets** (Buffer capacity: {len(engine.packets)} / {engine.max_packets})")

    if not packets:
        st.info("No packets match current filter criteria or buffer is currently empty.")
        return

    # Convert to DataFrame
    df_display = pd.DataFrame(packets)[[
        "packet_id", "time_formatted", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "packet_size", "tcp_flags", "direction", "summary"
    ]]
    df_display.columns = [
        "ID", "Time", "Src IP", "Src Port", "Dst IP", "Dst Port",
        "Protocol", "Size (B)", "Flags", "Direction", "Summary"
    ]

    st.dataframe(
        df_display,
        use_container_width=True,
        hide_index=True,
        height=400
    )

    # Detailed Packet Inspector
    st.markdown("#### 🔬 Detailed Packet Inspector")
    selected_id = st.number_input(
        "Enter Packet ID to inspect protocol headers:",
        min_value=1,
        max_value=max(p["packet_id"] for p in packets) if packets else 1,
        value=packets[0]["packet_id"] if packets else 1,
        step=1
    )

    # Find packet
    selected_pkt = next((p for p in engine.packets if p.get("packet_id") == selected_id), None)
    if selected_pkt:
        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown(f"""
            - **Packet ID:** `{selected_pkt.get('packet_id')}`
            - **Timestamp:** `{selected_pkt.get('time_formatted')}` ({selected_pkt.get('timestamp')})
            - **Network Interface:** `{selected_pkt.get('interface')}`
            - **Traffic Direction:** `{selected_pkt.get('direction')}`
            - **IP Version:** `IPv{selected_pkt.get('ip_version', 4)}` | **TTL:** `{selected_pkt.get('ttl', 64)}`
            """)
        with d_col2:
            st.markdown(f"""
            - **Protocol:** `{selected_pkt.get('protocol')}`
            - **Source:** `{selected_pkt.get('src_ip')}:{selected_pkt.get('src_port') or 'N/A'}`
            - **Destination:** `{selected_pkt.get('dst_ip')}:{selected_pkt.get('dst_port') or 'N/A'}`
            - **Frame Size:** `{selected_pkt.get('packet_size')} bytes`
            - **TCP Flags:** `{selected_pkt.get('tcp_flags')}`
            """)
        st.markdown(f"**Dissected Header Summary:** `{selected_pkt.get('summary')}`")
    else:
        st.warning(f"Packet ID #{selected_id} is no longer in the active rolling buffer.")
