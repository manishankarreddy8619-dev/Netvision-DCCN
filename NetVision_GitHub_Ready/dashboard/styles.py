"""
NetVision UI Styling & Theme Assets
Provides a sleek, cybersecurity-inspired dark navy and cyan styling for Streamlit.
"""

CYBER_THEME_CSS = """
<style>
/* Main app dark navy styling */
.stApp {
    background-color: #0b0f19;
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background-color: #070d18 !important;
    border-right: 1px solid #1e293b;
}

/* Top App Header / Banner */
.netvision-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0c4a6e 100%);
    border: 1px solid #0284c7;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(2, 132, 199, 0.15);
}

.netvision-title {
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(90deg, #38bdf8 0%, #00f0ff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
}

.netvision-subtitle {
    font-size: 1.05rem;
    color: #94a3b8;
    margin-top: 4px;
    font-weight: 400;
}

/* Metric KPI Cards */
.kpi-card {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-top: 3px solid #0284c7;
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.kpi-card:hover {
    transform: translateY(-2px);
    border-top-color: #00f0ff;
    box-shadow: 0 6px 12px rgba(0, 240, 255, 0.1);
}

.kpi-title {
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #94a3b8;
    font-weight: 600;
    margin-bottom: 6px;
}

.kpi-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.2;
}

.kpi-sub {
    font-size: 0.78rem;
    color: #64748b;
    margin-top: 4px;
}

/* Status Badges */
.badge-live {
    background-color: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border: 1px solid #10b981;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.badge-sim {
    background-color: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid #38bdf8;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.badge-pcap {
    background-color: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border: 1px solid #f59e0b;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

/* Alert Severity Badges */
.severity-high {
    background-color: rgba(239, 68, 68, 0.2);
    color: #f87171;
    border: 1px solid #ef4444;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
}

.severity-med {
    background-color: rgba(245, 158, 11, 0.2);
    color: #fbbf24;
    border: 1px solid #f59e0b;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
}

.severity-low {
    background-color: rgba(14, 165, 233, 0.2);
    color: #38bdf8;
    border: 1px solid #0ea5e9;
    padding: 2px 8px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.75rem;
}

/* Buttons */
.stButton>button {
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.2s ease;
}

/* Alert Card */
.alert-box {
    background-color: #161e2e;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 12px;
}
</style>
"""


def render_header(capture_mode: str, status_msg: str, is_capturing: bool):
    """Renders the top title banner with active capture status."""
    if capture_mode == "live":
        badge_html = '<span class="badge-live">● LIVE CAPTURE</span>'
    elif capture_mode == "pcap":
        badge_html = '<span class="badge-pcap">📁 PCAP OFFLINE</span>'
    else:
        badge_html = '<span class="badge-sim">⚡ SIMULATION MODE</span>'

    state_desc = "Capturing Active" if is_capturing else "Engine Idle"

    html = f"""
    <div class="netvision-header">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
                <h1 class="netvision-title">NetVision</h1>
                <div class="netvision-subtitle">Real-Time Network Packet Sniffer & Intelligent Traffic Analyzer</div>
            </div>
            <div style="text-align: right;">
                {badge_html}
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 5px;">
                    <b>State:</b> {state_desc} | {status_msg}
                </div>
            </div>
        </div>
    </div>
    """
    return html


def render_kpi(title: str, value: str, subtext: str = "", border_color: str = "#0284c7") -> str:
    """Helper to render an individual cybersecurity KPI card."""
    return f"""
    <div class="kpi-card" style="border-top-color: {border_color};">
        <div class="kpi-title">{title}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-sub">{subtext}</div>
    </div>
    """
