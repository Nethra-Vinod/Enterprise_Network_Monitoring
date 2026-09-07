
import streamlit as st
import plotly.graph_objects as go
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
import subprocess
import csv
import io
import time
import sys
import os
import re
import importlib.util
from PIL import Image

wireshark_path = r"C:\Program Files\Wireshark"
if wireshark_path not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + wireshark_path

# ============================================================
# TECHNOVA SOLUTIONS — ENTERPRISE NETWORK MONITOR
#
# OFFLINE:
#   ONE source of truth: src/analysis/unified_analysis.py
#
# LIVE:
#   Direct TShark capture from the selected interface.
#
# TOPOLOGY:
#   Static Cisco Packet Tracer enterprise design.
# ============================================================

st.set_page_config(
    page_title="TechNova | Enterprise Network Monitor",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_DIR = PROJECT_ROOT / "src" / "analysis"
UNIFIED_FILE = ANALYSIS_DIR / "unified_analysis.py"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.live_monitor import LiveMonitor


def load_unified_analysis():
    """Load exactly src/analysis/unified_analysis.py."""
    if not UNIFIED_FILE.exists():
        raise FileNotFoundError(
            f"unified_analysis.py was not found at:\n{UNIFIED_FILE}"
        )

    if str(ANALYSIS_DIR) not in sys.path:
        sys.path.insert(0, str(ANALYSIS_DIR))

    spec = importlib.util.spec_from_file_location(
        "technova_unified_analysis",
        str(UNIFIED_FILE),
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            f"Could not create import specification for {UNIFIED_FILE}"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "analyze_all"):
        raise AttributeError(
            "unified_analysis.py does not provide analyze_all()."
        )

    return module


try:
    unified_analysis = load_unified_analysis()
except Exception as exc:
    st.error("Unable to load the unified analysis engine.")
    st.code(str(exc))
    st.info(
        "Make sure src/analysis/unified_analysis.py exists "
        "and contains analyze_all()."
    )
    st.stop()


# ============================================================
# THEME
# ============================================================

TEAL = "#147C80"
TEAL_DARK = "#0D6669"
GREEN = "#18805C"
AMBER = "#B7791F"
RED = "#C4473F"
PURPLE = "#7064A8"
BLUE = "#397A9C"
TEXT = "#1D2824"
MUTED = "#7B8782"
LINE = "#E6EBE8"
BG = "#0F1720"
PANEL = "#F0F4F2"
WHITE = "#FFFFFF"


# ============================================================
# SESSION STATE
# ============================================================

# Initialized below with the preferred live capture interface.

# ============================================================
# CSS
# ============================================================

st.markdown(
    f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {{
    font-family: Inter, sans-serif;
    font-size: 100%;
}}

.stApp {{
    background: linear-gradient(180deg, #0d1419 0%, #0b1218 100%) !important;
    color: {TEXT} !important;
    color-scheme: light !important;
}}

#MainMenu, footer {{
    visibility: hidden;
}}

header[data-testid="stHeader"] {{
    background: transparent;
}}

.block-container {{
    max-width: 1480px;
    padding-top: 1rem;
    padding-bottom: 2rem;
    padding-left: 1.25rem;
    padding-right: 1.25rem;
    background: {PANEL};
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 18px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.18);
}}

section[data-testid="stSidebar"] {{
    background: #F5F3EF;
    border-right: 1px solid {LINE};
    min-width: 255px !important;
    max-width: 255px !important;
    border-radius: 18px 0 0 18px;
    margin-left: 8px;
    margin-top: 8px;
    margin-bottom: 8px;
}}

section[data-testid="stSidebar"] > div {{
    padding: 1.15rem 1rem;
}}

.brand {{
    padding: .15rem .2rem .75rem;
    border-bottom: 1px solid {LINE};
    margin-bottom: 1.15rem;
}}

.brand-row {{
    display:flex;
    align-items:center;
    gap:9px;
}}

.brand-icon {{
    width:32px;
    height:32px;
    border-radius:9px;
    background:#E1F1EC;
    color:{TEAL};
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:17px;
    font-weight:800;
}}

.brand-name {{
    font-size:17px;
    font-weight:800;
    color:{TEXT};
    letter-spacing:-.035em;
}}

.brand-caption {{
    color:#9AA49F;
    font-size:8px;
    letter-spacing:.14em;
    margin-left:41px;
    margin-top:2px;
}}

.side-label {{
    color:#9AA49F;
    font-size:10.5px;
    font-weight:800;
    letter-spacing:.13em;
    text-transform:uppercase;
    margin:.72rem 0 .3rem .18rem;
}}

div[data-testid="stRadio"] label {{
    font-size:.75rem !important;
    line-height:1.25 !important;
    color:#24332D !important;
    -webkit-text-fill-color:#24332D !important;
    opacity:1 !important;
    font-weight:600 !important;
    padding:.28rem .2rem !important;
}}

div[data-testid="stRadio"] label span,
div[data-testid="stRadio"] label p,
div[data-testid="stRadio"] label [data-testid="stMarkdownContainer"],
div[data-testid="stRadio"] label [data-testid="stMarkdownContainer"] p,
div[data-testid="stRadio"] label[data-baseweb="radio"] p {{
    color:#24332D !important;
    -webkit-text-fill-color:#24332D !important;
    font-size:.75rem !important;
    line-height:1.25 !important;
    opacity:1 !important;
}}

div[data-testid="stRadio"] label:hover {{
    color:{TEAL} !important;
}}

div[data-testid="stSelectbox"] label {{
    color:#6E7B75 !important;
    font-size:.7rem !important;
}}

div[data-baseweb="select"] > div {{
    border-color:#DDE5E1 !important;
    border-radius:9px !important;
    background:#FFFFFF !important;
}}

div[data-testid="stSelectbox"] [data-baseweb="select"] > div,
div[data-testid="stSelectbox"] [data-baseweb="select"] input {{
    color:#24332D !important;
}}

[data-testid="stCaptionContainer"] p {{
    color:#9AA49F !important;
    font-size:.65rem !important;
}}

.header {{
    background:#F9FAF9;
    border:1px solid {LINE};
    border-radius:16px;
    padding:1.25rem 1.35rem;
    display:flex;
    justify-content:space-between;
    align-items:center;
    box-shadow:0 4px 15px rgba(30,50,40,.035);
    margin-bottom:1.4rem;
}}

.company {{
    color:{TEAL};
    font-size:.65rem;
    font-weight:800;
    letter-spacing:.14em;
}}

.title {{
    color:{TEXT};
    font-size:1.45rem;
    font-weight:800;
    letter-spacing:-.045em;
    margin-top:.22rem;
}}

.subtitle {{
    color:#8C9892;
    font-size:.7rem;
    margin-top:.25rem;
}}

.status {{
    display:flex;
    align-items:center;
    gap:7px;
    border:1px solid #DDE8E3;
    background:#F7FBF9;
    color:#51625A;
    border-radius:999px;
    padding:.45rem .7rem;
    font-size:.62rem;
    font-weight:800;
    letter-spacing:.05em;
}}

.status-dot {{
    width:8px;
    height:8px;
    border-radius:50%;
    background:{GREEN};
}}

.section {{
    margin:.25rem 0 1rem;
}}

.section h2 {{
    margin:0;
    color:{TEXT};
    font-size:1.05rem;
    font-weight:800;
    letter-spacing:-.025em;
}}

.section p {{
    margin:.28rem 0 0;
    color:#8C9892;
    font-size:.68rem;
}}

.card {{
    background:#F9FBFA;
    border:1px solid {LINE};
    border-radius:14px;
    padding:.85rem .9rem;
    min-height:108px;
    box-shadow:0 4px 15px rgba(30,50,40,.03);
}}

.card-top {{
    display:flex;
    align-items:center;
    gap:8px;
}}

.card-icon {{
    width:29px;
    height:29px;
    border-radius:8px;
    display:flex;
    align-items:center;
    justify-content:center;
    font-weight:800;
    font-size:14px;
}}

.card-label {{
    color:#8A9690;
    font-size:.62rem;
    font-weight:700;
}}

.card-value {{
    color:#25322D;
    font-size:1.18rem;
    font-weight:800;
    letter-spacing:-.035em;
    margin-top:.62rem;
}}

.card-sub {{
    color:#A0AAA5;
    font-size:.58rem;
    margin-top:.16rem;
}}

.health {{
    background:linear-gradient(135deg,#F0F8F5,#FAFCFB);
    border:1px solid #D8EAE3;
    border-radius:16px;
    padding:1.35rem;
    min-height:205px;
}}

.health-label {{
    color:#79918A;
    font-size:.61rem;
    font-weight:800;
    letter-spacing:.11em;
    text-transform:uppercase;
}}

.health-value {{
    color:#18382F;
    font-size:2.55rem;
    font-weight:800;
    letter-spacing:-.06em;
    margin-top:.35rem;
}}

.health-badge {{
    display:inline-block;
    border-radius:999px;
    padding:.25rem .52rem;
    font-size:.56rem;
    font-weight:800;
    margin-top:.28rem;
}}

.health-text {{
    color:#73847D;
    font-size:.66rem;
    line-height:1.55;
    margin-top:.75rem;
}}

.panel {{
    background:#F9FBFA;
    border:1px solid {LINE};
    border-radius:16px;
    padding:1rem;
    box-shadow:0 4px 15px rgba(30,50,40,.035);
}}

.panel-title {{
    color:{TEXT};
    font-size:.9rem;
    font-weight:800;
    margin-bottom:.15rem;
}}

.panel-sub {{
    color:#99A59F;
    font-size:.72rem;
    margin-bottom:.65rem;
}}

.event {{
    display:flex;
    align-items:center;
    gap:10px;
    padding:.62rem 0;
    border-bottom:1px solid #EEF2F0;
}}

.event:last-child {{
    border-bottom:0;
}}

.event-dot {{
    width:8px;
    height:8px;
    border-radius:50%;
    flex:0 0 auto;
}}

.event-main {{
    flex:1;
}}

.event-title {{
    color:#34413B;
    font-size:.78rem;
    font-weight:700;
}}

.event-sub {{
    color:#98A49F;
    font-size:.69rem;
    margin-top:2px;
}}

.badge {{
    font-size:.62rem;
    font-weight:800;
    border-radius:999px;
    padding:.25rem .42rem;
}}

.badge.warn {{
    color:#9A6416;
    background:#FFF4DF;
}}

.badge.info {{
    color:{TEAL};
    background:#E6F4F2;
}}

.badge.ok {{
    color:{GREEN};
    background:#E3F5EC;
}}

.summary-item {{
    padding:.55rem .6rem;
    border-radius:9px;
    background:#F8FAF9;
    border:1px solid #EDF2EF;
}}

.summary-label {{
    color:#9AA49F;
    font-size:.57rem;
    font-weight:800;
    letter-spacing:.1em;
}}

.summary-value {{
    color:#34413B;
    font-size:.73rem;
    font-weight:800;
    margin-top:.15rem;
}}

.footer {{
    text-align:center;
    color:#A2AAA6;
    font-size:.62rem;
    padding-top:1.5rem;
}}

[data-testid="stHorizontalBlock"] {{
    align-items:stretch;
}}
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# DISPLAY HELPERS
# ============================================================

def card(icon, label, value, sub, accent=TEAL):
    return f"""
    <div class="card">
        <div class="card-top">
            <div class="card-icon" style="background:{accent}18;color:{accent};">{icon}</div>
            <div class="card-label">{label}</div>
        </div>
        <div class="card-value">{value}</div>
        <div class="card-sub">{sub}</div>
    </div>
    """


def panel(title, subtitle):
    st.markdown(
        f"""
        <div class="panel-title">{title}</div>
        <div class="panel-sub">{subtitle}</div>
        """,
        unsafe_allow_html=True,
    )


def section(title, subtitle):
    st.markdown(
        f"""
        <div class="section">
            <h2>{title}</h2>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def base_layout(fig, height=315, margin=None):
    fig.update_layout(
        height=height,
        margin=margin or dict(l=10, r=15, t=10, b=10),
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(color="#0B3D2E"),
        xaxis=dict(
            tickfont=dict(color="#0B3D2E"),
            title_font=dict(color="#0B3D2E"),
        ),
        yaxis=dict(
            tickfont=dict(color="#0B3D2E"),
            title_font=dict(color="#0B3D2E"),
        ),
    )
    return fig


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def format_kbps(bits_per_second):
    return f"{safe_float(bits_per_second) / 1000:.2f} Kbps"


def status_for_health(score):
    score = safe_float(score)
    if score >= 90:
        return "HEALTHY"
    if score >= 75:
        return "GOOD"
    if score >= 60:
        return "MONITOR"
    return "REVIEW REQUIRED"


# ============================================================
# LIVE CAPTURE
# ============================================================

def get_interfaces():
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=True,
        )

        interfaces = []

        for line in result.stdout.splitlines():
            if ". " not in line:
                continue

            number, name = line.split(". ", 1)
            clean_name = name.strip()

            if " (" in clean_name and clean_name.endswith(")"):
                clean_name = clean_name.rsplit("(", 1)[1][:-1].strip()

            try:
                interfaces.append((int(number), clean_name))
            except ValueError:
                continue

        return interfaces

    except Exception:
        return [(5, "Wi-Fi")]


def preferred_interface():
    interfaces = get_interfaces()
    if not interfaces:
        return (5, "Wi-Fi")

    preferred_order = (
        "Wi-Fi",
        "Wireless",
        "Ethernet",
        "Local Area Connection",
    )

    for token in preferred_order:
        for number, name in interfaces:
            if token.lower() in name.lower():
                return (number, name)

    for number, name in interfaces:
        if "loopback" not in name.lower() and "etw" not in name.lower():
            return (number, name)

    return interfaces[0]


PREFERRED_INTERFACE = preferred_interface()

DEFAULTS = {
    "mode": "Offline Analysis",
    "module": "Dashboard",
    "live_interface": PREFERRED_INTERFACE[0],
    "live_name": PREFERRED_INTERFACE[1],
    "live_started": None,
    "live_packets": 0,
    "live_bytes": 0,
    "live_protocols": Counter(),
    "live_per_second": defaultdict(int),
    "live_rtts": [],
    "live_pending_icmp": {},
    "live_retrans": 0,
    "live_dup_ack": 0,
    "live_ooo": 0,
    "live_rst": 0,
    "live_dns_queries": 0,
    "live_dns_responses": 0,
    "live_dns_failed": 0,
    "live_dns_success": 0,
    "live_arp_req": 0,
    "live_arp_reply": 0,
    "live_last_packets": [],
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def get_live_monitor():
    monitor = st.session_state.get("live_monitor_instance")
    if monitor is None or not monitor.running:
        interface = st.session_state.get("live_interface", 5)
        monitor = LiveMonitor(interface=interface)
        monitor.start()
        st.session_state.live_monitor_instance = monitor
    return st.session_state.live_monitor_instance

def reset_live_state():
    if "live_monitor_instance" in st.session_state:
        st.session_state.live_monitor_instance.stop()
        del st.session_state["live_monitor_instance"]

def live_snapshot():
    return get_live_monitor().snapshot()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div class="brand">
            <div class="brand-row">
                <div class="brand-icon">◎</div>
                <div class="brand-name">TechNova</div>
            </div>
            <div class="brand-caption">NETWORK INTELLIGENCE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="side-label">Monitoring Mode</div>',
        unsafe_allow_html=True,
    )

    mode = st.radio(
        "Monitoring Mode",
        ["Offline Analysis", "Live Monitoring"],
        index=(
            0
            if st.session_state.mode == "Offline Analysis"
            else 1
        ),
        label_visibility="collapsed",
    )

    if mode != st.session_state.mode:
        st.session_state.mode = mode
        reset_live_state()

        if mode == "Live Monitoring":
            get_live_monitor()


    st.markdown(
        '<div class="side-label">Modules</div>',
        unsafe_allow_html=True,
    )

    MODULES = [
        "Dashboard",
        "Protocol Analysis",
        "Performance",
        "Security",
        "Live Traffic",
        "Network Topology",
    ]

    module = st.radio(
        "Modules",
        MODULES,
        index=MODULES.index(st.session_state.module),
        label_visibility="collapsed",
    )

    st.session_state.module = module

    st.markdown(
        '<div class="side-label">Data Source</div>',
        unsafe_allow_html=True,
    )

    if st.session_state.mode == "Offline Analysis":

        st.selectbox(
            "Offline source",
            ["Unified analysis suite"],
            label_visibility="collapsed",
        )

        st.caption(
            "tcp_test.pcapng • icmp_test.pcapng • dns_test.pcapng"
        )

    else:

        interfaces = get_interfaces()

        if not interfaces:
            interfaces = [(5, "Wi-Fi")]

        names = [
            f"{number}: {name}"
            for number, name in interfaces
        ]

        current = (
            f"{st.session_state.live_interface}: "
            f"{st.session_state.live_name}"
        )

        index = names.index(current) if current in names else 0

        selected = st.selectbox(
            "Interface",
            names,
            index=index,
            label_visibility="collapsed",
        )

        number, name = selected.split(":", 1)

        new_interface = int(number)
        new_name = name.strip()

        if (
            new_interface != st.session_state.live_interface
            or new_name != st.session_state.live_name
        ):
            st.session_state.live_interface = new_interface
            st.session_state.live_name = new_name
            reset_live_state()

            if st.session_state.mode == "Live Monitoring":
                get_live_monitor()

    st.markdown(
        '<div class="side-label">Analysis Engine</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="summary-item">
            <div class="summary-label">PACKET ENGINE</div>
            <div class="summary-value">Scapy PCAPNG</div>
            <div class="summary-label" style="margin-top:4px;">
                Same offline engine locally and in Cloud
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# GLOBAL DATA
# ============================================================

if st.session_state.mode == "Offline Analysis":

    try:
        # ========================================================
        # ONE CALL ONLY.
        #
        # Protocol Analysis, Performance and Security all use
        # this same dictionary returned by unified_analysis.py.
        # ========================================================
        OFFLINE = unified_analysis.analyze_all()

    except Exception as exc:
        st.error(f"Unified analysis error: {exc}")
        st.info(
            "Check TShark, the three PCAP files and "
            "src/analysis/unified_analysis.py."
        )
        st.stop()

    I = OFFLINE["icmp"]
    D = OFFLINE["dns"]
    T = OFFLINE["tcp"]
    A = OFFLINE["arp"]
    TH = OFFLINE["throughput"]
    PROTOCOLS = OFFLINE["protocols"]

    RTT_VALUES = I.get("rtts", [])
    TRAFFIC = TH.get("traffic", [])

    HEALTH = float(OFFLINE.get("health", 0))
    STATUS = OFFLINE.get(
        "status",
        status_for_health(HEALTH),
    )

else:

    LIVE = live_snapshot()

    I = {
        "requests": LIVE.get("icmp_requests", 0),
        "replies": LIVE.get("icmp_replies", 0),
        "loss": LIVE.get("packet_loss", 0),
        "rtts": LIVE.get("icmp_rtts", []),
        "avg_rtt": LIVE.get("avg_icmp_rtt", 0.0),
        "min_rtt": LIVE.get("min_icmp_rtt", 0.0),
        "max_rtt": LIVE.get("max_icmp_rtt", 0.0),
    }

    T = {
        "total": LIVE.get("total_packets", 0),
        "retransmissions": LIVE.get("tcp_retransmissions", 0),
        "duplicate_acks": LIVE.get("tcp_duplicate_acks", 0),
        "out_of_order": LIVE.get("tcp_out_of_order", 0),
        "rst": LIVE.get("tcp_rst", 0),
    }

    D = {
        "queries": LIVE.get("dns_queries", 0),
        "responses": LIVE.get("dns_responses", 0),
        "successful": LIVE.get("dns_success", 0),
        "failed": LIVE.get("dns_failed", 0),
        "success_rate": LIVE.get("dns_success_rate", 0.0),
        "rtts": LIVE.get("dns_rtts", []),
        "avg_rtt": LIVE.get("avg_dns_rtt", 0.0),
        "min_rtt": LIVE.get("min_dns_rtt", 0.0),
        "max_rtt": LIVE.get("max_dns_rtt", 0.0),
    }

    A = {
        "requests": LIVE.get("arp_requests", 0),
        "replies": LIVE.get("arp_replies", 0),
        "broadcasts": 0,
    }

    TH = {
        "packets": LIVE.get("total_packets", 0),
        "bytes": LIVE.get("total_bytes", 0),
        "duration": LIVE.get("elapsed", 0.0),
        "packet_rate": LIVE.get("packet_rate", 0.0),
        "throughput": LIVE.get("throughput_bps", 0),
        "traffic": LIVE.get("traffic", []),
        "last_packets": LIVE.get("last_packets", []),
    }

    PROTOCOLS = LIVE.get("protocols", {})
    RTT_VALUES = LIVE.get("icmp_rtts", [])
    TRAFFIC = LIVE.get("traffic", [])

    HEALTH = LIVE.get("health_score", 100)
    STATUS = LIVE.get("health_status", "GOOD")


if st.session_state.mode == "Live Monitoring":

    if hasattr(st, "fragment"):

        @st.fragment(run_every="1s")
        def refresh_live_monitor():
            # We only need to refresh the current live snapshot; avoid a full
            # page rerun from inside the fragment so mode switches stay fast.
            live_snapshot()

        refresh_live_monitor()


# ============================================================
# HEADER
# ============================================================

mode_text = (
    "OFFLINE CAPTURE"
    if st.session_state.mode == "Offline Analysis"
    else "LIVE MONITORING"
)

st.markdown(
    f"""
    <div class="header">
        <div>
            <div class="company">TECHNOVA SOLUTIONS PVT. LTD.</div>
            <div class="title">Enterprise Network Monitor</div>
            <div class="subtitle">
                Network intelligence • Performance analytics • Security monitoring
            </div>
        </div>
        <div class="status">
            <span class="status-dot"></span>
            {mode_text}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DASHBOARD
# ============================================================

if st.session_state.module == "Dashboard":

    section(
        "Network Command Center",
        "Unified network overview from the active analysis source",
    )

    cols = st.columns(6)

    overview_cards = [
        (
            "▣",
            "Total Packets",
            f"{TH['packets']:,}",
            "Captured packets",
            TEAL,
        ),
        (
            "↗",
            "Throughput",
            format_kbps(TH["throughput"]),
            "Average traffic rate",
            GREEN,
        ),
        (
            "◷",
            "Average RTT",
            f"{I['avg_rtt']:.2f} ms",
            "ICMP round-trip time",
            PURPLE,
        ),
        (
            "⌁",
            "Packet Loss",
            f"{I['loss']:.2f}%",
            "ICMP packet loss",
            GREEN,
        ),
        (
            "◆",
            "Packet Rate",
            f"{TH['packet_rate']:.2f}",
            "Packets / second",
            BLUE,
        ),
        (
            "◉",
            "Data Captured",
            f"{TH['bytes'] / 1024:.2f} KB",
            "Total captured data",
            AMBER,
        ),
    ]

    for col, item in zip(cols, overview_cards):
        with col:
            st.markdown(card(*item), unsafe_allow_html=True)

    st.write("")

    left, right = st.columns([1, 1.5], gap="medium")

    with left:
        badge_color = (
            GREEN
            if HEALTH >= 75
            else AMBER
            if HEALTH >= 60
            else RED
        )

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=HEALTH,
            title={'text': "Network Health", 'font': {'size': 20, 'color': TEXT}},
            number={'font': {'size': 42, 'color': badge_color}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': LINE},
                'bar': {'color': badge_color},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': LINE,
                'steps': [
                    {'range': [0, 60], 'color': "#FFEBEE"},
                    {'range': [60, 75], 'color': "#FFF3E0"},
                    {'range': [75, 100], 'color': "#E8F5E9"}
                ],
                'threshold': {
                    'line': {'color': badge_color, 'width': 4},
                    'thickness': 0.75,
                    'value': HEALTH
                }
            }
        ))
        
        base_layout(fig, height=250, margin=dict(l=20, r=20, t=50, b=20))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        st.markdown(
            f"""
            <div class="health" style="min-height: auto; padding: 1rem;">
                <div class="health-label">Status Overview</div>
                <div class="health-badge"
                     style="color:{badge_color};background:{badge_color}18; font-size: 0.7rem;">
                    {STATUS}
                </div>
                <div class="health-text">
                    Combined project score based on ICMP latency and loss,
                    TCP reliability, DNS performance and traffic indicators.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "Network Events",
            "Automatically derived indicators",
        )

        events = [
            (
                "warn" if T["retransmissions"] else "ok",
                "TCP retransmissions",
                f"{T['retransmissions']} detected",
            ),
            (
                "warn" if D["success_rate"] < 90 else "ok",
                "DNS reliability",
                f"{D['success_rate']:.2f}% success",
            ),
            (
                "warn" if I["loss"] > 0 else "ok",
                "ICMP reachability",
                f"{I['loss']:.2f}% packet loss",
            ),
            (
                "info",
                "ARP requests",
                f"{A['requests']} observed",
            ),
        ]

        for kind, title_text, detail in events:

            if kind == "warn":
                dot = AMBER
                badge = "WARN"
                cls = "warn"
            elif kind == "ok":
                dot = GREEN
                badge = "OK"
                cls = "ok"
            else:
                dot = TEAL
                badge = "INFO"
                cls = "info"

            st.markdown(
                f"""
                <div class="event">
                    <div class="event-dot" style="background:{dot};"></div>
                    <div class="event-main">
                        <div class="event-title">{title_text}</div>
                        <div class="event-sub">{detail}</div>
                    </div>
                    <span class="badge {cls}">{badge}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")

    st.markdown('<div class="panel">', unsafe_allow_html=True)

    panel(
        "Capture Summary",
        "Current unified analysis source"
        if st.session_state.mode == "Offline Analysis"
        else "Current live capture session",
    )

    summary_cols = st.columns(4)

    summaries = [
        (
            "CAPTURE",
            TH.get("capture", "Live interface")
            if st.session_state.mode == "Offline Analysis"
            else st.session_state.live_name,
        ),
        ("DURATION", f"{TH['duration']:.2f} s"),
        ("TCP PACKETS", f"{T['total']:,}"),
        ("DNS RESPONSES", f"{D['responses']:,}"),
    ]

    for col, (label, value) in zip(summary_cols, summaries):
        with col:
            st.markdown(
                f"""
                <div class="summary-item">
                    <div class="summary-label">{label}</div>
                    <div class="summary-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# PROTOCOL ANALYSIS
# ============================================================

elif st.session_state.module == "Protocol Analysis":

    section(
        "Protocol Analysis",
        "Protocol distribution produced directly by unified_analysis.py",
    )

    items = sorted(
        PROTOCOLS.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    top = items[:12]
    protocol_total = sum(PROTOCOLS.values())

    if top:

        cols = st.columns(4)

        for col, (name, count) in zip(cols, top[:4]):

            pct = (
                count / protocol_total * 100
                if protocol_total
                else 0
            )

            with col:
                st.markdown(
                    card(
                        "●",
                        name,
                        f"{count:,}",
                        f"{pct:.2f}% of packets",
                        TEAL,
                    ),
                    unsafe_allow_html=True,
                )

        st.write("")

        p1, p2 = st.columns(2, gap="medium")

        with p1:

            st.markdown('<div class="panel">', unsafe_allow_html=True)

            panel(
                "Protocol Share",
                "Relative packet contribution",
            )

            labels = [item[0] for item in top]
            values = [item[1] for item in top]

            fig = go.Figure(
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=.62,
                    textinfo="label+percent",
                    textfont=dict(
                        color="#0B3D2E",
                        size=10,
                    ),
                    marker=dict(
                        colors=[
                            "#147C80",
                            "#4B9296",
                            "#78AAA1",
                            "#A0C3B8",
                            "#BCD2CB",
                            "#D2E1DC",
                            "#B7CCC5",
                            "#9CBDB5",
                            "#81A9A5",
                            "#678F8D",
                            "#9EB5B0",
                            "#C5D4D0",
                        ]
                    ),
                )
            )

            base_layout(
                fig,
                height=350,
                margin=dict(l=10, r=10, t=10, b=10),
            )

            fig.update_layout(showlegend=False)

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

            st.markdown("</div>", unsafe_allow_html=True)

        with p2:

            st.markdown('<div class="panel">', unsafe_allow_html=True)

            panel(
                "Packet Count",
                "Absolute number of packets by protocol",
            )

            labels = [item[0] for item in top]
            values = [item[1] for item in top]

            fig = go.Figure(
                go.Bar(
                    x=values,
                    y=labels,
                    orientation="h",
                    marker_color=TEAL,
                    text=values,
                    textposition="outside",
                    textfont=dict(color="#18332D"),
                )
            )

            base_layout(
                fig,
                height=350,
                margin=dict(l=70, r=45, t=10, b=45),
            )

            fig.update_yaxes(autorange="reversed")
            fig.update_xaxes(
                title="Packets",
                gridcolor="#EDF0EE",
                title_font=dict(color="#18332D"),
                tickfont=dict(color="#18332D"),
            )
            fig.update_yaxes(tickfont=dict(color="#18332D"))

            fig.update_layout(showlegend=False)

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

            st.markdown("</div>", unsafe_allow_html=True)

    else:
        st.warning(
            "No protocol data was returned by unified_analysis.py."
        )


# ============================================================
# PERFORMANCE
# ============================================================

elif st.session_state.module == "Performance":

    section(
        "Network Performance",
        "Latency, throughput and traffic-volume analysis",
    )

    cols = st.columns(5)

    performance_cards = [
        (
            "◷",
            "Minimum RTT",
            f"{I['min_rtt']:.2f} ms",
            "Best ICMP response",
            TEAL,
        ),
        (
            "◷",
            "Average RTT",
            f"{I['avg_rtt']:.2f} ms",
            "Mean ICMP response",
            BLUE,
        ),
        (
            "◷",
            "Maximum RTT",
            f"{I['max_rtt']:.2f} ms",
            "Highest ICMP response",
            AMBER,
        ),
        (
            "⌁",
            "Packet Loss",
            f"{I['loss']:.2f}%",
            "ICMP reachability",
            GREEN,
        ),
        (
            "↗",
            "Throughput",
            format_kbps(TH["throughput"]),
            "Average traffic",
            PURPLE,
        ),
    ]

    for col, item in zip(cols, performance_cards):
        with col:
            st.markdown(
                card(*item),
                unsafe_allow_html=True,
            )

    st.write("")

    p1, p2 = st.columns(2, gap="medium")

    with p1:

        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "ICMP RTT Trend",
            f"Round-trip time for {len(RTT_VALUES)} matched ICMP echo pairs",
        )

        fig = go.Figure()

        if RTT_VALUES:

            fig.add_trace(
                go.Scatter(
                    x=list(range(1, len(RTT_VALUES) + 1)),
                    y=RTT_VALUES,
                    mode="lines+markers",
                    line=dict(color=TEAL, width=3),
                    marker=dict(color=TEAL, size=7),
                    fill="tozeroy",
                    fillcolor="rgba(20,124,128,.08)",
                    hovertemplate=(
                        "Ping %{x}<br>"
                        "RTT %{y:.2f} ms<extra></extra>"
                    ),
                )
            )

            base_layout(
                fig,
                height=320,
                margin=dict(l=55, r=15, t=10, b=50),
            )

            fig.update_xaxes(
                title="Ping sequence",
                showgrid=False,
            )

            fig.update_yaxes(
                title="RTT (ms)",
                showgrid=True,
                gridcolor="#EDF0EE",
            )

        else:

            fig.add_annotation(
                text=(
                    "Waiting for live traffic..."
                    if st.session_state.mode == "Live Monitoring"
                    else "No matched ICMP RTT data"
                ),
                x=.5,
                y=.5,
                xref="paper",
                yref="paper",
                showarrow=False,
            )

            base_layout(fig, height=320)

        fig.update_layout(showlegend=False)

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False},
        )

        st.markdown("</div>", unsafe_allow_html=True)

    with p2:

        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "Traffic Volume",
            "Packets captured each second",
        )

        if st.session_state.mode == "Live Monitoring" and not TRAFFIC:
            st.info("Waiting for live traffic...")

        fig = go.Figure(
            go.Bar(
                x=list(range(len(TRAFFIC))),
                y=TRAFFIC,
                marker_color="#5A9EA0",
            )
        )

        base_layout(
            fig,
            height=320,
            margin=dict(l=55, r=15, t=10, b=50),
        )

        fig.update_xaxes(
            title="Time (seconds)",
            showgrid=False,
        )

        fig.update_yaxes(
            title="Packets",
            showgrid=True,
            gridcolor="#EDF0EE",
        )

        fig.update_layout(showlegend=False)

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False},
        )

        st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# SECURITY
# ============================================================

elif st.session_state.module == "Security":

    section(
        "Security & Traffic",
        "Reliability and security-relevant indicators from unified_analysis.py",
    )

    cols = st.columns(5)

    security_cards = [
        (
            "!",
            "Retransmissions",
            T["retransmissions"],
            "TCP",
            AMBER,
        ),
        (
            "!",
            "Duplicate ACKs",
            T["duplicate_acks"],
            "TCP",
            AMBER,
        ),
        (
            "!",
            "Out-of-order",
            T["out_of_order"],
            "TCP",
            PURPLE,
        ),
        (
            "!",
            "RST Packets",
            T["rst"],
            "TCP",
            RED,
        ),
        (
            "⌁",
            "ARP Requests",
            A["requests"],
            "ARP",
            TEAL,
        ),
    ]

    for col, item in zip(cols, security_cards):
        with col:
            st.markdown(
                card(*item),
                unsafe_allow_html=True,
            )

    st.write("")

    s1, s2 = st.columns([1.1, 1], gap="medium")

    with s1:

        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "Security Findings",
            "Indicators generated from observed traffic",
        )

        findings = []

        if T["retransmissions"]:
            findings.append(
                (
                    "warn",
                    "TCP retransmissions detected",
                    f"{T['retransmissions']} retransmissions",
                )
            )

        if T["duplicate_acks"]:
            findings.append(
                (
                    "info",
                    "TCP duplicate ACK activity",
                    f"{T['duplicate_acks']} duplicate ACKs",
                )
            )

        if T["out_of_order"]:
            findings.append(
                (
                    "info",
                    "TCP out-of-order activity",
                    f"{T['out_of_order']} packets",
                )
            )

        if T["rst"]:
            findings.append(
                (
                    "info",
                    "TCP reset packets detected",
                    f"{T['rst']} RST packets",
                )
            )

        if A["broadcasts"]:
            findings.append(
                (
                    "info",
                    "ARP broadcast activity",
                    f"{A['broadcasts']} broadcasts",
                )
            )

        if D["failed"]:
            findings.append(
                (
                    "warn",
                    "DNS failed responses detected",
                    f"{D['failed']} failed responses",
                )
            )

        if I["loss"] > 0:
            findings.append(
                (
                    "warn",
                    "ICMP packet loss detected",
                    f"{I['loss']:.2f}% packet loss",
                )
            )

        if not findings:
            findings.append(
                (
                    "ok",
                    "No reliability indicators detected",
                    "No observed non-zero indicators",
                )
            )

        for kind, title_text, detail in findings:

            if kind == "warn":
                dot = AMBER
                badge = "WARN"
                cls = "warn"

            elif kind == "ok":
                dot = GREEN
                badge = "OK"
                cls = "ok"

            else:
                dot = TEAL
                badge = "INFO"
                cls = "info"

            st.markdown(
                f"""
                <div class="event">
                    <div class="event-dot" style="background:{dot};"></div>
                    <div class="event-main">
                        <div class="event-title">{title_text}</div>
                        <div class="event-sub">{detail}</div>
                    </div>
                    <span class="badge {cls}">{badge}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    with s2:

        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "DNS Reliability",
            "Successful versus failed DNS responses",
        )

        successful = D["successful"]
        failed = D["failed"]

        if successful + failed:

            fig = go.Figure(
                go.Pie(
                    labels=["Successful", "Failed"],
                    values=[successful, failed],
                    hole=.68,
                    marker=dict(
                        colors=[GREEN, "#E7B76E"]
                    ),
                    textinfo="none",
                )
            )

            base_layout(
                fig,
                height=285,
                margin=dict(l=5, r=5, t=5, b=5),
            )

            fig.update_layout(
                showlegend=False,
                annotations=[
                    dict(
                        text=f"{D['success_rate']:.1f}%",
                        x=.5,
                        y=.5,
                        font=dict(
                            size=25,
                            color=TEXT,
                        ),
                        showarrow=False,
                    )
                ],
            )

        else:

            fig = go.Figure()

            fig.add_annotation(
                text="No DNS response data",
                x=.5,
                y=.5,
                xref="paper",
                yref="paper",
                showarrow=False,
            )

            base_layout(fig, height=285)

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False},
        )

        st.markdown(
            f"""
            <div style="text-align:center;color:#87948E;font-size:.62rem;">
                DNS success rate •
                Avg RTT {D.get('avg_rtt', 0):.2f} ms •
                Max RTT {D.get('max_rtt', 0):.2f} ms
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# LIVE TRAFFIC
# ============================================================

elif st.session_state.module == "Live Traffic":

    section(
        "Live Traffic",
        (
            "Direct TShark capture from the selected interface"
            if st.session_state.mode == "Live Monitoring"
            else
            "Switch to Live Monitoring to capture packets from a real interface"
        ),
    )

    if st.session_state.mode != "Live Monitoring":

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">Live capture is disabled</div>
                <div class="panel-sub">
                    Select Live Monitoring from the sidebar.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    else:

        live = LIVE

        cols = st.columns(5)

        live_cards = [
            (
                "●",
                "Packets",
                f"{live.get('total_packets', 0):,}",
                "Session total",
                TEAL,
            ),
            (
                "↗",
                "Throughput",
                format_kbps(live.get("throughput_bps", 0)),
                "Current session rate",
                GREEN,
            ),
            (
                "◷",
                "RTT",
                (
                    f"{live.get('avg_icmp_rtt', 0.0):.2f} ms"
                    if live.get("avg_icmp_rtt") is not None
                    else "N/A"
                ),
                "Matched ICMP",
                PURPLE,
            ),
            (
                "!",
                "Retransmissions",
                live.get("tcp_retransmissions", 0),
                "TCP",
                AMBER,
            ),
            (
                "⌁",
                "ARP Requests",
                live.get("arp_requests", 0),
                "ARP",
                TEAL,
            ),
        ]

        for col, item in zip(cols, live_cards):
            with col:
                st.markdown(
                    card(*item),
                    unsafe_allow_html=True,
                )

        st.write("")

        p1, p2 = st.columns(2, gap="medium")

        with p1:

            st.markdown('<div class="panel">', unsafe_allow_html=True)

            panel(
                "Live Protocol Distribution",
                "Packets seen during this monitoring session",
            )

            items = sorted(
                live["protocols"].items(),
                key=lambda item: item[1],
                reverse=True,
            )[:12]

            labels = [item[0] for item in items]
            values = [item[1] for item in items]

            fig = go.Figure(
                go.Bar(
                    x=values,
                    y=labels,
                    orientation="h",
                    marker_color=TEAL,
                    text=values,
                    textposition="outside",
                )
            )

            base_layout(
                fig,
                height=315,
                margin=dict(l=75, r=45, t=10, b=45),
            )

            fig.update_yaxes(autorange="reversed")
            fig.update_xaxes(
                title="Packets",
                gridcolor="#EDF0EE",
            )

            fig.update_layout(showlegend=False)

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

            st.markdown("</div>", unsafe_allow_html=True)

        with p2:

            st.markdown('<div class="panel">', unsafe_allow_html=True)

            panel(
                "Live Packet Rate",
                "Packets captured per elapsed second",
            )

            fig = go.Figure(
                go.Bar(
                    x=list(range(len(live["traffic"]))),
                    y=live["traffic"],
                    marker_color="#5A9EA0",
                    hovertemplate=(
                        "%{x}s: %{y} packets<extra></extra>"
                    ),
                )
            )

            base_layout(
                fig,
                height=315,
                margin=dict(l=55, r=15, t=10, b=50),
            )

            fig.update_xaxes(
                title="Second",
                showgrid=False,
            )

            fig.update_yaxes(
                title="Packets",
                gridcolor="#EDF0EE",
            )

            fig.update_layout(showlegend=False)

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

            st.markdown("</div>", unsafe_allow_html=True)

        st.write("")

        st.markdown('<div class="panel">', unsafe_allow_html=True)

        panel(
            "Live Packet Stream",
            "Most recently captured packets",
        )

        recent = list(reversed(live["last_packets"][-12:]))

        if recent:
            st.dataframe(
                recent,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("Waiting for packets...")

        st.markdown("</div>", unsafe_allow_html=True)

        # Refresh only in live mode.
        time.sleep(0.2)
        st.rerun()


# ============================================================
# NETWORK TOPOLOGY
# ============================================================

elif st.session_state.module == "Network Topology" and False:

    section(
        "Network Topology",
        "Cisco Packet Tracer enterprise design — logical topology and VLAN structure",
    )

    st.markdown(
        """
        <div class="panel">
            <svg viewBox="0 0 1100 470" style="width:100%;height:auto;">

                <g stroke="#D9E3DF" stroke-width="4" fill="none">
                    <line x1="95" y1="120" x2="245" y2="120"/>
                    <line x1="335" y1="120" x2="490" y2="120"/>
                    <line x1="580" y1="120" x2="735" y2="120"/>

                    <line x1="825" y1="120" x2="900" y2="70"/>
                    <line x1="825" y1="120" x2="900" y2="165"/>
                    <line x1="825" y1="120" x2="900" y2="260"/>
                    <line x1="825" y1="120" x2="900" y2="355"/>
                </g>

                <circle
                    cx="55" cy="120" r="38"
                    fill="#E5F2ED"
                    stroke="#147C80"
                    stroke-width="3"
                />
                <text
                    x="55" y="128"
                    text-anchor="middle"
                    font-size="22"
                >☁</text>
                <text
                    x="55" y="180"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="13"
                >Internet</text>

                <rect
                    x="245" y="85"
                    width="90" height="70"
                    rx="12"
                    fill="#F0F6F4"
                    stroke="#82AAA5"
                    stroke-width="2"
                />
                <text
                    x="290" y="128"
                    text-anchor="middle"
                    fill="#147C80"
                    font-size="23"
                >↔</text>
                <text
                    x="290" y="180"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="13"
                >ISP Router</text>

                <rect
                    x="490" y="85"
                    width="90" height="70"
                    rx="12"
                    fill="#E5F2ED"
                    stroke="#147C80"
                    stroke-width="2"
                />
                <text
                    x="535" y="128"
                    text-anchor="middle"
                    fill="#147C80"
                    font-size="22"
                >◇</text>
                <text
                    x="535" y="180"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="13"
                >Edge Router</text>

                <rect
                    x="735" y="80"
                    width="90" height="80"
                    rx="12"
                    fill="#E5F2ED"
                    stroke="#18805C"
                    stroke-width="3"
                />
                <text
                    x="780" y="125"
                    text-anchor="middle"
                    fill="#18805C"
                    font-size="21"
                >▦</text>
                <text
                    x="780" y="180"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="13"
                >Core L3 Switch</text>

                <rect
                    x="900" y="35"
                    width="150" height="65"
                    rx="11"
                    fill="#FAFCFB"
                    stroke="#82AAA5"
                    stroke-width="2"
                />
                <text
                    x="975" y="60"
                    text-anchor="middle"
                    fill="#164E3B"
                    font-size="12"
                    font-weight="700"
                >HR-SW1</text>
                <text
                    x="975" y="82"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="11"
                >VLAN 10 • 192.168.10.0/24</text>

                <rect
                    x="900" y="130"
                    width="150" height="65"
                    rx="11"
                    fill="#FAFCFB"
                    stroke="#82AAA5"
                    stroke-width="2"
                />
                <text
                    x="975" y="155"
                    text-anchor="middle"
                    fill="#164E3B"
                    font-size="12"
                    font-weight="700"
                >SALES-SW1</text>
                <text
                    x="975" y="177"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="11"
                >VLAN 20 • 192.168.20.0/24</text>

                <rect
                    x="900" y="225"
                    width="150" height="65"
                    rx="11"
                    fill="#FAFCFB"
                    stroke="#82AAA5"
                    stroke-width="2"
                />
                <text
                    x="975" y="250"
                    text-anchor="middle"
                    fill="#164E3B"
                    font-size="12"
                    font-weight="700"
                >IT-SW1</text>
                <text
                    x="975" y="272"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="11"
                >VLAN 30 • 192.168.30.0/24</text>

                <rect
                    x="900" y="320"
                    width="150" height="65"
                    rx="11"
                    fill="#E5F2ED"
                    stroke="#18805C"
                    stroke-width="2"
                />
                <text
                    x="975" y="345"
                    text-anchor="middle"
                    fill="#164E3B"
                    font-size="12"
                    font-weight="700"
                >Server Farm</text>
                <text
                    x="975" y="367"
                    text-anchor="middle"
                    fill="#64716C"
                    font-size="11"
                >VLAN 40 • DHCP • DNS • Apps</text>

                <g fill="#66756E" font-size="12">
                    <text x="620" y="235" text-anchor="middle">
                        802.1Q trunk links
                    </text>
                    <text x="620" y="258" text-anchor="middle">
                        Inter-VLAN routing • DHCP relay
                    </text>
                    <text x="620" y="281" text-anchor="middle">
                        VLAN 99 • Management • 192.168.99.0/24
                    </text>
                </g>

            </svg>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")

    cols = st.columns(5)

    topology_data = [
        ("VLAN 10", "HR", "192.168.10.0/24"),
        ("VLAN 20", "SALES", "192.168.20.0/24"),
        ("VLAN 30", "IT", "192.168.30.0/24"),
        ("VLAN 40", "SERVER", "192.168.40.0/24"),
        ("VLAN 99", "MGMT", "192.168.99.0/24"),
    ]

    for col, (vlan, name, subnet) in zip(cols, topology_data):

        with col:

            st.markdown(
                f"""
                <div class="summary-item">
                    <div class="summary-label">{vlan}</div>
                    <div class="summary-value">{name}</div>
                    <div class="summary-label" style="margin-top:4px;">
                        {subnet}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ============================================================
# NETWORK TOPOLOGY (PACKET TRACER VIEW)
# ============================================================

elif st.session_state.module == "Network Topology":

    section(
        "Network Topology",
        "Cisco Packet Tracer enterprise design — logical topology and VLAN structure",
    )

    topology_image = PROJECT_ROOT / "packet_tracer" / "Enterprise_Network_Topology.png"

    if topology_image.exists():
        with topology_image.open("rb") as image_file:
            topology_image_data = Image.open(image_file).convert("RGB")
            st.image(
                topology_image_data,
                use_container_width=True,
                caption="Cisco Packet Tracer enterprise topology",
            )
    else:
        st.warning(
            "Packet Tracer screenshot not found. Add it as "
            f"{topology_image.name} in the packet_tracer folder."
        )

    st.write("")

    st.markdown('<div class="panel">', unsafe_allow_html=True)

    panel(
        "VLAN and IP Information",
        "Addressing and department allocation from the Packet Tracer design",
    )

    vlan_rows = [
        {
            "VLAN ID": 10,
            "VLAN Name": "HR",
            "Network": "192.168.10.0/24",
            "Default Gateway": "192.168.10.1",
            "Department/Devices": "4 HR PCs",
        },
        {
            "VLAN ID": 20,
            "VLAN Name": "SALES",
            "Network": "192.168.20.0/24",
            "Default Gateway": "192.168.20.1",
            "Department/Devices": "6 Sales PCs",
        },
        {
            "VLAN ID": 30,
            "VLAN Name": "IT",
            "Network": "192.168.30.0/24",
            "Default Gateway": "192.168.30.1",
            "Department/Devices": "5 IT PCs",
        },
        {
            "VLAN ID": 40,
            "VLAN Name": "SERVER",
            "Network": "192.168.40.0/24",
            "Default Gateway": "192.168.40.1",
            "Department/Devices": "Infra + App Server",
        },
        {
            "VLAN ID": 99,
            "VLAN Name": "MANAGEMENT",
            "Network": "192.168.99.0/24",
            "Default Gateway": "192.168.99.1",
            "Department/Devices": "Management",
        },
    ]

    st.dataframe(vlan_rows, use_container_width=True, hide_index=True)

    st.markdown("**Important Device IPs**")

    device_rows = [
        {"Device": "Infra Server", "IP Address": "192.168.40.10", "Role": "DHCP, DNS"},
        {"Device": "App Server", "IP Address": "192.168.40.20", "Role": "HTTP, FTP, Email"},
        {"Device": "R1 WAN", "IP Address": "203.0.113.2", "Role": ""},
        {"Device": "R1 Core connection", "IP Address": "192.168.254.2", "Role": ""},
        {"Device": "Core-SW1 R1-facing IP", "IP Address": "192.168.254.1", "Role": ""},
        {"Device": "ISP", "IP Address": "203.0.113.1", "Role": ""},
        {"Device": "ISP External", "IP Address": "198.51.100.1", "Role": ""},
    ]

    st.dataframe(device_rows, use_container_width=True, hide_index=True)

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    f"""
    <div class="footer">
        <b>TECHNOVA SOLUTIONS PVT. LTD.</b> • {datetime.now().year}
        • Enterprise Network Monitor • TShark + Wireshark + Python
    </div>
    """,
    unsafe_allow_html=True,
)
