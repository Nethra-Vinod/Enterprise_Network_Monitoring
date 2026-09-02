
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
import importlib.util

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
BG = "#F4F7F5"
WHITE = "#FFFFFF"


# ============================================================
# SESSION STATE
# ============================================================

DEFAULTS = {
    "mode": "Offline Analysis",
    "module": "Dashboard",
    "live_interface": 5,
    "live_name": "Wi-Fi",
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


# ============================================================
# CSS
# ============================================================

st.markdown(
    f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {{
    font-family: Inter, sans-serif;
}}

.stApp {{
    background: {BG} !important;
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
}}

section[data-testid="stSidebar"] {{
    background: #FBFCFB;
    border-right: 1px solid {LINE};
    min-width: 255px !important;
    max-width: 255px !important;
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
    font-size:.84rem !important;
    line-height:1.25 !important;
    color:#24332D !important;
    opacity:1 !important;
    font-weight:600 !important;
    padding:.28rem .2rem !important;
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

[data-testid="stCaptionContainer"] p {{
    color:#9AA49F !important;
    font-size:.65rem !important;
}}

.header {{
    background:white;
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
    background:white;
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
    background:white;
    border:1px solid {LINE};
    border-radius:16px;
    padding:1rem;
    box-shadow:0 4px 15px rgba(30,50,40,.035);
}}

.panel-title {{
    color:{TEXT};
    font-size:.78rem;
    font-weight:800;
    margin-bottom:.15rem;
}}

.panel-sub {{
    color:#99A59F;
    font-size:.62rem;
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
    font-size:.68rem;
    font-weight:700;
}}

.event-sub {{
    color:#98A49F;
    font-size:.6rem;
    margin-top:2px;
}}

.badge {{
    font-size:.54rem;
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

            try:
                interfaces.append((int(number), name.strip()))
            except ValueError:
                continue

        return interfaces

    except Exception:
        return [(5, "Wi-Fi")]


def reset_live_state():
    st.session_state.live_packets = 0
    st.session_state.live_bytes = 0
    st.session_state.live_started = time.time()
    st.session_state.live_protocols = Counter()
    st.session_state.live_per_second = defaultdict(int)
    st.session_state.live_rtts = []
    st.session_state.live_pending_icmp = {}
    st.session_state.live_retrans = 0
    st.session_state.live_dup_ack = 0
    st.session_state.live_ooo = 0
    st.session_state.live_rst = 0
    st.session_state.live_dns_queries = 0
    st.session_state.live_dns_responses = 0
    st.session_state.live_dns_failed = 0
    st.session_state.live_dns_success = 0
    st.session_state.live_arp_req = 0
    st.session_state.live_arp_reply = 0
    st.session_state.live_last_packets = []


def capture_live_chunk(interface_number, seconds=2):
    fields = [
        "frame.time_epoch",
        "frame.len",
        "_ws.col.Protocol",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.seq",
        "icmp.ident",
        "tcp.analysis.retransmission",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.out_of_order",
        "tcp.flags.reset",
        "dns.id",
        "dns.flags.response",
        "dns.flags.rcode",
        "arp.opcode",
    ]

    cmd = [
        "tshark",
        "-i", str(interface_number),
        "-a", f"duration:{seconds}",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]

    for field in fields:
        cmd.extend(["-e", field])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=seconds + 8,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            exc.stderr.strip() or "TShark live capture failed."
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError("TShark was not found in PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("TShark live capture timed out.") from exc

    return list(csv.reader(io.StringIO(result.stdout), delimiter="\t"))


def process_live_rows(rows):
    start = st.session_state.live_started or time.time()

    for row in rows:
        if not row:
            continue

        while len(row) < 16:
            row.append("")

        (
            epoch,
            length,
            protocol,
            src,
            dst,
            icmp_type,
            icmp_seq,
            icmp_ident,
            retrans,
            dup_ack,
            ooo,
            rst,
            dns_id,
            dns_response,
            dns_rcode,
            arp_opcode,
        ) = row[:16]

        try:
            packet_time = float(epoch)
            packet_len = int(length)
        except (ValueError, TypeError):
            continue

        st.session_state.live_packets += 1
        st.session_state.live_bytes += packet_len

        protocol = protocol.strip() or "OTHER"
        st.session_state.live_protocols[protocol] += 1

        second = max(0, int(packet_time - start))
        st.session_state.live_per_second[second] += 1

        st.session_state.live_last_packets.append(
            {
                "Time": datetime.fromtimestamp(packet_time).strftime(
                    "%H:%M:%S.%f"
                )[:-3],
                "Source": src or "-",
                "Destination": dst or "-",
                "Protocol": protocol,
                "Bytes": packet_len,
            }
        )
        st.session_state.live_last_packets = (
            st.session_state.live_last_packets[-25:]
        )

        if retrans:
            st.session_state.live_retrans += 1

        if dup_ack:
            st.session_state.live_dup_ack += 1

        if ooo:
            st.session_state.live_ooo += 1

        if rst == "1":
            st.session_state.live_rst += 1

        if icmp_type == "8" and icmp_seq:
            key = (src, dst, icmp_seq, icmp_ident)
            st.session_state.live_pending_icmp[key] = packet_time

        elif icmp_type == "0" and icmp_seq:
            key = (dst, src, icmp_seq, icmp_ident)
            request_time = st.session_state.live_pending_icmp.pop(
                key,
                None,
            )

            if request_time is not None:
                rtt = (packet_time - request_time) * 1000
                if rtt >= 0:
                    st.session_state.live_rtts.append(rtt)

        if dns_id:
            if dns_response.lower() == "true":
                st.session_state.live_dns_responses += 1

                if dns_rcode == "0":
                    st.session_state.live_dns_success += 1
                else:
                    st.session_state.live_dns_failed += 1
            else:
                st.session_state.live_dns_queries += 1

        if arp_opcode == "1":
            st.session_state.live_arp_req += 1

        elif arp_opcode == "2":
            st.session_state.live_arp_reply += 1


def live_snapshot():
    started = st.session_state.live_started or time.time()
    elapsed = max(time.time() - started, 0.001)

    packets = st.session_state.live_packets
    total_bytes = st.session_state.live_bytes
    rtts = list(st.session_state.live_rtts)

    dns_responses = st.session_state.live_dns_responses
    dns_success = st.session_state.live_dns_success

    dns_success_rate = (
        dns_success / dns_responses * 100
        if dns_responses
        else None
    )

    # Pending ICMP requests are not immediately called lost.
    # They may still receive a reply in a later live capture chunk.
    loss = 0.0

    if st.session_state.live_pending_icmp:
        matched = len(rtts)
        pending = len(st.session_state.live_pending_icmp)
        total_requests = matched + pending

        if total_requests:
            loss = pending / total_requests * 100

    return {
        "packets": packets,
        "bytes": total_bytes,
        "elapsed": elapsed,
        "throughput": total_bytes * 8 / elapsed,
        "packet_rate": packets / elapsed,
        "protocols": dict(
            st.session_state.live_protocols.most_common()
        ),
        "rtts": rtts,
        "min_rtt": min(rtts) if rtts else None,
        "avg_rtt": sum(rtts) / len(rtts) if rtts else None,
        "max_rtt": max(rtts) if rtts else None,
        "loss": loss,
        "retrans": st.session_state.live_retrans,
        "dup_ack": st.session_state.live_dup_ack,
        "ooo": st.session_state.live_ooo,
        "rst": st.session_state.live_rst,
        "dns_queries": st.session_state.live_dns_queries,
        "dns_responses": dns_responses,
        "dns_failed": st.session_state.live_dns_failed,
        "dns_success": dns_success_rate,
        "arp_req": st.session_state.live_arp_req,
        "arp_reply": st.session_state.live_arp_reply,
        "traffic": [
            st.session_state.live_per_second[i]
            for i in range(
                max(st.session_state.live_per_second.keys(), default=-1) + 1
            )
        ],
        "last_packets": list(st.session_state.live_last_packets),
    }


def live_health(live):
    score = 100

    if live["loss"] > 0:
        score -= min(live["loss"] * 0.5, 20)

    if live["avg_rtt"] is not None:
        if live["avg_rtt"] > 100:
            score -= 10
        elif live["avg_rtt"] > 50:
            score -= 5

    score -= min(live["retrans"], 10)

    if live["dup_ack"] > 5:
        score -= 3

    if live["ooo"] > 5:
        score -= 3

    if live["rst"] > 5:
        score -= 5

    if live["dns_success"] is not None and live["dns_success"] < 90:
        score -= 10

    return max(0, min(100, int(score)))


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

        if mode == "Live Monitoring":
            reset_live_state()

        st.rerun()

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

    st.markdown(
        '<div class="side-label">Analysis Engine</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="summary-item">
            <div class="summary-label">PACKET ENGINE</div>
            <div class="summary-value">TShark 4.x</div>
            <div class="summary-label" style="margin-top:4px;">
                Wireshark compatible • Python analysis
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

    if st.session_state.live_started is None:
        reset_live_state()

    try:
        rows = capture_live_chunk(
            st.session_state.live_interface,
            seconds=2,
        )
        process_live_rows(rows)
    except Exception as exc:
        st.error(f"Live capture error: {exc}")
        st.info(
            "Make sure TShark/Npcap is installed and the selected "
            "interface can be captured."
        )
        st.stop()

    LIVE = live_snapshot()

    I = {
        "requests": 0,
        "replies": len(LIVE["rtts"]),
        "loss": LIVE["loss"],
        "rtts": LIVE["rtts"],
        "avg_rtt": LIVE["avg_rtt"] or 0.0,
        "min_rtt": LIVE["min_rtt"] or 0.0,
        "max_rtt": LIVE["max_rtt"] or 0.0,
    }

    T = {
        "total": 0,
        "retransmissions": LIVE["retrans"],
        "duplicate_acks": LIVE["dup_ack"],
        "out_of_order": LIVE["ooo"],
        "rst": LIVE["rst"],
    }

    D = {
        "queries": LIVE["dns_queries"],
        "responses": LIVE["dns_responses"],
        "successful": st.session_state.live_dns_success,
        "failed": LIVE["dns_failed"],
        "success_rate": LIVE["dns_success"] or 0.0,
        "rtts": [],
        "avg_rtt": 0.0,
        "min_rtt": 0.0,
        "max_rtt": 0.0,
    }

    A = {
        "requests": LIVE["arp_req"],
        "replies": LIVE["arp_reply"],
        "broadcasts": 0,
    }

    TH = {
        "packets": LIVE["packets"],
        "bytes": LIVE["bytes"],
        "duration": LIVE["elapsed"],
        "packet_rate": LIVE["packet_rate"],
        "throughput": LIVE["throughput"],
        "traffic": LIVE["traffic"],
    }

    PROTOCOLS = LIVE["protocols"]
    RTT_VALUES = LIVE["rtts"]
    TRAFFIC = LIVE["traffic"]

    HEALTH = live_health(LIVE)
    STATUS = status_for_health(HEALTH)


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
        st.markdown('<div class="health">', unsafe_allow_html=True)

        badge_color = (
            GREEN
            if HEALTH >= 75
            else AMBER
            if HEALTH >= 60
            else RED
        )

        st.markdown(
            f"""
            <div class="health-label">Network Health Score</div>
            <div class="health-value">
                {HEALTH:.0f}
                <span style="font-size:1rem;color:#8A9891;"> /100</span>
            </div>
            <div class="health-badge"
                 style="color:{badge_color};background:{badge_color}18;">
                {STATUS}
            </div>
            <div class="health-text">
                Combined project score based on ICMP latency and loss,
                TCP reliability, DNS performance and traffic indicators.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("</div>", unsafe_allow_html=True)

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
            )

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
                text="No matched ICMP RTT data",
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
                f"{live['packets']:,}",
                "Session total",
                TEAL,
            ),
            (
                "↗",
                "Throughput",
                format_kbps(live["throughput"]),
                "Current session rate",
                GREEN,
            ),
            (
                "◷",
                "RTT",
                (
                    f"{live['avg_rtt']:.2f} ms"
                    if live["avg_rtt"] is not None
                    else "N/A"
                ),
                "Matched ICMP",
                PURPLE,
            ),
            (
                "!",
                "Retransmissions",
                live["retrans"],
                "TCP",
                AMBER,
            ),
            (
                "⌁",
                "ARP Requests",
                live["arp_req"],
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

elif st.session_state.module == "Network Topology":

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
