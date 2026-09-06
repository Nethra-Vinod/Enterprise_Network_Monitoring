from __future__ import annotations

import csv
import io
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, PcapNgReader

# ---------------------------------------------------------------------------
# Enterprise Network Monitor - unified offline analysis engine
# ---------------------------------------------------------------------------
# All offline dashboard modules use this single file as their source of truth.
# Packet data is read with TShark, the command-line engine shipped with
# Wireshark. This avoids nested asyncio/event-loop issues in Streamlit.
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = PROJECT_ROOT / "captures" / "raw"

TCP_PCAP = CAPTURE_DIR / "tcp_test.pcapng"
ICMP_PCAP = CAPTURE_DIR / "icmp_test.pcapng"
DNS_PCAP = CAPTURE_DIR / "dns_test.pcapng"
USE_TSHARK_OFFLINE = os.getenv("TECHNOVA_USE_TSHARK_OFFLINE") == "1"


def _require_tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        win_path = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.isfile(win_path):
            return win_path
        raise RuntimeError(
            "TShark was not found in PATH. Install Wireshark with TShark "
            "and verify that `tshark -v` works in Command Prompt."
        )
    return exe


def _read_packets(pcap_file: Path) -> list:
    """Read PCAPNG files without requiring the Wireshark executable."""
    with PcapNgReader(str(pcap_file)) as capture:
        return list(capture)


def _has_tshark() -> bool:
    return USE_TSHARK_OFFLINE and (
        shutil.which("tshark") is not None or os.path.isfile(
        r"C:\Program Files\Wireshark\tshark.exe"
        )
    )


def _run_tshark(
    pcap_file: Path,
    fields: tuple[str, ...],
    display_filter: str = "",
) -> list[list[str]]:
    """Return TShark field output as rows."""
    if not pcap_file.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_file}")

    cmd = [
        _require_tshark(),
        "-r", str(pcap_file),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]

    for field in fields:
        cmd.extend(["-e", field])

    if display_filter:
        cmd.extend(["-Y", display_filter])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            exc.stderr.strip() or f"TShark failed for {pcap_file.name}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"TShark timed out while analysing {pcap_file.name}."
        ) from exc

    reader = csv.reader(io.StringIO(result.stdout), delimiter="\t")
    return [row for row in reader if any(cell.strip() for cell in row)]


def _count(pcap_file: Path, display_filter: str) -> int:
    if not _has_tshark():
        packets = _read_packets(pcap_file)
        if display_filter == "tcp":
            return sum(packet.haslayer(TCP) for packet in packets)
        if display_filter == "arp.opcode == 1":
            return sum(packet.haslayer(ARP) and packet[ARP].op == 1 for packet in packets)
        if display_filter == "arp.opcode == 2":
            return sum(packet.haslayer(ARP) and packet[ARP].op == 2 for packet in packets)
        if display_filter == "arp && eth.dst == ff:ff:ff:ff:ff:ff":
            return sum(
                packet.haslayer(ARP)
                and packet.haslayer(Ether)
                and packet[Ether].dst.lower() == "ff:ff:ff:ff:ff:ff"
                for packet in packets
            )
        if display_filter == "tcp.flags.reset == 1":
            return sum(packet.haslayer(TCP) and "R" in str(packet[TCP].flags) for packet in packets)
        return 0
    return len(_run_tshark(pcap_file, ("frame.number",), display_filter))


def analyze_icmp() -> dict:
    if not _has_tshark():
        packets = _read_packets(ICMP_PCAP)
        pending: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
        rtts: list[float] = []
        requests = replies = 0
        for packet in packets:
            if not packet.haslayer(IP) or not packet.haslayer(ICMP):
                continue
            ip = packet[IP]
            icmp = packet[ICMP]
            timestamp = float(packet.time)
            key = (ip.src, ip.dst, str(getattr(icmp, "seq", "")), str(getattr(icmp, "id", "")))
            if icmp.type == 8:
                requests += 1
                pending[key].append(timestamp)
            elif icmp.type == 0:
                replies += 1
                reverse_key = (ip.dst, ip.src, str(getattr(icmp, "seq", "")), str(getattr(icmp, "id", "")))
                if pending[reverse_key]:
                    rtts.append((timestamp - pending[reverse_key].pop(0)) * 1000)
        matched = len(rtts)
        loss = ((requests - matched) / requests * 100) if requests else 0.0
        return {
            "requests": requests, "replies": replies, "matched_replies": matched,
            "loss": max(0.0, min(100.0, loss)), "rtts": rtts,
            "avg_rtt": mean(rtts) if rtts else 0.0,
            "min_rtt": min(rtts) if rtts else 0.0,
            "max_rtt": max(rtts) if rtts else 0.0,
        }
    rows = _run_tshark(
        ICMP_PCAP,
        (
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "icmp.type",
            "icmp.seq",
            "icmp.ident",
        ),
        "icmp",
    )

    pending: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    rtts: list[float] = []
    requests = 0
    replies = 0

    for row in rows:
        if len(row) < 6:
            continue

        try:
            timestamp = float(row[0])
        except (TypeError, ValueError):
            continue

        src, dst, icmp_type, seq, ident = row[1:6]
        if not seq:
            continue

        if icmp_type == "8":  # Echo request
            requests += 1
            pending[(src, dst, seq, ident)].append(timestamp)

        elif icmp_type == "0":  # Echo reply
            replies += 1
            key = (dst, src, seq, ident)
            if pending[key]:
                request_time = pending[key].pop(0)
                rtt = (timestamp - request_time) * 1000
                if rtt >= 0:
                    rtts.append(rtt)

    # Packet loss is based on echo requests for which no corresponding
    # echo reply was observed.
    matched = len(rtts)
    loss = ((requests - matched) / requests * 100) if requests else 0.0

    return {
        "requests": requests,
        "replies": replies,
        "matched_replies": matched,
        "loss": max(0.0, min(100.0, loss)),
        "rtts": rtts,
        "avg_rtt": mean(rtts) if rtts else 0.0,
        "min_rtt": min(rtts) if rtts else 0.0,
        "max_rtt": max(rtts) if rtts else 0.0,
    }


def analyze_dns() -> dict:
    if not _has_tshark():
        packets = _read_packets(DNS_PCAP)
        queries = responses = successful = failed = 0
        a_queries = aaaa_queries = other_queries = 0
        rtts: list[float] = []
        pending: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        for packet in packets:
            if not packet.haslayer(IP) or not packet.haslayer(DNS):
                continue
            ip, dns = packet[IP], packet[DNS]
            key = (ip.src, ip.dst, int(dns.id))
            timestamp = float(packet.time)
            if dns.qr == 0:
                queries += 1
                pending[key].append(timestamp)
                if packet.haslayer(DNSQR):
                    qtype = int(packet[DNSQR].qtype)
                    if qtype == 1:
                        a_queries += 1
                    elif qtype == 28:
                        aaaa_queries += 1
                    else:
                        other_queries += 1
            else:
                responses += 1
                if int(dns.rcode) == 0:
                    successful += 1
                else:
                    failed += 1
                reverse_key = (ip.dst, ip.src, int(dns.id))
                if pending[reverse_key]:
                    rtts.append((timestamp - pending[reverse_key].pop(0)) * 1000)
        return {
            "queries": queries, "responses": responses, "successful": successful,
            "failed": failed, "success_rate": successful / responses * 100 if responses else 0.0,
            "rtts": rtts, "min_rtt": min(rtts) if rtts else 0.0,
            "avg_rtt": mean(rtts) if rtts else 0.0,
            "max_rtt": max(rtts) if rtts else 0.0,
            "a_queries": a_queries, "aaaa_queries": aaaa_queries,
            "other_queries": other_queries,
        }
    rows = _run_tshark(
        DNS_PCAP,
        (
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "dns.id",
            "dns.flags.response",
            "dns.flags.rcode",
            "dns.qry.type",
        ),
        "dns",
    )

    queries = 0
    responses = 0
    successful = 0
    failed = 0
    a_queries = 0
    aaaa_queries = 0
    other_queries = 0
    rtts: list[float] = []

    # Match a DNS response to the most recent preceding query with the same
    # transaction ID and reversed client/server addresses.
    pending: dict[tuple[str, str, str], list[float]] = defaultdict(list)

    for row in rows:
        if len(row) < 7:
            continue

        try:
            timestamp = float(row[0])
        except (TypeError, ValueError):
            continue

        src, dst, txid, response_flag, rcode, qtype = row[1:7]
        key = (src, dst, txid)

        if response_flag.lower() != "true":
            queries += 1
            pending[key].append(timestamp)

            if qtype == "1":
                a_queries += 1
            elif qtype == "28":
                aaaa_queries += 1
            else:
                other_queries += 1

        else:
            responses += 1
            if rcode == "0":
                successful += 1
            else:
                failed += 1

            reverse_key = (dst, src, txid)
            if pending[reverse_key]:
                query_time = pending[reverse_key].pop(0)
                rtt = (timestamp - query_time) * 1000
                if rtt >= 0:
                    rtts.append(rtt)

    return {
        "queries": queries,
        "responses": responses,
        "successful": successful,
        "failed": failed,
        "success_rate": successful / responses * 100 if responses else 0.0,
        "rtts": rtts,
        "min_rtt": min(rtts) if rtts else 0.0,
        "avg_rtt": mean(rtts) if rtts else 0.0,
        "max_rtt": max(rtts) if rtts else 0.0,
        "a_queries": a_queries,
        "aaaa_queries": aaaa_queries,
        "other_queries": other_queries,
    }


def analyze_tcp() -> dict:
    if not _has_tshark():
        packets = _read_packets(TCP_PCAP)
        tcp_packets = [packet[TCP] for packet in packets if packet.haslayer(TCP)]
        seen_sequences: set[tuple[str, str, int, int]] = set()
        next_sequence: dict[tuple[str, str], int] = {}
        retransmissions = duplicate_acks = out_of_order = 0
        for packet in tcp_packets:
            flow = (packet.underlayer.src, packet.underlayer.dst) if packet.underlayer else ("", "")
            sequence_key = (flow[0], flow[1], int(packet.seq), int(packet.ack), int(packet.flags))
            payload_length = len(bytes(packet.payload))
            if sequence_key in seen_sequences and payload_length:
                retransmissions += 1
            seen_sequences.add(sequence_key)
            if packet.flags == "A" and payload_length == 0:
                reverse_flow = (flow[1], flow[0])
                if reverse_flow in next_sequence and int(packet.ack) == next_sequence[reverse_flow]:
                    duplicate_acks += 1
            if payload_length:
                expected = next_sequence.get(flow)
                if expected is not None and int(packet.seq) > expected:
                    out_of_order += 1
                next_sequence[flow] = max(expected or 0, int(packet.seq) + payload_length)
        return {
            "total": len(tcp_packets), "retransmissions": retransmissions,
            "duplicate_acks": duplicate_acks, "out_of_order": out_of_order,
            "rst": sum("R" in str(packet.flags) for packet in tcp_packets),
        }
    total = _count(TCP_PCAP, "tcp")
    retransmissions = _count(TCP_PCAP, "tcp.analysis.retransmission")
    duplicate_acks = _count(TCP_PCAP, "tcp.analysis.duplicate_ack")
    out_of_order = _count(TCP_PCAP, "tcp.analysis.out_of_order")
    rst = _count(TCP_PCAP, "tcp.flags.reset == 1")

    return {
        "total": total,
        "retransmissions": retransmissions,
        "duplicate_acks": duplicate_acks,
        "out_of_order": out_of_order,
        "rst": rst,
    }


def analyze_arp() -> dict:
    if not _has_tshark():
        packets = _read_packets(TCP_PCAP)
        arp_packets = [packet for packet in packets if packet.haslayer(ARP)]
        return {
            "requests": sum(packet[ARP].op == 1 for packet in arp_packets),
            "replies": sum(packet[ARP].op == 2 for packet in arp_packets),
            "broadcasts": sum(
                packet.haslayer(Ether)
                and packet[Ether].dst.lower() == "ff:ff:ff:ff:ff:ff"
                for packet in arp_packets
            ),
        }
    requests = _count(TCP_PCAP, "arp.opcode == 1")
    replies = _count(TCP_PCAP, "arp.opcode == 2")
    broadcasts = _count(
        TCP_PCAP,
        "arp && eth.dst == ff:ff:ff:ff:ff:ff",
    )
    return {
        "requests": requests,
        "replies": replies,
        "broadcasts": broadcasts,
    }


def analyze_throughput() -> dict:
    if not _has_tshark():
        packets = _read_packets(TCP_PCAP)
        timestamps = [float(packet.time) for packet in packets]
        total_bytes = sum(len(packet) for packet in packets)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        first_timestamp = timestamps[0] if timestamps else None
        per_second = Counter(
            int(timestamp - first_timestamp) for timestamp in timestamps
        ) if first_timestamp is not None else Counter()
        traffic = [per_second[i] for i in range(int(duration) + 1)] if timestamps else []
        return {
            "capture": TCP_PCAP.name, "packets": len(packets), "bytes": total_bytes,
            "duration": duration, "throughput": total_bytes * 8 / duration if duration else 0.0,
            "packet_rate": len(packets) / duration if duration else 0.0,
            "traffic": traffic,
        }
    rows = _run_tshark(
        TCP_PCAP,
        (
            "frame.number",
            "frame.time_epoch",
            "frame.len",
        ),
    )

    packets = 0
    total_bytes = 0
    timestamps: list[float] = []
    per_second = Counter()

    first_timestamp = None

    for row in rows:
        if len(row) < 3:
            continue
        try:
            timestamp = float(row[1])
            length = int(row[2])
        except (TypeError, ValueError):
            continue

        packets += 1
        total_bytes += length
        timestamps.append(timestamp)

        if first_timestamp is None:
            first_timestamp = timestamp

        per_second[int(timestamp - first_timestamp)] += 1

    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    throughput_bps = total_bytes * 8 / duration if duration > 0 else 0.0
    packet_rate = packets / duration if duration > 0 else 0.0

    traffic = (
        [per_second[i] for i in range(int(duration) + 1)]
        if timestamps
        else []
    )

    return {
        "capture": TCP_PCAP.name,
        "packets": packets,
        "bytes": total_bytes,
        "duration": duration,
        "throughput": throughput_bps,
        "packet_rate": packet_rate,
        "traffic": traffic,
    }


def analyze_protocols() -> dict:
    if not _has_tshark():
        packets = _read_packets(TCP_PCAP)
        protocols = Counter()
        for packet in packets:
            if packet.haslayer(TCP):
                protocols["TCP"] += 1
            elif packet.haslayer(ARP):
                protocols["ARP"] += 1
            elif packet.haslayer(IP):
                protocols["IP"] += 1
            else:
                protocols[packet.lastlayer().__class__.__name__] += 1
        return dict(protocols.most_common())
    rows = _run_tshark(
        TCP_PCAP,
        ("_ws.col.Protocol",),
    )
    protocols = Counter()

    for row in rows:
        if not row:
            continue
        protocol = row[0].strip()
        if protocol:
            protocols[protocol] += 1

    return dict(protocols.most_common())


def calculate_health_score(icmp: dict, dns: dict, tcp: dict) -> int:
    """Project-specific reliability indicator, not an industry standard."""
    score = 100

    if icmp["loss"] > 0:
        score -= min(icmp["loss"] * 0.5, 20)

    if icmp["avg_rtt"] > 100:
        score -= 10
    elif icmp["avg_rtt"] > 50:
        score -= 5

    if tcp["retransmissions"] > 0:
        score -= min(tcp["retransmissions"], 10)

    if tcp["duplicate_acks"] > 5:
        score -= 3

    if tcp["out_of_order"] > 5:
        score -= 3

    if tcp["rst"] > 5:
        score -= 5

    if dns["success_rate"] < 90:
        score -= 10

    if dns["avg_rtt"] > 200:
        score -= 5
    elif dns["avg_rtt"] > 100:
        score -= 3

    return max(0, min(100, int(score)))


def get_status(score: int) -> str:
    if score >= 90:
        return "HEALTHY"
    if score >= 75:
        return "GOOD"
    if score >= 60:
        return "MONITOR"
    return "REVIEW REQUIRED"


def analyze_all() -> dict:
    """Single source of truth consumed by the offline Streamlit dashboard."""
    icmp = analyze_icmp()
    dns = analyze_dns()
    tcp = analyze_tcp()
    arp = analyze_arp()
    throughput = analyze_throughput()
    protocols = analyze_protocols()

    health = calculate_health_score(icmp, dns, tcp)

    return {
        "icmp": icmp,
        "dns": dns,
        "tcp": tcp,
        "arp": arp,
        "throughput": throughput,
        "protocols": protocols,
        "health": health,
        "status": get_status(health),
    }


def main() -> None:
    data = analyze_all()
    t = data["throughput"]
    i = data["icmp"]
    d = data["dns"]
    tcp = data["tcp"]
    a = data["arp"]

    print("=" * 64)
    print("UNIFIED NETWORK ANALYSIS")
    print("=" * 64)

    print("\nNETWORK OVERVIEW")
    print("-" * 40)
    print(f"Total packets          : {t['packets']}")
    print(f"Total bytes            : {t['bytes']}")
    print(f"Capture duration       : {t['duration']:.2f} seconds")
    print(f"Packet rate            : {t['packet_rate']:.2f} packets/sec")
    print(f"Average throughput     : {t['throughput'] / 1000:.2f} Kbps")

    print("\nPROTOCOL DISTRIBUTION")
    print("-" * 40)
    for protocol, count in data["protocols"].items():
        print(f"{protocol:<20} : {count}")

    print("\nICMP / RTT PERFORMANCE")
    print("-" * 40)
    print(f"ICMP requests          : {i['requests']}")
    print(f"ICMP replies           : {i['replies']}")
    print(f"Packet loss            : {i['loss']:.2f}%")
    print(f"Minimum RTT            : {i['min_rtt']:.2f} ms")
    print(f"Average RTT            : {i['avg_rtt']:.2f} ms")
    print(f"Maximum RTT            : {i['max_rtt']:.2f} ms")

    print("\nTCP PERFORMANCE / RELIABILITY")
    print("-" * 40)
    print(f"TCP packets            : {tcp['total']}")
    print(f"Retransmissions        : {tcp['retransmissions']}")
    print(f"Duplicate ACKs         : {tcp['duplicate_acks']}")
    print(f"Out-of-order packets   : {tcp['out_of_order']}")
    print(f"RST packets            : {tcp['rst']}")

    print("\nDNS PERFORMANCE")
    print("-" * 40)
    print(f"DNS queries            : {d['queries']}")
    print(f"DNS responses          : {d['responses']}")
    print(f"Successful responses   : {d['successful']}")
    print(f"Failed responses       : {d['failed']}")
    print(f"DNS success rate       : {d['success_rate']:.2f}%")
    print(f"Minimum DNS RTT        : {d['min_rtt']:.2f} ms")
    print(f"Average DNS RTT        : {d['avg_rtt']:.2f} ms")
    print(f"Maximum DNS RTT        : {d['max_rtt']:.2f} ms")

    print("\nARP ACTIVITY")
    print("-" * 40)
    print(f"ARP requests           : {a['requests']}")
    print(f"ARP replies            : {a['replies']}")
    print(f"ARP broadcasts         : {a['broadcasts']}")

    print("\nSECURITY / RELIABILITY")
    print("-" * 40)
    print(f"TCP retransmissions    : {tcp['retransmissions']}")
    print(f"TCP duplicate ACKs     : {tcp['duplicate_acks']}")
    print(f"TCP out-of-order       : {tcp['out_of_order']}")
    print(f"TCP RST packets        : {tcp['rst']}")
    print(f"DNS failures           : {d['failed']}")

    print("\n" + "=" * 64)
    print("OVERALL NETWORK HEALTH")
    print("=" * 64)
    print(f"Network Health Score   : {data['health']} / 100")
    print(f"Overall Status         : {data['status']}")
    print("=" * 64)


if __name__ == "__main__":
    main()
