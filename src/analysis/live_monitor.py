import subprocess
import time
import threading
import shutil
import os
from collections import Counter, defaultdict
from datetime import datetime

INTERFACE = "5"
DISPLAY_FILTER = "ip or arp"


def start_tshark(interface=INTERFACE, display_filter=DISPLAY_FILTER):
    tshark = shutil.which("tshark")
    if not tshark:
        windows_tshark = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.isfile(windows_tshark):
            tshark = windows_tshark
    if not tshark:
        raise RuntimeError(
            "Live monitoring requires TShark. Install Wireshark with TShark "
            "or use Offline Analysis."
        )
    command = [
        tshark, "-i", str(interface), "-l",
        "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.flags",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.duplicate_ack",
        "-e", "tcp.analysis.out_of_order",
        "-e", "dns.flags.response",
        "-e", "dns.flags.rcode",
        "-e", "dns.id",
        "-e", "icmp.type",
        "-e", "icmp.ident",
        "-e", "icmp.seq",
        "-e", "arp.opcode",
    ]
    if display_filter:
        command.extend(["-Y", display_filter])
    return subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )


def safe_int(value, default=None):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def new_stats():
    return {
        "start_time": time.time(),
        "total_packets": 0, "total_bytes": 0, "protocols": Counter(),
        "tcp_retransmissions": 0, "tcp_duplicate_acks": 0,
        "tcp_out_of_order": 0, "tcp_rst": 0,
        "dns_queries": 0, "dns_responses": 0, "dns_success": 0,
        "dns_failed": 0, "dns_rtts": [],
        "icmp_requests": 0, "icmp_replies": 0,
        "icmp_matched_replies": 0, "icmp_rtts": [],
        "arp_requests": 0, "arp_replies": 0,
        "icmp_pending": {}, "dns_pending": {},
        "traffic_per_second": defaultdict(int),
        "last_packets": [],
    }


def calculate_health(packet_loss, tcp_retransmissions, tcp_duplicate_acks,
                     tcp_out_of_order, tcp_rst, dns_success_rate):
    score = 100
    if packet_loss >= 10: score -= 25
    elif packet_loss >= 5: score -= 15
    elif packet_loss > 1: score -= 5
    if tcp_retransmissions >= 10: score -= 15
    elif tcp_retransmissions >= 5: score -= 8
    elif tcp_retransmissions > 0: score -= 3
    if tcp_duplicate_acks >= 10: score -= 10
    elif tcp_duplicate_acks >= 5: score -= 5
    elif tcp_duplicate_acks > 0: score -= 2
    if tcp_out_of_order >= 5: score -= 8
    elif tcp_out_of_order > 0: score -= 3
    if tcp_rst >= 10: score -= 10
    elif tcp_rst >= 5: score -= 5
    elif tcp_rst > 0: score -= 2
    if dns_success_rate < 80: score -= 10
    elif dns_success_rate < 95: score -= 5
    score = max(0, min(100, score))
    return score, "GOOD" if score >= 80 else ("WARNING" if score >= 60 else "CRITICAL")


def process_packet_line(line, stats):
    fields = line.strip().split("|")
    if len(fields) < 16:
        return False
    (timestamp, frame_length, protocol, ip_src, ip_dst, tcp_flags,
     tcp_retransmission, tcp_duplicate_ack, tcp_out_of_order,
     dns_response, dns_rcode, dns_id, icmp_type, icmp_ident,
     icmp_seq, arp_opcode) = fields[:16]

    try:
        packet_time = float(timestamp)
    except (ValueError, TypeError):
        return False

    stats["total_packets"] += 1
    stats["total_bytes"] += safe_int(frame_length, 0)

    start_t = stats["start_time"]
    second_idx = max(0, int(packet_time - start_t))
    stats["traffic_per_second"][second_idx] += 1

    stats["last_packets"].append({
        "Time": datetime.fromtimestamp(packet_time).strftime("%H:%M:%S.%f")[:-3],
        "Source": ip_src or "-",
        "Destination": ip_dst or "-",
        "Protocol": protocol or "OTHER",
        "Bytes": safe_int(frame_length, 0),
    })
    stats["last_packets"] = stats["last_packets"][-25:]

    if protocol:
        stats["protocols"][protocol] += 1

    if protocol == "TCP":
        if tcp_retransmission: stats["tcp_retransmissions"] += 1
        if tcp_duplicate_ack: stats["tcp_duplicate_acks"] += 1
        if tcp_out_of_order: stats["tcp_out_of_order"] += 1
        if safe_int(tcp_flags, 0) & 0x04: stats["tcp_rst"] += 1

    if protocol == "DNS":
        if dns_response.lower() == "true":
            stats["dns_responses"] += 1
            if safe_int(dns_rcode, 0) == 0: stats["dns_success"] += 1
            else: stats["dns_failed"] += 1
            if dns_id:
                start = stats["dns_pending"].pop(
                    (ip_dst, ip_src, dns_id), None
                )
                if start is not None:
                    rtt = (packet_time - start) * 1000
                    if 0 <= rtt <= 10000: stats["dns_rtts"].append(rtt)
        else:
            stats["dns_queries"] += 1
            if dns_id:
                stats["dns_pending"][(ip_src, ip_dst, dns_id)] = packet_time

    if protocol == "ICMP":
        t = safe_int(icmp_type)
        key = (ip_src, ip_dst, icmp_ident, icmp_seq)
        reverse = (ip_dst, ip_src, icmp_ident, icmp_seq)
        if t == 8:
            stats["icmp_requests"] += 1
            stats["icmp_pending"][key] = packet_time
        elif t == 0:
            stats["icmp_replies"] += 1
            start = stats["icmp_pending"].pop(reverse, None)
            if start is not None:
                stats["icmp_matched_replies"] += 1
                rtt = (packet_time - start) * 1000
                if 0 <= rtt <= 10000: stats["icmp_rtts"].append(rtt)

    if protocol == "ARP":
        opcode = safe_int(arp_opcode)
        if opcode == 1: stats["arp_requests"] += 1
        elif opcode == 2: stats["arp_replies"] += 1

    return True


def calculate_snapshot(stats):
    elapsed = max(time.time() - stats["start_time"], 0.001)
    packets = stats["total_packets"]
    bytes_ = stats["total_bytes"]
    packet_loss = (
        max(0, (stats["icmp_requests"] - stats["icmp_matched_replies"])
            / stats["icmp_requests"] * 100)
        if stats["icmp_requests"] else 0.0
    )
    dns_success_rate = (
        stats["dns_success"] / stats["dns_responses"] * 100
        if stats["dns_responses"] else 0.0
    )
    rtts = stats["icmp_rtts"]
    dns_rtts = stats["dns_rtts"]
    health, status = calculate_health(
        packet_loss, stats["tcp_retransmissions"],
        stats["tcp_duplicate_acks"], stats["tcp_out_of_order"],
        stats["tcp_rst"], dns_success_rate
    )
    return {
        "elapsed": elapsed, "total_packets": packets, "total_bytes": bytes_,
        "packet_rate": packets / elapsed,
        "throughput_bps": bytes_ * 8 / elapsed,
        "throughput_kbps": bytes_ * 8 / elapsed / 1000,
        "protocols": Counter(stats["protocols"]),
        "icmp_requests": stats["icmp_requests"],
        "icmp_replies": stats["icmp_replies"],
        "icmp_matched_replies": stats["icmp_matched_replies"],
        "packet_loss": packet_loss,
        "min_icmp_rtt": min(rtts) if rtts else 0.0,
        "avg_icmp_rtt": sum(rtts) / len(rtts) if rtts else 0.0,
        "max_icmp_rtt": max(rtts) if rtts else 0.0,
        "tcp_retransmissions": stats["tcp_retransmissions"],
        "tcp_duplicate_acks": stats["tcp_duplicate_acks"],
        "tcp_out_of_order": stats["tcp_out_of_order"],
        "tcp_rst": stats["tcp_rst"],
        "dns_queries": stats["dns_queries"],
        "dns_responses": stats["dns_responses"],
        "dns_success": stats["dns_success"],
        "dns_failed": stats["dns_failed"],
        "dns_success_rate": dns_success_rate,
        "min_dns_rtt": min(dns_rtts) if dns_rtts else 0.0,
        "avg_dns_rtt": sum(dns_rtts) / len(dns_rtts) if dns_rtts else 0.0,
        "max_dns_rtt": max(dns_rtts) if dns_rtts else 0.0,
        "arp_requests": stats["arp_requests"],
        "arp_replies": stats["arp_replies"],
        "health_score": health, "health_status": status,
        "traffic": [stats["traffic_per_second"][i] for i in range(max(stats["traffic_per_second"].keys(), default=-1) + 1)],
        "last_packets": list(stats["last_packets"]),
        "icmp_rtts": list(stats["icmp_rtts"]),
        "dns_rtts": list(stats["dns_rtts"]),
    }


class LiveMonitor:
    """Background TShark capture that Streamlit can safely read."""

    def __init__(self, interface=INTERFACE, display_filter=DISPLAY_FILTER):
        self.interface = str(interface)
        self.display_filter = display_filter
        self.process = None
        self.thread = None
        self.running = False
        self._lock = threading.Lock()
        self._stats = None

    def start(self):
        if self.running:
            return
        self._stats = new_stats()
        try:
            self.process = start_tshark(self.interface, self.display_filter)
        except (OSError, RuntimeError):
            self.process = None
            self.running = False
            return
        self.running = True
        self.thread = threading.Thread(
            target=self._reader_loop, daemon=True,
            name="LiveMonitorTSharkReader"
        )
        self.thread.start()

    def _reader_loop(self):
        try:
            if self.process and self.process.stdout:
                for line in self.process.stdout:
                    if not self.running:
                        break
                    with self._lock:
                        process_packet_line(line, self._stats)
        finally:
            self.running = False

    def snapshot(self):
        if self._stats is None:
            return calculate_snapshot(new_stats())
        with self._lock:
            return calculate_snapshot(self._stats)

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: self.process.kill()
                except Exception: pass
            except Exception:
                pass
        self.process = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
        self.thread = None


# ============================================================
# ORIGINAL TERMINAL MODE
# ============================================================

def main():
    print("=" * 65)
    print("STARTING LIVE NETWORK MONITOR")
    print("=" * 65)
    print(f"Interface: Wi-Fi ({INTERFACE})")
    print("Starting TShark...\n")

    monitor = LiveMonitor()
    monitor.start()

    try:
        while monitor.running:
            s = monitor.snapshot()
            print(
                f"Packets: {s['total_packets']} | "
                f"Throughput: {s['throughput_kbps']:.2f} Kbps | "
                f"ICMP RTT: {s['avg_icmp_rtt']:.2f} ms | "
                f"DNS success: {s['dns_success_rate']:.2f}% | "
                f"Health: {s['health_score']}/100 ({s['health_status']})"
            )
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping live monitor...")
    finally:
        monitor.stop()
        print("Live monitoring stopped.")


if __name__ == "__main__":
    main()
