import pyshark


PCAP_FILE = r"captures\raw\tcp_test.pcapng"


def count_packets(display_filter):
    capture = pyshark.FileCapture(
        PCAP_FILE,
        display_filter=display_filter
    )

    count = 0

    for _ in capture:
        count += 1

    capture.close()

    return count


def analyze_security():

    print("=" * 60)
    print("NETWORK SECURITY ANALYSIS")
    print("=" * 60)

    # ---------------------------------------------------------
    # TCP SECURITY / RELIABILITY INDICATORS
    # ---------------------------------------------------------

    retransmissions = count_packets(
        "tcp.analysis.retransmission"
    )

    duplicate_acks = count_packets(
        "tcp.analysis.duplicate_ack"
    )

    out_of_order = count_packets(
        "tcp.analysis.out_of_order"
    )

    rst_packets = count_packets(
        "tcp.flags.reset == 1"
    )

    # ---------------------------------------------------------
    # DNS INDICATORS
    # ---------------------------------------------------------

    dns_failed = count_packets(
        "dns.flags.response == 1 && dns.flags.rcode != 0"
    )

    dns_responses = count_packets(
        "dns.flags.response == 1"
    )

    # ---------------------------------------------------------
    # ARP INDICATORS
    # ---------------------------------------------------------

    arp_requests = count_packets(
        "arp.opcode == 1"
    )

    arp_replies = count_packets(
        "arp.opcode == 2"
    )

    arp_broadcasts = count_packets(
        "arp && eth.dst == ff:ff:ff:ff:ff:ff"
    )

    # ---------------------------------------------------------
    # DNS SUCCESS RATE
    # ---------------------------------------------------------

    if dns_responses > 0:
        dns_success_rate = (
            (dns_responses - dns_failed)
            / dns_responses
        ) * 100
    else:
        dns_success_rate = 0

    # ---------------------------------------------------------
    # SECURITY FINDINGS
    # ---------------------------------------------------------

    findings = []

    if retransmissions > 0:
        findings.append(
            "WARNING: TCP retransmissions detected"
        )

    if duplicate_acks > 0:
        findings.append(
            "INFO: TCP duplicate ACK activity detected"
        )

    if out_of_order > 0:
        findings.append(
            "INFO: TCP out-of-order packets detected"
        )

    if rst_packets > 0:
        findings.append(
            "INFO: TCP connection reset packets detected"
        )

    if dns_failed > 0:
        findings.append(
            "WARNING: DNS failed responses detected"
        )

    if arp_broadcasts > 0:
        findings.append(
            "INFO: ARP broadcast activity detected"
        )

    # ---------------------------------------------------------
    # OVERALL STATUS
    # ---------------------------------------------------------

    if retransmissions >= 10 or dns_failed >= 10:
        overall_status = "REVIEW REQUIRED"
    elif retransmissions > 0 or dns_failed > 0:
        overall_status = "MONITOR"
    else:
        overall_status = "NORMAL"

    # ---------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------

    print()

    print("TCP Security / Reliability Indicators")
    print("-" * 40)
    print(f"Retransmissions        : {retransmissions}")
    print(f"Duplicate ACKs         : {duplicate_acks}")
    print(f"Out-of-order packets   : {out_of_order}")
    print(f"TCP RST packets        : {rst_packets}")

    print()

    print("DNS Security Indicators")
    print("-" * 40)
    print(f"DNS responses          : {dns_responses}")
    print(f"DNS failed responses   : {dns_failed}")
    print(f"DNS success rate       : {dns_success_rate:.2f}%")

    print()

    print("ARP Indicators")
    print("-" * 40)
    print(f"ARP requests           : {arp_requests}")
    print(f"ARP replies            : {arp_replies}")
    print(f"ARP broadcasts         : {arp_broadcasts}")

    print()

    print("Security Findings")
    print("-" * 40)

    if findings:
        for finding in findings:
            print(f"[{finding.split(':')[0]}] {finding.split(': ', 1)[1]}")
    else:
        print("No significant indicators detected.")

    print()

    print(f"Overall Security Status: {overall_status}")

    print()
    print("Analysis completed successfully.")


if __name__ == "__main__":
    analyze_security()