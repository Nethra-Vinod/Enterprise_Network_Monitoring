import pyshark
from collections import Counter


PCAP_FILE = r"captures\raw\tcp_test.pcapng"


def analyze_arp():

    print("=" * 60)
    print("ARP NETWORK ANALYSIS")
    print("=" * 60)

    capture = pyshark.FileCapture(
        PCAP_FILE,
        display_filter="arp"
    )

    total_packets = 0
    requests = 0
    replies = 0
    broadcasts = 0

    source_ips = []
    target_ips = []

    request_times = []

    for packet in capture:

        try:
            arp = packet.arp

            total_packets += 1

            # ARP opcode
            opcode = int(arp.opcode)

            if opcode == 1:
                requests += 1
            elif opcode == 2:
                replies += 1

            # Source and destination protocol addresses
            if hasattr(arp, "src_proto_ipv4"):
                source_ips.append(arp.src_proto_ipv4)

            if hasattr(arp, "dst_proto_ipv4"):
                target_ips.append(arp.dst_proto_ipv4)

            # Ethernet destination
            try:
                destination = packet.eth.dst

                if destination.lower() == "ff:ff:ff:ff:ff:ff":
                    broadcasts += 1

            except AttributeError:
                pass

            # Relative packet time
            try:
                request_times.append(float(packet.sniff_time.timestamp()))
            except Exception:
                pass

        except Exception:
            continue

    capture.close()

    # Calculate duration and request rate
    if len(request_times) > 1:
        duration = max(request_times) - min(request_times)

        if duration > 0:
            arp_rate = total_packets / duration
        else:
            arp_rate = 0
    else:
        duration = 0
        arp_rate = 0

    print()
    print(f"Total ARP packets       : {total_packets}")
    print(f"ARP Requests            : {requests}")
    print(f"ARP Replies             : {replies}")
    print(f"ARP Broadcasts          : {broadcasts}")
    print()
    print(f"Unique Source IPs       : {len(set(source_ips))}")
    print(f"Unique Target IPs       : {len(set(target_ips))}")
    print()
    print(f"Capture Duration        : {duration:.2f} seconds")
    print(f"ARP Packet Rate         : {arp_rate:.2f} packets/sec")

    print()

    print("Most Requested IPs:")
    target_counter = Counter(target_ips)

    for ip, count in target_counter.most_common(10):
        print(f"  {ip}: {count} request(s)")

    print()
    print("Analysis completed successfully.")


if __name__ == "__main__":
    analyze_arp()