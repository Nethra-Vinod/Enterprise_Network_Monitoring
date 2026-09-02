import pyshark
from collections import defaultdict


PCAP_FILE = r"captures\raw\tcp_test.pcapng"


def analyze_throughput():

    print("=" * 60)
    print("NETWORK THROUGHPUT ANALYSIS")
    print("=" * 60)

    capture = pyshark.FileCapture(PCAP_FILE)

    total_packets = 0
    total_bytes = 0

    packet_times = []
    traffic_per_second = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for packet in capture:

        try:
            # Packet length from frame layer
            packet_length = int(packet.length)

            total_packets += 1
            total_bytes += packet_length

            # Relative timestamp
            timestamp = float(packet.sniff_timestamp)
            packet_times.append(timestamp)

            # Create a relative second bucket
            if packet_times:
                relative_time = timestamp - packet_times[0]
                second = int(relative_time)

                traffic_per_second[second]["packets"] += 1
                traffic_per_second[second]["bytes"] += packet_length

        except Exception:
            continue

    capture.close()

    # Capture duration
    if len(packet_times) > 1:
        duration = max(packet_times) - min(packet_times)
    else:
        duration = 0

    # Throughput calculation
    #
    # Throughput (bps) = Total Bytes × 8 / Duration
    #
    if duration > 0:
        throughput_bps = (total_bytes * 8) / duration
        packet_rate = total_packets / duration
    else:
        throughput_bps = 0
        packet_rate = 0

    throughput_kbps = throughput_bps / 1000
    throughput_mbps = throughput_bps / 1_000_000

    print()
    print(f"Total packets           : {total_packets}")
    print(f"Total bytes             : {total_bytes}")
    print(f"Capture duration        : {duration:.2f} seconds")
    print()
    print(f"Packet rate             : {packet_rate:.2f} packets/sec")
    print(f"Average throughput      : {throughput_bps:.2f} bps")
    print(f"Average throughput      : {throughput_kbps:.2f} Kbps")
    print(f"Average throughput      : {throughput_mbps:.4f} Mbps")

    print()
    print("Per-second traffic:")
    print("-" * 45)

    print(f"{'Second':<10}{'Packets':<12}{'Bytes':<15}")

    for second in sorted(traffic_per_second):

        packets = traffic_per_second[second]["packets"]
        bytes_count = traffic_per_second[second]["bytes"]

        print(
            f"{second:<10}"
            f"{packets:<12}"
            f"{bytes_count:<15}"
        )

    print()
    print("Analysis completed successfully.")


if __name__ == "__main__":
    analyze_throughput()