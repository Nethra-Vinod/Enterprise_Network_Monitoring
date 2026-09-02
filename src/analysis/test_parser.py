from packet_parser import PacketParser


CAPTURE_FILE = "captures/raw/tcp_test.pcapng"


def main():
    parser = PacketParser(CAPTURE_FILE)

    print("=" * 50)
    print("PCAP ANALYSIS TEST")
    print("=" * 50)

    packet_count = parser.get_packet_count()

    print(f"\nTotal packets: {packet_count}")

    print("\nProtocol counts:")

    protocol_counts = parser.get_protocol_counts()

    for protocol, count in sorted(protocol_counts.items()):
        print(f"{protocol:<15} {count}")

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()