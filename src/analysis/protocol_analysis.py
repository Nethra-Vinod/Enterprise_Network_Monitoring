from packet_parser import PacketParser


class ProtocolAnalyzer:
    """
    Performs protocol-level analysis on a PCAP/PCAPNG file.
    """

    def __init__(self, capture_file):
        self.parser = PacketParser(capture_file)

    def analyze(self):
        """
        Return protocol statistics and total packet count.
        """

        packet_count = self.parser.get_packet_count()
        protocol_counts = self.parser.get_protocol_counts()

        return {
            "total_packets": packet_count,
            "protocol_counts": protocol_counts
        }

    def print_report(self):
        """
        Print a formatted protocol analysis report.
        """

        results = self.analyze()

        print("=" * 60)
        print("PROTOCOL ANALYSIS REPORT")
        print("=" * 60)

        print(f"\nTotal packets: {results['total_packets']}")

        print("\nProtocol distribution:")
        print("-" * 30)

        for protocol, count in sorted(
            results["protocol_counts"].items(),
            key=lambda item: item[1],
            reverse=True
        ):
            percentage = (
                count / results["total_packets"]
            ) * 100

            print(
                f"{protocol:<15} "
                f"{count:>5} packets "
                f"({percentage:>6.2f}%)"
            )

        print("\nAnalysis completed successfully.")


if __name__ == "__main__":

    CAPTURE_FILE = "captures/raw/tcp_test.pcapng"

    analyzer = ProtocolAnalyzer(CAPTURE_FILE)

    analyzer.print_report()