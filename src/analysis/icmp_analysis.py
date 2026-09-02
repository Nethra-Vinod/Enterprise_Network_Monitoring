import pyshark
from pathlib import Path


class ICMPAnalyzer:
    """
    Performs ICMP and RTT analysis on a PCAP/PCAPNG file.
    """

    def __init__(self, capture_file):
        self.capture_file = Path(capture_file)

        if not self.capture_file.exists():
            raise FileNotFoundError(
                f"Capture file not found: {self.capture_file}"
            )

    def analyze(self):

        capture = pyshark.FileCapture(
            str(self.capture_file),
            display_filter="icmp",
            keep_packets=False
        )

        requests = {}
        rtts = []

        try:

            for packet in capture:

                try:
                    icmp = packet.icmp

                    icmp_type = int(icmp.type)
                    sequence = int(icmp.seq)

                    timestamp = float(packet.sniff_timestamp)

                    # ICMP Echo Request
                    if icmp_type == 8:
                        requests[sequence] = timestamp

                    # ICMP Echo Reply
                    elif icmp_type == 0:

                        if sequence in requests:

                            rtt = (
                                timestamp -
                                requests[sequence]
                            ) * 1000

                            rtts.append(rtt)

                except (AttributeError, ValueError, TypeError):
                    continue

        finally:
            capture.close()

        total_requests = len(requests)
        total_replies = len(rtts)

        if rtts:

            minimum_rtt = min(rtts)
            maximum_rtt = max(rtts)
            average_rtt = sum(rtts) / len(rtts)

        else:

            minimum_rtt = 0
            maximum_rtt = 0
            average_rtt = 0

        if total_requests:

            packet_loss = (
                (total_requests - total_replies)
                / total_requests
            ) * 100

        else:

            packet_loss = 0

        return {
            "requests": total_requests,
            "replies": total_replies,
            "packet_loss": packet_loss,
            "min_rtt": minimum_rtt,
            "max_rtt": maximum_rtt,
            "avg_rtt": average_rtt,
            "rtts": rtts
        }

    def print_report(self):

        results = self.analyze()

        print("=" * 60)
        print("ICMP / RTT PERFORMANCE ANALYSIS")
        print("=" * 60)

        print(f"\nICMP Echo Requests : {results['requests']}")
        print(f"ICMP Echo Replies  : {results['replies']}")

        print(
            f"Packet Loss        : "
            f"{results['packet_loss']:.2f}%"
        )

        print(
            f"\nMinimum RTT        : "
            f"{results['min_rtt']:.2f} ms"
        )

        print(
            f"Maximum RTT        : "
            f"{results['max_rtt']:.2f} ms"
        )

        print(
            f"Average RTT        : "
            f"{results['avg_rtt']:.2f} ms"
        )

        print("\nRTT values:")

        for index, rtt in enumerate(results["rtts"], start=1):
            print(
                f"  Packet {index}: "
                f"{rtt:.2f} ms"
            )

        print("\nAnalysis completed successfully.")


if __name__ == "__main__":

    CAPTURE_FILE = "captures/raw/icmp_test.pcapng"

    analyzer = ICMPAnalyzer(CAPTURE_FILE)

    analyzer.print_report()