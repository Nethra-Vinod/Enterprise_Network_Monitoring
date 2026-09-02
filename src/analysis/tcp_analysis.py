import pyshark
from pathlib import Path


class TCPAnalyzer:
    """
    Performs TCP performance analysis on a PCAP/PCAPNG file.
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
            display_filter="tcp",
            keep_packets=False
        )

        total_tcp = 0
        syn = 0
        syn_ack = 0
        fin = 0
        rst = 0
        retransmissions = 0
        duplicate_acks = 0
        out_of_order = 0

        try:

            for packet in capture:

                total_tcp += 1

                try:
                    tcp = packet.tcp

                    flags = int(tcp.flags, 16)

                    # SYN
                    if flags & 0x02:
                        syn += 1

                    # SYN + ACK
                    if (flags & 0x02) and (flags & 0x10):
                        syn_ack += 1

                    # FIN
                    if flags & 0x01:
                        fin += 1

                    # RST
                    if flags & 0x04:
                        rst += 1

                    # Retransmission
                    if hasattr(tcp, "analysis_retransmission"):
                        retransmissions += 1

                    # Duplicate ACK
                    if hasattr(tcp, "analysis_duplicate_ack"):
                        duplicate_acks += 1

                    # Out of order
                    if hasattr(tcp, "analysis_out_of_order"):
                        out_of_order += 1

                except (AttributeError, ValueError, TypeError):
                    continue

        finally:
            capture.close()

        if total_tcp:
            retransmission_rate = (
                retransmissions / total_tcp
            ) * 100
        else:
            retransmission_rate = 0

        return {
            "total_tcp": total_tcp,
            "syn": syn,
            "syn_ack": syn_ack,
            "fin": fin,
            "rst": rst,
            "retransmissions": retransmissions,
            "duplicate_acks": duplicate_acks,
            "out_of_order": out_of_order,
            "retransmission_rate": retransmission_rate
        }

    def print_report(self):

        results = self.analyze()

        print("=" * 60)
        print("TCP PERFORMANCE ANALYSIS")
        print("=" * 60)

        print(f"\nTotal TCP packets    : {results['total_tcp']}")

        print("\nConnection activity:")
        print(f"SYN packets          : {results['syn']}")
        print(f"SYN-ACK packets      : {results['syn_ack']}")
        print(f"FIN packets          : {results['fin']}")
        print(f"RST packets          : {results['rst']}")

        print("\nTCP reliability:")
        print(
            f"Retransmissions     : "
            f"{results['retransmissions']}"
        )
        print(
            f"Duplicate ACKs      : "
            f"{results['duplicate_acks']}"
        )
        print(
            f"Out-of-order packets: "
            f"{results['out_of_order']}"
        )
        print(
            f"Retransmission rate : "
            f"{results['retransmission_rate']:.2f}%"
        )

        print("\nAnalysis completed successfully.")


if __name__ == "__main__":

    CAPTURE_FILE = "captures/raw/tcp_test.pcapng"

    analyzer = TCPAnalyzer(CAPTURE_FILE)

    analyzer.print_report()