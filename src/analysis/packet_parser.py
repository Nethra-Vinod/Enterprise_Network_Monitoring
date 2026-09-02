import pyshark
from pathlib import Path


class PacketParser:
    """
    Basic PCAP/PCAPNG packet reader using PyShark.
    """

    def __init__(self, capture_file):
        self.capture_file = Path(capture_file)

        if not self.capture_file.exists():
            raise FileNotFoundError(
                f"Capture file not found: {self.capture_file}"
            )

    def load_packets(self):
        """
        Load packets from the capture file.
        """
        capture = pyshark.FileCapture(
            str(self.capture_file),
            keep_packets=False
        )

        packets = []

        try:
            for packet in capture:
                packets.append(packet)
        finally:
            capture.close()

        return packets

    def get_packet_count(self):
        """
        Return total number of packets in the capture.
        """
        capture = pyshark.FileCapture(
            str(self.capture_file),
            keep_packets=False
        )

        count = 0

        try:
            for _ in capture:
                count += 1
        finally:
            capture.close()

        return count

    def get_protocol_counts(self):
        """
        Count packets according to their highest-level
        protocol identified by Wireshark.
        """
        capture = pyshark.FileCapture(
            str(self.capture_file),
            keep_packets=False
        )

        protocol_counts = {}

        try:
            for packet in capture:
                protocol = packet.highest_layer

                protocol_counts[protocol] = (
                    protocol_counts.get(protocol, 0) + 1
                )
        finally:
            capture.close()

        return protocol_counts