#!/usr/bin/env python3

import subprocess
import os
import statistics


PCAP_FILE = os.path.join(
    "captures",
    "raw",
    "dns_test.pcapng"
)


def run_tshark():

    command = [
        "tshark",
        "-r",
        PCAP_FILE,
        "-Y",
        "dns",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "dns.id",
        "-e",
        "dns.flags.response",
        "-e",
        "dns.flags.rcode",
        "-e",
        "dns.qry.name",
        "-e",
        "dns.qry.type"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:

        print("ERROR: TShark failed.")
        print(result.stderr)

        return []

    return result.stdout.strip().splitlines()


def analyze_dns():

    print("=" * 60)
    print("DNS PERFORMANCE ANALYSIS")
    print("=" * 60)

    if not os.path.exists(PCAP_FILE):

        print()
        print("ERROR: PCAP file not found:")
        print(PCAP_FILE)

        return

    lines = run_tshark()

    if not lines:

        print()
        print("No DNS packets found.")

        return

    # ============================================================
    # COUNTERS
    # ============================================================

    total_dns_packets = 0

    queries = 0
    responses = 0

    a_queries = 0
    aaaa_queries = 0
    other_queries = 0

    successful_responses = 0
    failed_responses = 0

    query_times = {}
    rtt_values = []

    # ============================================================
    # PROCESS PACKETS
    # ============================================================

    for line in lines:

        fields = line.split("|")

        if len(fields) < 9:
            continue

        (
            frame_number,
            timestamp,
            src,
            dst,
            transaction_id,
            response_flag,
            response_code,
            query_name,
            query_type
        ) = fields[:9]

        total_dns_packets += 1

        # ========================================================
        # DNS QUERY
        # ========================================================

        if response_flag.lower() == "false":

            queries += 1

            # Save timestamp for RTT calculation
            if transaction_id:

                query_times[transaction_id] = float(timestamp)

            # ----------------------------------------------------
            # DNS QUERY TYPE
            # ----------------------------------------------------

            if query_type == "1":

                # A record
                a_queries += 1

            elif query_type == "28":

                # AAAA record
                aaaa_queries += 1

            else:

                # PTR / HTTPS / other
                other_queries += 1

        # ========================================================
        # DNS RESPONSE
        # ========================================================

        elif response_flag.lower() == "true":

            responses += 1

            # ----------------------------------------------------
            # RESPONSE CODE
            #
            # 0 = NOERROR
            # 3 = NXDOMAIN
            # ----------------------------------------------------

            if response_code == "0":

                successful_responses += 1

            else:

                failed_responses += 1

            # ----------------------------------------------------
            # DNS RTT
            # ----------------------------------------------------

            if transaction_id in query_times:

                query_time = query_times[transaction_id]

                response_time = float(timestamp)

                rtt = (
                    response_time - query_time
                ) * 1000

                if rtt >= 0:

                    rtt_values.append(rtt)

                # Remove matched transaction
                del query_times[transaction_id]

    # ============================================================
    # CALCULATE SUCCESS RATE
    # ============================================================

    if responses > 0:

        success_rate = (
            successful_responses /
            responses
        ) * 100

    else:

        success_rate = 0.0

    # ============================================================
    # CALCULATE RTT
    # ============================================================

    if rtt_values:

        minimum_rtt = min(rtt_values)

        maximum_rtt = max(rtt_values)

        average_rtt = statistics.mean(
            rtt_values
        )

    else:

        minimum_rtt = 0.0
        maximum_rtt = 0.0
        average_rtt = 0.0

    # ============================================================
    # DISPLAY RESULTS
    # ============================================================

    print()

    print(f"Total DNS packets      : {total_dns_packets}")

    print(f"DNS Queries            : {queries}")

    print(f"DNS Responses          : {responses}")

    print()

    print(f"A Queries              : {a_queries}")

    print(f"AAAA Queries           : {aaaa_queries}")

    print(f"Other Queries          : {other_queries}")

    print()

    print(
        f"Successful Responses   : "
        f"{successful_responses}"
    )

    print(
        f"Failed Responses       : "
        f"{failed_responses}"
    )

    print(
        f"DNS Success Rate       : "
        f"{success_rate:.2f}%"
    )

    print()

    print(
        f"Minimum DNS RTT        : "
        f"{minimum_rtt:.2f} ms"
    )

    print(
        f"Maximum DNS RTT        : "
        f"{maximum_rtt:.2f} ms"
    )

    print(
        f"Average DNS RTT        : "
        f"{average_rtt:.2f} ms"
    )

    # ============================================================
    # RTT VALUES
    # ============================================================

    if rtt_values:

        print()

        print("DNS RTT values:")

        for i, rtt in enumerate(
            rtt_values,
            start=1
        ):

            print(
                f"  Transaction {i}: "
                f"{rtt:.2f} ms"
            )

    print()

    print("Analysis completed successfully.")


if __name__ == "__main__":

    analyze_dns()