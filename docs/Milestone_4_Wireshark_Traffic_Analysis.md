# Milestone 4 – Wireshark Traffic Capture and Network Analysis

**Project:** Enterprise Network Monitoring and Security Analysis Dashboard using Cisco Packet Tracer, Wireshark, and Python

**Date:** 27 August 2026

**Status:** Completed

# Objective
The objective of this milestone was to begin the practical network monitoring and traffic analysis phase of the project.
Wireshark and TShark were used to capture and analyze real network traffic generated during different network activities.
The analysis focused on:
* ICMP traffic and Round Trip Time (RTT)
* ARP traffic
* DNS queries and responses
* TCP conversations
* TCP three-way handshake
* TCP retransmissions
* Duplicate ACKs
* Out-of-order TCP segments
* TCP connection termination
* HTTP traffic
* UDP conversations
* QUIC traffic
* Wireshark Expert Information
* Network traffic statistics
* Security validation using ACLs implemented in Cisco Packet Tracer

# Tools Used

| Tool | Purpose |
| ------------------- | --------------------------------------------- |
| Wireshark | Graphical packet capture and analysis |
| TShark | Command-line packet analysis |
| Cisco Packet Tracer | Enterprise network simulation |
| Python | Future automation and dashboard development |
| Windows 11 | Development and analysis environment |

# TShark Verification
TShark was verified successfully from the project virtual environment.

The installed version was:
```text
TShark (Wireshark) 4.6.8

The available capture interfaces were checked using:
tshark -D

The system successfully detected multiple Npcap interfaces including the Wi-Fi interface and loopback interface.
This confirmed that packet capture could be performed from the development system.

Capture Files
The following packet capture files were created for analysis:
captures/
└── raw/
    ├── icmp_test.pcapng
    ├── dns_test.pcapng
    └── tcp_test.pcapng
Each capture was used for a different type of protocol and performance analysis.

ICMP Analysis
The ICMP capture was analyzed using:
tshark -r captures\raw\icmp_test.pcapng -Y "icmp" -T fields -E separator=, -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e icmp.type -e icmp.seq
The capture contained ICMP Echo Requests from:
192.168.1.113 → 8.8.8.8
and corresponding Echo Replies:
8.8.8.8 → 192.168.1.113
The analyzed packets contained sequences 2 through 11.

ICMP RTT Analysis
Round Trip Time was calculated by comparing the timestamp of each Echo Request with the corresponding Echo Reply.
The measured RTT values were approximately:
Sequence	RTT
2	21.08 ms
3	19.49 ms
4	17.52 ms
5	44.55 ms
6	12.69 ms
7	15.57 ms
8	16.71 ms
9	25.45 ms
10	12.64 ms
11	17.03 ms

The resulting performance measurements were:
Minimum RTT: approximately 12.64 ms
Maximum RTT: approximately 44.55 ms
Average RTT: approximately 20.33 ms
ICMP packet loss in the analyzed request/reply sequence: 0%
ICMP Traffic Statistics

The capture duration reported by TShark was approximately:
38.400770 second
The following command was used to obtain traffic statistics:
tshark -r captures\raw\icmp_test.pcapng -q -z io,stat,1
The output showed the number of frames and bytes transmitted during each one-second interval.

This information can later be used by the dashboard to visualize traffic volume over time.

DNS Analysis
DNS traffic was analyzed from the DNS capture using:
tshark -r captures\raw\dns_test.pcapng -Y dns
The capture contained DNS queries and responses involving the DNS server:
192.168.1.1

The client address observed in the capture was:
192.168.1.113
DNS Query Types

The analysis identified multiple DNS query types:
A records
AAAA records
HTTPS records
PTR records

Examples of domains queried included:
google.com
youtube.com
microsoft.com
example.com
chatgpt.com
random-test-12345.example.com
DNS Resolution Analysis

Successful DNS responses were observed for domains such as:
google.com
youtube.com
microsoft.com
example.com
chatgpt.com

The DNS server returned both IPv4 and IPv6 information where available.

For example, google.com generated:
A
AAAA
queries and corresponding responses.
The test domain:
random-test-12345.example.com
did not resolve to an address and resulted in DNS responses containing SOA information.
This demonstrated both successful DNS resolution and unsuccessful/non-existent domain resolution.

DNS Retransmission Analysis
The DNS capture also demonstrated retransmitted DNS queries and responses.
These events were identified using TShark and Wireshark analysis.
This information is useful for identifying potential DNS reliability or network-delay conditions.

TCP Conversation Analysis
TCP conversations were analyzed using:
tshark -r captures\raw\tcp_test.pcapng -q -z conv,tcp
Multiple TCP conversations were identified between the client:
192.168.1.113
and external servers using ports:
80
443

The largest observed TCP conversation contained:
136 frames
approximately 95 kB
duration approximately 20.63 seconds

This demonstrated active TCP-based application traffic in the capture.

TCP Three-Way Handshake
TCP SYN traffic was extracted using:
tshark -r captures\raw\tcp_test.pcapng -Y "tcp.flags.syn == 1" -T fields -E separator=, -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags

The capture contained TCP connection establishment packets including:
SYN
SYN + ACK
for connections to ports 80 and 443.

This confirms the presence of TCP connection establishment activity and provides packet-level evidence of the TCP three-way handshake.

TCP Retransmission Analysis
TCP retransmissions were counted using:
tshark -r captures\raw\tcp_test.pcapng -Y "tcp.analysis.retransmission" | find /c /v ""

The result was:
5
Therefore, five TCP retransmission events were identified in the analyzed capture.

Duplicate ACK Analysis
Duplicate acknowledgements were counted using:
tshark -r captures\raw\tcp_test.pcapng -Y "tcp.analysis.duplicate_ack" | find /c /v ""

The result was:
7

Therefore, seven duplicate ACK events were detected.

Out-of-Order Segment Analysis
The following filter was used to identify retransmissions, duplicate ACKs, and out-of-order segments:
tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.out_of_order
The analysis identified suspected out-of-order TCP segments in the capture.
This information can be used as a network performance indicator because packet reordering may affect TCP efficiency.

TCP D-SACK and Sequence Analysis
Wireshark Expert Information reported:
D-SACK Sequence
and other TCP sequence-related events.
These events were recorded as part of the TCP reliability analysis.

TCP Connection Reset
The Expert Information output identified:
TCP Connection reset (RST)
A TCP RST represents an abrupt termination/reset of a TCP connection.
The event was recorded as a TCP anomaly indicator for later dashboard analysis.

TCP Connection Closing
The Expert Information output also identified TCP connection closing events involving:

FIN
This demonstrated normal TCP connection termination activity in addition to the observed reset event.

TCP Expert Information
The following command was used:
tshark -r captures\raw\tcp_test.pcapng -q -z expert
Wireshark reported several sequence, protocol, and decryption-related events.

Important observations included:
TCP retransmissions
Duplicate ACKs
Suspected out-of-order segments
D-SACK events
TCP connection reset
DNS query retransmissions
DNS response retransmissions
Previous segments not captured
QUIC decryption context unavailable

These events provide useful information for automated network health and anomaly detection.

HTTP Analysis
HTTP statistics were obtained using:
tshark -r captures\raw\tcp_test.pcapng -q -z http,stat
The following HTTP response status was observed:
200 OK
The capture contained:
3 HTTP 200 OK responses
The request method statistics included:
GET     3
NOTIFY  3
This demonstrates HTTP application-level traffic in the capture.

UDP Analysis
UDP conversations were analyzed using:
tshark -r captures\raw\tcp_test.pcapng -q -z conv,udp
DNS traffic was observed using UDP port:
53
Other UDP traffic included:
UDP 443
mDNS 5353
SSDP 1900
The capture therefore contained both application traffic and local network service discovery traffic.

ARP Analysis
ARP traffic was extracted using:
tshark -r captures\raw\tcp_test.pcapng -Y "arp"
Multiple ARP requests were observed.
The requests were generated by:
192.168.1.1
and were broadcast to locate different hosts in the:
192.168.1.0/24
network.

Examples included requests such as:
Who has 192.168.1.107?
Who has 192.168.1.110?
Who has 192.168.1.112?
Who has 192.168.1.116?

The ARP requests demonstrate address-resolution activity occurring within the local network.
ARP Traffic Statistics
ARP traffic was measured using:
tshark -r captures\raw\tcp_test.pcapng -q -z io,stat,1,"COUNT(arp)arp"
The result showed that ARP traffic occurred intermittently throughout the capture.
Several one-second intervals contained multiple ARP requests, demonstrating periodic address-resolution activity.

QUIC Analysis
QUIC traffic was also observed in the capture.

Wireshark Expert Information reported:
Failed to create decryption context: Secrets are not available
This is expected when the required QUIC decryption secrets are unavailable.
The event was therefore recorded as an encrypted-traffic analysis limitation rather than automatically classified as a security attack.

Packet-Level Traffic Classification
The captured traffic can be broadly classified into:
Category	Observed Traffic
Network Discovery	ARP
Name Resolution	DNS
Network Testing	ICMP
Reliable Transport	TCP
Connection Establishment	TCP SYN/SYN-ACK
Application Traffic	HTTP/HTTPS
Datagram Traffic	UDP
Modern Transport	QUIC
Local Service Discovery	mDNS/SSDP
Cisco Packet Tracer Security Validation
Network security policies were implemented and tested in the Cisco Packet Tracer enterprise network.
The enterprise network contained separate VLANs for:
VLAN 10 – HR
VLAN 20 – SALES
VLAN 30 – IT
VLAN 40 – SERVER
VLAN 99 – MANAGEMENT
ACL policies were configured to control inter-VLAN communication.

HR Security Policy
The HR ACL contained:
deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
permit ip 192.168.10.0 0.0.0.255 any
Testing confirmed that:
HR → SALES     Blocked
HR → IT        Allowed

The HR systems successfully communicated with permitted network destinations while restricted traffic was blocked.

Sales Security Policy
The Sales ACL contained:
deny ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255
permit ip 192.168.20.0 0.0.0.255 any
Testing confirmed:
SALES → HR     Blocked
SALES → IT     Allowed
SALES → SERVER Allowed
This verified the intended isolation between the Sales and HR VLANs.

DHCP Validation
DHCP relay functionality was also validated.
The VLAN interfaces on Core-SW1 used the DHCP server:
192.168.40.10
using:
ip helper-address 192.168.40.10

The DHCP configuration was successfully validated for:
HR
SALES
IT
The clients received addresses from their respective VLAN networks.
Examples included:
HR:
192.168.10.x
SALES:
192.168.20.x
IT:
192.168.30.x
DNS and Application Server Validation
The application server was configured in the SERVER VLAN.
The server address was:
192.168.40.20
DNS resolution successfully mapped:
app.company.local
to:
192.168.40.20
The application server was successfully reached using ICMP.

FTP Validation
FTP connectivity to the application/server environment was tested successfully.
The following command was used:
ftp 192.168.40.20
The connection returned:
220- Welcome to PT Ftp server

Authentication was successful and the FTP directory listing was retrieved.
This verified application-layer connectivity to the server VLAN.

Network Security and Performance Findings
The combined Packet Tracer and Wireshark analysis produced the following findings:

Metric	Result
ICMP packet loss	0%
Average ICMP RTT	~20.33 ms
Minimum ICMP RTT	~12.64 ms
Maximum ICMP RTT	~44.55 ms
TCP retransmissions	5
TCP duplicate ACKs	7
TCP out-of-order events	Observed
TCP D-SACK events	Observed
TCP RST	1
DNS retransmissions	Observed
HTTP 200 responses	3
DHCP validation	Successful
DNS server validation	Successful
FTP connectivity	Successful
HR/Sales ACL isolation	Successful
Observations

The following observations were made during the milestone:
Wireshark successfully captured real network traffic.
TShark successfully extracted protocol-specific information from PCAPNG files.
ICMP traffic could be used to calculate RTT and packet loss.
DNS queries and responses could be extracted and classified.
TCP conversations provided information about active connections.
TCP SYN and SYN-ACK packets demonstrated connection establishment.
Retransmissions and duplicate ACKs provided indicators of TCP reliability issues.
ARP traffic demonstrated local address-resolution activity.
HTTP, UDP, and QUIC traffic were identified in the capture.
Wireshark Expert Information provided additional protocol and sequence-level events.
Cisco Packet Tracer ACLs successfully enforced the intended inter-VLAN restrictions.
DHCP relay and server connectivity were successfully validated.

Deliverables
ICMP packet capture
DNS packet capture
TCP packet capture
TShark protocol analysis results
ICMP RTT measurements
TCP reliability statistics
ARP analysis
DNS analysis
HTTP analysis
UDP conversation analysis
Wireshark Expert Information analysis
Cisco Packet Tracer security validation
DHCP validation
DNS and application server validation
FTP connectivity validation

Outcome
Milestone 4 successfully established the packet-analysis foundation of the project.
Real network traffic was captured and analyzed using Wireshark and TShark, while the enterprise network created in Cisco Packet Tracer was validated through connectivity, DHCP, DNS, FTP, VLAN, and ACL tests.
The collected packet captures and extracted network metrics will serve as the input for the automated Python-based analysis and monitoring dashboard in the subsequent milestones.

Milestone Status:  Completed