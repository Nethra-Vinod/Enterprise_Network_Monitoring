# Project Journal

## Project

**Enterprise Network Monitoring and Security Analysis Dashboard using Cisco Packet Tracer, Wireshark, and Python**

---

## 21 July 2026

### Milestone 1 – Environment Setup

**Status:** Completed

### Objectives Achieved

* Created the project workspace.
* Organized the project directory structure.
* Created and configured a Python virtual environment.
* Installed all required Python libraries.
* Verified Python 3.10.11 installation.
* Verified Wireshark and TShark 4.6.7.
* Generated the `requirements.txt` file.
* Created the initial Python application.
* Initialized the Git repository.
* Renamed the Git branch from `master` to `main`.
* Created the initial project documentation.

### Observations

The development environment was successfully configured without dependency conflicts. All required software and libraries are functioning correctly.

---

## 22 July 2026

### Milestone 2 – Network Planning and Architecture

**Status:** Completed

### Objectives Achieved

* Selected the enterprise project scenario.
* Finalized the company profile.
* Identified departments and required network devices.
* Designed the logical network architecture.
* Planned VLAN assignments.
* Created the IP addressing scheme.
* Planned the server infrastructure.
* Defined the security strategy.
* Planned network traffic generation scenarios.
* Designed the dashboard architecture.
* Documented expected project outcomes.

### Key Design Decisions

* Selected **TechNova Solutions Pvt. Ltd.** as the enterprise scenario.
* Adopted a five-VLAN architecture for logical segmentation.
* Chose separate Infrastructure and Application servers.
* Decided to implement a hybrid monitoring approach using Cisco Packet Tracer, Wireshark, and Python.
* Planned a modular Streamlit dashboard with separate sections for overview, protocol analysis, performance, security, and topology.

### Current Progress

* Milestone 1 – Completed
* Milestone 2 – Completed
* Milestone 3 – Ready to Begin

---

## 25 August 2026

### Milestone 3 – Enterprise Network Implementation and Verification

**Status:** Completed

### Objectives Achieved

* Created and configured the enterprise network topology in Cisco Packet Tracer.
* Created and configured VLANs for HR, Sales, IT, Server, and Management networks.
* Configured access ports and trunk links between the core and departmental switches.
* Configured inter-VLAN routing using Core-SW1.
* Configured centralized DHCP services and DHCP relay.
* Assigned dynamic IP addresses to all departmental PCs.
* Configured the Infrastructure and Application server network.
* Configured DNS services and verified hostname resolution.
* Configured and tested HTTP/Web services.
* Configured and tested FTP services.
* Configured and tested email services.
* Implemented ACL-based security policies for departmental isolation.
* Configured router connectivity between the enterprise network and simulated ISP.
* Configured static routing between Core-SW1 and R1.
* Configured NAT/PAT for WAN connectivity.
* Verified end-to-end connectivity across the enterprise network.
* Verified application-level services from client devices.
* Verified connectivity between the enterprise network and simulated external network.

### Security Implementation

* Implemented `HR_POLICY` to restrict HR-to-Sales communication.
* Implemented `SALES_POLICY` to restrict Sales-to-HR communication.
* Allowed authorized communication between departments and server resources.
* Added explicit DHCP permissions to the ACLs to prevent DHCP requests from being blocked.

### Verification Results

* All 4 HR PCs successfully received addresses from the HR DHCP pool.
* All 6 Sales PCs successfully received addresses from the Sales DHCP pool.
* All 5 IT PCs successfully received addresses from the IT DHCP pool.
* HR-to-IT communication was successfully verified.
* Sales-to-IT communication was successfully verified.
* HR-to-Sales communication was successfully blocked.
* Sales-to-HR communication was successfully blocked.
* DNS resolution of `app.company.local` was successfully verified.
* HTTP/Web access to the Application Server was successfully verified.
* FTP login and directory access were successfully verified.
* Email transmission and reception were successfully verified.
* WAN connectivity through R1 and the simulated ISP was successfully verified.
* NAT/PAT and routing functionality were successfully validated.

### Issues Identified and Resolved

* DHCP initially failed for HR and Sales clients because the inbound ACLs did not explicitly permit DHCP traffic.
* DHCP permit rules were added to the respective ACLs, after which dynamic IP assignment functioned correctly.
* WAN connectivity initially failed because R1 did not have routes to the internal VLAN networks.
* Static routes were added on R1 through Core-SW1, restoring end-to-end WAN connectivity.

### Observations

The enterprise network was successfully implemented and validated. VLAN segmentation, inter-VLAN routing, centralized services, security policies, application services, NAT/PAT, and WAN connectivity are functioning as designed.

### Current Progress

* Milestone 1 – Completed
* Milestone 2 – Completed
* Milestone 3 – Completed
* Cisco Packet Tracer enterprise network – Completed
* Network service verification – Completed
* Security and connectivity verification – Completed
* Wireshark traffic capture and analysis – Next Phase
* Python monitoring dashboard integration – Next Phase
----

## 27 August 2026

### Milestone 4 – Wireshark Traffic Capture and Network Analysis

**Status:** Completed

### Objectives Achieved
* Verified TShark installation and packet-capture interfaces.
* Generated and collected ICMP, DNS, and TCP packet captures.
* Analyzed ICMP Echo Request and Echo Reply traffic.
* Calculated ICMP Round Trip Time (RTT).
* Measured minimum, maximum, and average RTT.
* Verified ICMP packet loss for the analyzed packets.
* Analyzed ARP address-resolution traffic.
* Analyzed DNS queries and responses.
* Identified A, AAAA, HTTPS, and PTR DNS queries.
* Investigated successful and unsuccessful DNS resolution.
* Analyzed TCP conversations.
* Identified TCP SYN and SYN-ACK packets.
* Studied TCP connection establishment and termination.
* Measured TCP retransmissions.
* Measured duplicate ACKs.
* Identified out-of-order TCP segments.
* Identified D-SACK and TCP reset events.
* Analyzed HTTP statistics.
* Analyzed UDP conversations.
* Identified QUIC traffic and encryption limitations.
* Used Wireshark Expert Information for protocol and anomaly analysis.
* Validated VLAN connectivity and inter-VLAN routing.
* Validated DHCP operation using DHCP relay.
* Validated DNS resolution for the enterprise application server.
* Validated FTP connectivity.
* Verified ACL-based security restrictions between HR and Sales VLANs.

### Key Results
* Average ICMP RTT: approximately 20.33 ms.
* Minimum ICMP RTT: approximately 12.64 ms.
* Maximum ICMP RTT: approximately 44.55 ms.
* ICMP packet loss in the analyzed request/reply sequence: 0%.
* TCP retransmissions detected: 5.
* TCP duplicate ACKs detected: 7.
* TCP out-of-order events were observed.
* TCP D-SACK events were observed.
* One TCP connection reset was identified.
* DNS retransmission events were identified.
* HTTP 200 OK responses were observed.
* ARP, DNS, TCP, UDP, HTTP, HTTPS, and QUIC traffic were identified.

### Security Validation
The enterprise ACL policies were successfully tested.
* HR-to-Sales communication was blocked.
* Sales-to-HR communication was blocked.
* Permitted HR, Sales, and IT communication was successful.
* DHCP relay successfully provided addresses to the departmental VLANs.
* DNS successfully resolved the enterprise application server.
* FTP connectivity to the application server was successfully established.

### Captures Generated
The following packet captures were collected:
* `icmp_test.pcapng`
* `dns_test.pcapng`
* `tcp_test.pcapng`

### Observations
The milestone established that Wireshark and TShark can provide packet-level information required for the proposed monitoring dashboard.
The Cisco Packet Tracer network was also successfully validated from a networking and security perspective. The captured traffic and extracted metrics will be used as the foundation for automated Python-based analysis and visualization.

### Current Progress
* Milestone 1 – Completed
* Milestone 2 – Completed
* Milestone 3 – Completed
* Milestone 4 – Completed
* Milestone 5 – Ready to Begin
---