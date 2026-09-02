# Milestone 2 – Network Planning and Architecture

**Project:** Enterprise Network Monitoring and Security Analysis Dashboard using Cisco Packet Tracer, Wireshark, and Python

**Date:** 22 July 2026

**Status:**  Completed


# Objective

The objective of this milestone was to design a realistic enterprise network before implementation in Cisco Packet Tracer. Proper planning reduces configuration errors and provides a structured foundation for the remaining phases of the project.


# Company Profile

## Company Name

**TechNova Solutions Pvt. Ltd.**

## Industry

Information Technology Services and Software Development

## Office Description

TechNova Solutions operates from a single headquarters with multiple departments connected through an enterprise local area network (LAN). Employees access centralized services such as DHCP, DNS, web hosting, file transfer, and email. The IT department manages the network infrastructure, while a custom Network Operations Center (NOC) dashboard monitors network performance and security.

---

# Department Layout

| Department      | Function               |
| --------------- | ---------------------- |
| Human Resources | Employee Management    |
| Sales           | Customer Relations     |
| IT Support      | Network Administration |
| Server Room     | Network Services       |
| Management      | Device Administration  |


# Network Devices

## Core Infrastructure

* 1 Edge Router
* 1 Layer-3 Switch

## Access Layer

* 3 Cisco 2960 Access Switches

## End Devices

### HR

* 4 PCs
* 1 Network Printer

### Sales

* 6 PCs
* 1 Network Printer

### IT

* 5 PCs


# Server Design

The network will use two dedicated servers.

### Infrastructure Server

* DHCP
* DNS

### Application Server

* HTTP
* FTP
* Email

Separating infrastructure and application services reflects common enterprise network design practices.


# VLAN Design

| VLAN | Name       | Purpose                   |
| ---- | ---------- | ------------------------- |
| 10   | HR         | Human Resources           |
| 20   | SALES      | Sales Department          |
| 30   | IT         | IT Department             |
| 40   | SERVER     | Server Network            |
| 99   | MANAGEMENT | Network Device Management |


# IP Addressing Scheme

| VLAN       | Network         | Default Gateway |
| ---------- | --------------- | --------------- |
| HR         | 192.168.10.0/24 | 192.168.10.1    |
| SALES      | 192.168.20.0/24 | 192.168.20.1    |
| IT         | 192.168.30.0/24 | 192.168.30.1    |
| SERVER     | 192.168.40.0/24 | 192.168.40.1    |
| MANAGEMENT | 192.168.99.0/24 | 192.168.99.1    |


# Network Topology

The proposed topology consists of:

* Internet connectivity through an Edge Router.
* Layer-3 Switch providing Inter-VLAN Routing.
* Three Access Switches serving department VLANs.
* Dedicated Server VLAN.
* Centralized management network.

This design provides scalability, logical segmentation, and simplified administration.


# Network Services

The enterprise network will provide:

* DHCP
* DNS
* HTTP
* FTP
* Email
* SSH
* Inter-VLAN Routing
* Access Control Lists (ACLs)


# Security Strategy

The planned security measures include:

* VLAN segmentation
* SSH for secure device administration
* ACLs for traffic filtering
* Dedicated Management VLAN
* Separation of user devices and servers

For protocol analysis, HTTP and HTTPS traffic will be compared using Wireshark captures collected on the host computer.


# Traffic Generation Plan

The following activities will be performed during testing:

* ICMP Ping
* DNS Queries
* HTTP Browsing
* HTTPS Browsing
* FTP Upload
* FTP Download
* Email Communication
* SSH Login

These activities provide representative enterprise traffic for protocol and performance analysis.


# Wireshark Capture Plan

Separate packet captures will be collected for:

* General Browsing
* DNS Activity
* FTP Transfers
* Email Communication
* SSH Sessions
* ICMP Testing

Each capture will later be processed by the Python analysis modules.


# Dashboard Modules

The dashboard will include:

### Network Overview

* Network Health Score
* Active Hosts
* Active Conversations
* Total Packets
* Total Bytes

### Protocol Analysis

* Protocol Distribution
* TCP vs UDP
* HTTP
* DNS
* FTP
* ARP
* ICMP

### Performance Analysis

* Throughput
* RTT
* Packet Rate
* Average Packet Size
* TCP Retransmissions
* Duplicate ACKs

### Security Analysis

* HTTP vs HTTPS
* SSH Sessions
* TCP Reset Packets
* SYN Packets
* Broadcast Traffic
* Security Risk Indicator

### Network Topology

* Logical Network Diagram
* VLAN Information
* Device Information
* IP Addressing
* Packet Statistics


# Expected Outcomes

The completed project will demonstrate:

* Enterprise network design
* VLAN implementation
* Inter-VLAN routing
* Server configuration
* Network monitoring
* Protocol analysis
* Performance evaluation
* Security visualization through an interactive dashboard


# Outcome

The complete network architecture has been finalized and documented. The project is now ready for implementation in Cisco Packet Tracer.


**Milestone Status:** ✅ Completed
