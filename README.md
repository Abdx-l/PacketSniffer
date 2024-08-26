# Packet Sniffer

# Overview
This project is a Python-based packet sniffer that intercepts and processes network traffic at a low level. By utilizing raw sockets, the sniffer captures various types of packets and extracts meaningful information from them. This packet sniffer is designed to give insights into the underlying mechanisms of network communication by dissecting Ethernet frames, IPv4 packets, ICMP messages, TCP segments, and UDP datagrams.

# How It Works
Packet Capture:

The sniffer initializes a raw socket using the socket.AF_PACKET family, which allows it to operate at the data link layer. This socket type enables the capture of all network traffic passing through the network interface, making it ideal for a packet sniffer.


Ethernet Frame Parsing:

Upon receiving raw packet data, the sniffer first parses the Ethernet frame. The Ethernet frame consists of the destination MAC address, source MAC address, and the EtherType, which indicates the protocol of the encapsulated payload.


IPv4 Packet Parsing:

If the EtherType indicates that the payload is an IPv4 packet, the sniffer proceeds to parse the IPv4 header. This includes extracting the IP version, header length, Time-To-Live (TTL), protocol identifier, and source/destination IP addresses.


ICMP Message Parsing:

For IPv4 packets where the protocol field indicates ICMP (Internet Control Message Protocol), the sniffer extracts the ICMP type, code, and checksum from the packet.


TCP Segment Parsing:

When the protocol is identified as TCP (Transmission Control Protocol), the sniffer parses the TCP segment. This includes extracting the source and destination ports, sequence number, acknowledgment number, and various TCP flags such as SYN, ACK, PSH, etc.


UDP Datagram Parsing:

If the protocol is identified as UDP (User Datagram Protocol), the sniffer extracts the source and destination ports and the length of the UDP datagram.


# Purpose
The primary objective of this packet sniffer is to provide a transparent view of network traffic, exposing the details of protocol interactions and the structure of network packets. It serves as an educational tool for understanding how data is transmitted over networks and how various protocols function at a fundamental level.

# Disclaimer
This tool is only a project. Unauthorized packet sniffing can be illegal and unethical. Make sure you have proper authorization to monitor the network traffic. 
