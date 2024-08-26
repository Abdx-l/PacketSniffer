import socket
import struct

def start_sniffer():
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_packet, _ = sniffer_socket.recvfrom(65536)  # Intercepts and stores data
        dest_mac, src_mac, eth_type, payload = parse_ethernet_frame(raw_packet)
        print("\nEthernet Frame:")
        print(f"To: {dest_mac}, From: {src_mac}, Type: {eth_type}")

        # Handle IPv4 packets
        if eth_type == 8:
            ip_version, header_len, time_to_live, protocol, source_ip, dest_ip, payload = parse_ipv4_packet(payload)
            print("\t- " + "IPv4 Packet:")
            print(f"\t\t- Version: {ip_version}, Header Length: {header_len}, TTL: {time_to_live}")
            print(f"\t\t- Protocol: {protocol}, Source: {source_ip}, Destination: {dest_ip}")

            # Handle ICMP packets
            if protocol == 1:
                icmp_type, icmp_code, icmp_checksum, payload = parse_icmp_packet(payload)
                print("\t- " + "ICMP Packet:")
                print(f"\t\t- Type: {icmp_type}, Code: {icmp_code}, Checksum: {icmp_checksum}")

            # Handle TCP segments
            elif protocol == 6:
                src_port, dest_port, seq_num, ack_num, psh_flag, urg_flag, fin_flag, ack_flag, syn_flag, rst_flag, payload = parse_tcp_segment(payload)
                print("\t- " + "TCP Segment:")
                print(f"\t\t- Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"\t\t- Sequence: {seq_num}, Acknowledgment: {ack_num}")
                print(f"\t\t- Flags:")
                print(f"\t\t\t- URG: {urg_flag}, ACK: {ack_flag}, PSH: {psh_flag}")
                print(f"\t\t\t- RST: {rst_flag}, SYN: {syn_flag}, FIN: {fin_flag}")

            # Handle UDP segments if necessary
            elif protocol == 17:
                src_port, dest_port, length, payload = parse_udp_segment(payload)
                print("\t- " + "UDP Segment:")
                print(f"\t\t- Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")

# Unpacks Ethernet frame
def parse_ethernet_frame(packet_data):
    dest_mac, src_mac, eth_type = struct.unpack('! 6s 6s H', packet_data[:14])  # Unpacks the first 14 bytes
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(eth_type), packet_data[14:]  # Returns the payload

# Returns properly formatted MAC address
def format_mac_address(mac_bytes):
    mac_str = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac_str).upper()

# Unpacks IPv4 packet
def parse_ipv4_packet(packet_data):
    version_header_length = packet_data[0]
    ip_version = version_header_length >> 4  # Bit shifts 4 to the right
    header_len = (version_header_length & 15) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', packet_data[:20])
    return ip_version, header_len, ttl, proto, format_ipv4_address(src_ip), format_ipv4_address(dest_ip), packet_data[header_len:]

# Returns properly formatted IPv4 address
def format_ipv4_address(ip_bytes):
    return '.'.join(map(str, ip_bytes))

# Unpacks ICMP packet
def parse_icmp_packet(packet_data):
    icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', packet_data[:4])
    return icmp_type, icmp_code, icmp_checksum, packet_data[4:]

# Unpacks TCP segment
def parse_tcp_segment(packet_data):
    src_port, dest_port, seq_num, ack_num, offset_reserved_flags = struct.unpack('! H H L L H', packet_data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # Isolates Offset from the chunk
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seq_num, ack_num, flag_psh, flag_urg, flag_fin, flag_ack, flag_syn, flag_rst, packet_data[offset:]

# Unpacks UDP segment
def parse_udp_segment(packet_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', packet_data[:8])
    return src_port, dest_port, size, packet_data[8:]

if __name__ == "__main__":
    start_sniffer()
