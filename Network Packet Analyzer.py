import socket
import struct
import textwrap
import os

# Function to format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Function to unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = '.'.join(map(str, src))
    target = '.'.join(map(str, target))
    return version, header_length, ttl, proto, src, target, data[header_length:]

# Main function to capture packets
def main():
    # Create a raw socket and bind it to the public interface
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)

        print('\nIPv4 Packet:')
        print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
        print(f'Protocol: {proto}, Source: {src}, Target: {target}')
        print(f'Data:')
        print(format_multi_line('\t', data))

if __name__ == '__main__':
    main()
