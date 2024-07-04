import argparse
import socket
from scapy.all import *

# Define arguments
parser = argparse.ArgumentParser(description='Advanced Port Scanner')
parser.add_argument('--host', required=True, help='Target IP address')
parser.add_argument('--ports', required=True, help='Ports to scan (comma-separated)')
args = parser.parse_args()

# Parse the target IP address
target_ip = socket.gethostbyname(args.host)

# Parse the ports to scan
ports = [int(port) for port in args.ports.split(',')]

# Define a function to scan a single port
def scan_port(port):
    syn_packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
    syn_ack_packet = sr1(syn_packet, timeout=1, verbose=0)
    if syn_ack_packet and syn_ack_packet.haslayer(TCP) and syn_ack_packet[TCP].flags == 'SA':
        return True
    else:
        return False

# Scan the specified ports
for port in ports:
    result = scan_port(port)
    if result:
        print(f'Port {port} is open')
    else:
        print(f'Port {port} is closed')