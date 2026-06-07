# Basic Network Packet Sniffer
# CodeAlpha Cyber Security Internship - Task 1
# Author: Sneha Singh

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"[{timestamp}] {ip_src} -> {ip_dst} Protocol: {protocol}")
        
        if TCP in packet:
            print(f"  TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"  ICMP Type: {packet.type}")

print("Starting Network Packet Sniffer...")
print("Press Ctrl+C to stop")
sniff(prn=packet_callback, store=0)
