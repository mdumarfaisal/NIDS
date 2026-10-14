from scapy.all import IP, TCP
import backend

print("Generating simulated port-scan traffic...")

# Simulate suspicious connection attempts to common service ports
for i, port in enumerate([22, 23, 3389, 22, 23, 80, 443]):
    packet = IP(src='192.168.1.25', dst='192.168.1.100') / TCP(
        sport=40000 + i,
        dport=port,
        flags='S'
    )
    backend.packet_callback(packet)

print("Traffic sent. Refresh the dashboard to see suspicious packets.")
