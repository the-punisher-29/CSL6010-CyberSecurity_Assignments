from scapy.all import rdpcap, send
# Loading captured packets
packets = rdpcap("before_attack.pcapng")
# Replaying each packet
print("Replaying packets...")
for packet in packets:
    send(packet)
    print(f"Replayed: {packet.summary()}")
