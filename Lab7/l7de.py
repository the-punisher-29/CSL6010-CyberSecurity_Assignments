from scapy.all import rdpcap

def detect_replay(pcap_file):
    packets = rdpcap(pcap_file)
    seen_packets = set()
    replayed_packets = []

    for packet in packets:
        if packet.haslayer("ICMP"):
            # Create a unique identifier using sequence number and payload
            identifier = (packet[ICMP].seq, bytes(packet[ICMP].payload))
            if identifier in seen_packets:
                replayed_packets.append(packet)
            else:
                seen_packets.add(identifier)

    print(f"Detected {len(replayed_packets)} replayed packets.")
    for pkt in replayed_packets:
        print(pkt.summary())

# Detect replayed packets in capture file
detect_replay("capture.pcap")
