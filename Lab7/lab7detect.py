from scapy.all import rdpcap

# Loading the captured packets
packets = rdpcap('captured_packets.pcapng')  # Replace with your .pcapng file path
# Initializing sets to track seen sequence numbers and payloads
seen_seq_numbers = set()
seen_payloads = set()
# Tracking replayed packets
replayed_packets = []
# Iterating through each packet
for pkt in packets:
    if pkt.haslayer('ICMP'):  # Check if it's an ICMP packet
        icmp_layer = pkt['ICMP']
        # Getting sequence number and payload (if available)
        seq_number = icmp_layer.seq if hasattr(icmp_layer, 'seq') else None
        payload = bytes(pkt[ICMP].payload)
        # Checking for duplicates
        if seq_number in seen_seq_numbers or payload in seen_payloads:
            replayed_packets.append(pkt)
        else:
            seen_seq_numbers.add(seq_number)
            seen_payloads.add(payload)

# Outputing results
print(f"Total Packets: {len(packets)}")
print(f"Replayed Packets Detected: {len(replayed_packets)}")

if replayed_packets:
    print("\nDetails of Replayed Packets:")
    for rpkt in replayed_packets:
        print(rpkt.summary())
else:
    print("No replayed packets detected.")