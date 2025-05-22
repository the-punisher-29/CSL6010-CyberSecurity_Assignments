from scapy.all import rdpcap
import logging
import time

# Configuring logging to log suspicious activity
logging.basicConfig(filename='replay_attack_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')
# Loading the captured packets
packets = rdpcap('captured_packets.pcapng')
# Initializing sets to track seen sequence numbers, payloads, and timestamps
seen_seq_numbers = set()
seen_payloads = set()
seen_timestamps = set()

# Tracking replayed packets
replayed_packets = []
# Defining time window for valid packets (e.g., 2 minutes)
TIME_WINDOW = 120  # seconds
# Getting the current time for timestamp validation
current_time = time.time()

# Iterating through each packet
for pkt in packets:
    if pkt.haslayer('ICMP'):  # Checking if it's an ICMP packet
        icmp_layer = pkt['ICMP']

        # Getting sequence number, payload, and timestamp (if available)
        seq_number = icmp_layer.seq if hasattr(icmp_layer, 'seq') else None
        payload = bytes(pkt[ICMP].payload)
        pkt_time = pkt.time if hasattr(pkt, 'time') else None

        # Checking for duplicates in sequence numbers and payloads
        if seq_number in seen_seq_numbers or payload in seen_payloads:
            replayed_packets.append(pkt)
            logging.info(f"Replay detected: Sequence Number={seq_number}, Payload={payload}")

        # Checking for outdated timestamps
        elif pkt_time and (current_time - pkt_time > TIME_WINDOW):
            logging.info(f"Outdated packet detected: Timestamp={pkt_time}")
        
        else:
            seen_seq_numbers.add(seq_number)
            seen_payloads.add(payload)
            if pkt_time:
                seen_timestamps.add(pkt_time)

# Outputing results
print(f"Total Packets: {len(packets)}")
print(f"Replayed Packets Detected: {len(replayed_packets)}")

if replayed_packets:
    print("Details of Replayed Packets logged in replay_attack_log.txt")
else:
    print("No replayed packets detected.")