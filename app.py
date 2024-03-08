from DistUpgrade.DistUpgradeViewText import readline
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from scapy.all import rdpcap, TCP, IP
from scapy.all import rdpcap
from scapy.utils import PcapReader, hexdump

# Path to your pcap file
pcap_file = 'best_game.pcap'

def filter_tls_traffic(pcap_file):
    packets = rdpcap(pcap_file)
    tls_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443)]

    print(f"Found {len(tls_packets)} TLS (HTTPS) packets")

    for pkt in tls_packets[:10]:  # Just show the first 10 packets
        print(pkt.summary())


def allpackets_from_file(pcap_file):
    packets = PcapReader(pcap_file)

    # Iterate over each packet in the pcap file
    for packet in packets:
        # Print detailed information about the packet
        #packet.show()
        hexdump(bytes(packet))
        print("\n")


filter_tls_traffic(pcap_file)
allpackets_from_file(pcap_file)









# # Load the pcap file
# packets = rdpcap(pcap_file)
#
# # Filter for TCP packets on HTTPS port 443
# https_packets = [pkt for pkt in packets if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443)]
#
# # Iterate over filtered packets
# for packet in https_packets:
#     try:
#         # Display some basic info about the packet
#         print(f"Packet: {packet.summary()}")
#         print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")
#         print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
#         # This is where you'd attempt decryption, if you had the means
#     except Exception as e:
#         print(f"Error processing packet: {e}")
#     print("-" * 40)
