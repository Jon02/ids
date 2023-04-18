from scapy.all import *

# Set the network interface to monitor
iface = "Ethernet 3"

# Define a dictionary to store the number of packets received from each MAC address
mac_count = {}

def detect_broadcast_storm(pkt):
    # Check if the packet is a broadcast packet
    if pkt.dst == "ff:ff:ff:ff:ff:ff":
        # Get the source MAC address of the packet
        src_mac = pkt.src
        # Update the count for the source MAC address
        mac_count[src_mac] = mac_count.get(src_mac, 0) + 1
        # Check if the count for the source MAC address exceeds a threshold (e.g. 100 packets)
        if mac_count[src_mac] > 1000:
            print("Broadcast storm detected from MAC address", src_mac)
            # TODO: take action to mitigate the broadcast storm

# Start sniffing on the specified interfa,,,21,1ce
sniff(iface=iface, prn=detect_broadcast_storm)