import sys
import time

from getmac import get_mac_address
from attacks import arpspoofing, broadcast, macclones
import pyshark

# Arguments to start script: python main.py [Interface] [CSV-Path]

interface = sys.argv[1]
interface_mac = ""


def detect(packets):
    for packet in packets:

        if packet.eth.dst == "ff:ff:ff:ff:ff:ff" and not packet.eth.dst == interface_mac:
            broadcast.detect(packet)
        if "ARP" in str(packet.layers) and packet.arp.opcode == "2":
            arpspoofing.detect(packet, interface, interface_mac)


def write():
    try:
        with open(sys.argv[2], "w") as file:
            count_broadcast = str(broadcast.get_results())
            arp_spoofing = str(arpspoofing.get_results())
            mac_clones = str(macclones.get_results())

            file.write("BROADCAST;" + count_broadcast + "\nARP;" + arp_spoofing + "\nMAC_CLONES;" + mac_clones + "\n")
    except:
        pass


if __name__ == '__main__':
    interface_mac = get_mac_address(interface=interface)

    counter = 0

    capture = pyshark.LiveCapture(interface=interface)
    while 1:
        detect(capture.sniff_continuously(packet_count=50))
        counter += 1

        write()

        if counter >= 10:
            broadcast.reset()
            arpspoofing.reset()
            counter = 0

        time.sleep(1)
