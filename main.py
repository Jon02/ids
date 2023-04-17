from getmac import get_mac_address

from attacks import arpspoofing, macflooding
import pyshark

interface = ""
interface_mac = ""


def detect(packets):
    for packet in packets:
        if "ARP" in str(packet.layers) and packet.arp.opcode == "2":
            arpspoofing.detect(packet, interface, interface_mac)
        elif "MDNS" in str(packet.layers):
            macflooding.detect(packet)


if __name__ == '__main__':
    interface = "\\Device\\NPF_{C2A80708-19BC-4B96-9CF6-9D52377864AE}"
    interface_mac = get_mac_address(interface=interface)

    capture = pyshark.LiveCapture(interface=interface)
    while 1:
        detect(capture.sniff_continuously(packet_count=50))
