import pyshark


def start():
    capture = pyshark.LiveCapture(interface='\\Device\\NPF_{4186B5FC-9B56-40E4-AD57-6E1835174B67}', display_filter="arp && arp.opcode == 2")
    detect(capture.sniff_continuously(packet_count=50))


def detect(packets):
    ip = {}

    for packet in packets:
        if packet.eth.addr in ip:
            print("ARP Spoofing detected!")
        else:
            ip[packet.eth.addr] = packet.arp.src_proto_ipv4

    print(ip)