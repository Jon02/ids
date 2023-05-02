from scapy.data import ETHER_BROADCAST
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

is_attacked = False


def get_mac(ip, interface, interface_mac):
    packet = Ether(dst=ETHER_BROADCAST) / ARP(op=1, pdst=ip, hwsrc=interface_mac)
    response = srp(packet, verbose=False, timeout=2, iface=interface)[0]
    return response[0][1][ARP].hwsrc


def detect(packet, interface, interface_mac):
    global is_attacked

    ip = packet.arp.src_proto_ipv4
    mac = packet.arp.src_hw_mac

    try:
        real_mac = get_mac(ip, interface, interface_mac)

        if mac != real_mac:
            print("Someone is poisoning my ARP Cache! :/ :c >:C ;d It is: " + mac + " with IP " + ip)
            is_attacked = True
    except IndexError:
        pass


def get_results():
    return is_attacked


def reset():
    global is_attacked

    is_attacked = False
