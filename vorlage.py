import csv
import multiprocessing
import re
import time
from functools import partial

from scapy.all import Ether, ARP, DNS, srp, sniff


def get_mac(ip):
    """
    Returns MAC-Address of 'ip', if it's unable to find it -> Throw IndexError
    """

    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


def process(queueARP, queueMDNS, packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # if they are different -> ARP Spoofing attack
                if real_mac != response_mac:
                    print(f"[ARP Spoofing] You are under attack")
                    counterARP = queueARP.get()
                    counterARP += 1
                    queueARP.put(counterARP)
            except IndexError:
                pass
    elif packet.haslayer(DNS):
        counterMDNS = queueMDNS.get()
        counterMDNS += 1
        queueMDNS.put(counterMDNS)


def sniff_network(queueARP, queueMDNS):
    sniff(store=False, prn=partial(process, queueARP, queueMDNS), iface='eth0')


def check_mac_clone(queueCLONE):
    with open('/proc/net/arp') as proc_net_arp:
        arp_data_raw = proc_net_arp.read(-1).split("\n")[1:-1]
        parsed_arp_table = (dict(zip(('ip_address', 'type', 'flags', 'hw_address', 'mask', 'device'), v))
                            for v in (re.split('\s+', i) for i in arp_data_raw))

        mac_addresses = []
        for d in parsed_arp_table:
            mac_addresses.append(d['hw_address'])
        if len(set(mac_addresses)) < len(mac_addresses):
            counterCLONE = queueCLONE.get()
            counterCLONE += 1
            queueCLONE.put(counterCLONE)


if __name__ == '__main__':

    while 1:
        print('20 seconds over, updated csv file')
        counterARP = 0
        counterMDNS = 0
        counterCLONE = 0
        queueARP = multiprocessing.Queue()
        queueMDNS = multiprocessing.Queue()
        queueCLONE = multiprocessing.Queue()
        queueARP.put(counterARP)
        queueMDNS.put(counterMDNS)
        queueCLONE.put(counterCLONE)
        p = multiprocessing.Process(target=sniff_network, name="Sniffer", args=(queueARP, queueMDNS,))
        p2 = multiprocessing.Process(target=check_mac_clone, name="CloneDetector", args=(queueCLONE,))
        p.start()
        p2.start()

        time.sleep(20)

        p.terminate()
        p2.terminate()

        rows = [
            ['MDNS', queueMDNS.get()],
            ['ARP', queueARP.get()],
            ['CLONES', queueCLONE.get()]
        ]
        with open('data.csv', 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=';', quotechar='"')
            csv_writer.writerows(rows)

        p.join()
        p2.join()
