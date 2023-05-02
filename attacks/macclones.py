import re


def get_results():
    counter = 0

    with open('/proc/net/arp') as proc_net_arp:
        arp_data_raw = proc_net_arp.read(-1).split("\n")[1:-1]
        parsed_arp_table = (dict(zip(('ip_address', 'type', 'flags', 'hw_address', 'mask', 'device'), v))
                            for v in (re.split('\s+', i) for i in arp_data_raw))

        mac_addresses = []
        for d in parsed_arp_table:
            mac_addresses.append(d['hw_address'])
        if len(set(mac_addresses)) < len(mac_addresses):
            counter += 1

    print(counter)
    return counter
