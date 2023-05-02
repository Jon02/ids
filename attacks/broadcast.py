mac = {}
sus_macs = []


def detect(packet):
    src = packet.eth.src
    mac[src] = mac.get(src, 0) + 1

    if mac[src] > 200 and src not in sus_macs:
        sus_macs.append(src)


def get_results():
    return len(sus_macs)


def reset():
    mac.clear()
    sus_macs.clear()