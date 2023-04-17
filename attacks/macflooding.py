counter = 0


def detect(packet):
    #MDNS protocol is not used here, regular IPv4 packet instead
    global counter

    counter += 1
    print(packet)
