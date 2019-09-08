import sniffer

def arpFilter(frame):
    return frame.type == 'arp'

try:
    sniffer = sniffer.Sniffer(device = 'eth0')
    for frame in sniffer.sniff(arpFilter, 4):
        print(frame.pretty())
        print()
except KeyboardInterrupt:
    print("\nExiting")
