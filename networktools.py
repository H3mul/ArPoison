import sniffer
from utils import *

def ping(host):
    return runCmd(['ping', '-qc 1', host])

def arpMacLookup(host):
    cmds = [
        ["arp"],
        ["grep", host],
        ["head", "-n 1"],
        ["awk","{print $3}"]
    ]
    return pipeCmds(cmds)

def getMac(host):
    ping(host)
    return arpMacLookup(host);


def arpFilter(frame):
    return frame.type == 'arp'

def icmpFilter(frame):
    return frame.type == 'icmp'

try:
    target_ip = '10.0.0.201'

    print(getMac(target_ip))
    sniffer = sniffer.Sniffer(device = 'eth0')
    for frame in sniffer.sniff(icmpFilter, 2):
        print(frame.pretty())
        print()
except KeyboardInterrupt:
    print("\nExiting")
