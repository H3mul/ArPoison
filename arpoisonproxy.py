
# Convince a victim that you are the holder of an target ip address using ARP poisoning.

victim_ip = "10.0.0.131" # pater wlan0
target_ip = "10.0.0.202" # hemul-gaming

# NetworkTools
def sniff_packets(protocol):
    ...

def get_mac(ip):
    ...

def send_eth_packet(srcip, dstip, srcmac, dstmac):
    ...

def send_arp_response(srcip, dstip, srcmac, dstmac):
    ...

# ARPpoison
def poison_target():
    ...


