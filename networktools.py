import socket
import struct
from frames import *

device = "eth0"
packet_count = 10;

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
sniffer_socket.bind((device, socket.SOCK_RAW))

try:
    while packet_count > 0:
        raw_frame = sniffer_socket.recvfrom(65565)[0]
        frame = Frame(raw_frame)
        if frame.type == "arp":
            print(frame.pretty())
            print()
            --packet_count

except KeyboardInterrupt:
    print("\nExiting")
