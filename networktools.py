import socket
import struct

class EthFrame():
    def __init__(self, socket_buffer=None):
        self.src     = socket_buffer[ 0:6];
        self.dst     = socket_buffer[ 6:12];
        self.type    = socket_buffer[12:14];
        self.payload = socket_buffer[14:];

        # map protocol constants to their names
        self.protocol_map = {'0x0806':"ARP"}

        # human readable IP addresses 
        self.src_address = "%02X:%02X:%02X:%02X:%02X:%02X" % struct.unpack('BBBBBB', self.src)
        self.dst_address = "%02X:%02X:%02X:%02X:%02X:%02X" % struct.unpack('BBBBBB', self.dst)
        self.protocol = "0x%02X%02X" % struct.unpack('BB', self.type)

        # human readable protocol
        if self.protocol in self.protocol_map:
            self.protocol = self.protocol_map[self.protocol]


device = "wlan0"
packet_count = 10;

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
sniffer_socket.bind((device, socket.SOCK_RAW))

try:
    for i in range(0,packet_count):
        raw_frame = sniffer_socket.recvfrom(65565)[0]
        eth_frame = EthFrame(raw_frame)
        print("Protocol: %s %s -> %s\nPayload: \n%s" % (eth_frame.protocol, eth_frame.src_address, eth_frame.dst_address, eth_frame.payload))
        print()

except KeyboardInterrupt:
    print("\nExiting")
