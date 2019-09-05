import socket
import struct

class EthFrame():
    def __init__(self, socket_buffer=None):
        self.dst     = socket_buffer[  :6];
        self.src     = socket_buffer[ 6:12];
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
    def pretty(self):
        return "[ETH] Protocol: %s (%s) -> (%s)" % (self.protocol, self.src_address, self.dst_address)

class ARPFrame():
    def __init__(self, socket_buffer=None):
        self.eth_frame = EthFrame(socket_buffer)

        self.hwtype         = self.eth_frame.payload[ :2]
        self.proto_type     = self.eth_frame.payload[2:4]
        self.hlen           = self.eth_frame.payload[4:5]
        self.plen           = self.eth_frame.payload[5:6]
        self.op             = self.eth_frame.payload[6:8]
        self.sender_hw_addr = self.eth_frame.payload[8:14]
        self.sender_ip_addr = self.eth_frame.payload[14:18]
        self.target_hw_addr = self.eth_frame.payload[18:24]
        self.target_ip_addr = self.eth_frame.payload[24:28]

        self.opcode = int.from_bytes(self.op, byteorder='big', signed=False)

        self.sender_mac = "%02X:%02X:%02X:%02X:%02X:%02X" % struct.unpack('BBBBBB', self.sender_hw_addr)
        self.target_mac = "%02X:%02X:%02X:%02X:%02X:%02X" % struct.unpack('BBBBBB', self.target_hw_addr)

        self.sender_ip = socket.inet_ntoa(self.sender_ip_addr)
        self.target_ip = socket.inet_ntoa(self.target_ip_addr)

        self.oper_map = {1:'request', 2:'reply'}
        self.operation = self.oper_map[self.opcode] if (self.opcode in self.oper_map) else self.opcode

    def pretty(self):
        pretty_string = self.eth_frame.pretty()+"\n[ARP] "

        # ARP request
        if self.opcode == 1:
            pretty_string += "Who has %s (%s)? Tell %s (%s)" % (self.target_ip, self.target_mac, self.sender_ip, self.sender_mac)
        # ARP reply
        else:
            pretty_string += "%s is at %s -> %s (%s)" % (self.sender_ip, self.sender_mac, self.target_ip, self.target_mac)
        return pretty_string



device = "eth0"
packet_count = 10;

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
sniffer_socket.bind((device, socket.SOCK_RAW))

try:
    while packet_count > 0:
        raw_frame = sniffer_socket.recvfrom(65565)[0]
        eth_frame = EthFrame(raw_frame)

        if eth_frame.protocol == "ARP":
            arp_frame = ARPFrame(raw_frame)
            print(arp_frame.pretty())
            print()
            --packet_count


except KeyboardInterrupt:
    print("\nExiting")
