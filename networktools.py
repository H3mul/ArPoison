import socket
import struct

# An aggregate factory of Frame objects.
# Sequentially peels layers of frames, stores parsed frame types
# in separate object members.
class Frame():
    def __init__(self, raw_buffer=None):
        if not raw_buffer:
            return

        self.types = []
        self.addtype("eth", EthFrame(raw_buffer))

        if self.eth.proto_code == "0x0806":
            self.addtype("arp", ARPFrame(self.eth.payload))
        elif self.eth.proto_code == "0x0800":
            self.addtype("ip", ARPFrame(self.eth.payload))

    def pretty(self):
        pretty_strings = []
        for frame_type in self.types:
            if hasattr(self, frame_type):
                pretty_strings.append(getattr(self, frame_type).pretty())
        return "\n".join(pretty_strings)

    def addtype(self, type_name, type_frame):
        setattr(self, type_name, type_frame)
        self.types.append(type_name)
        self.type = type_name


def decodeMac(mac_binary):
    return "%02X:%02X:%02X:%02X:%02X:%02X" % unpackBinary(mac_binary)

def unpackBinary(data):
    unpack_string = ""
    for byte in data:
        unpack_string += "B"
    return struct.unpack(unpack_string, data)


class BaseFrame():
    def __init__(self, raw_buffer=None):
        if raw_buffer:
            self.parse(raw_buffer) 
            self.humanReadable()
    def parse(self, raw_buffer):
       raise Exception("Must implement parsing") 
    def humanReadable(self):
        pass
    def pretty(self):
        return vars(self)

class EthFrame(BaseFrame):
    def parse(self, raw_buffer):
        self.dst_mac_raw = raw_buffer[  :6]
        self.src_mac_raw = raw_buffer[ 6:12]
        self.type_raw    = raw_buffer[12:14]
        self.payload     = raw_buffer[14:]

    def humanReadable(self):
        # human readable IP addresses 
        self.src_mac = decodeMac(self.src_mac_raw)
        self.dst_mac = decodeMac(self.dst_mac_raw)
        self.proto_code = "0x%02X%02X" % unpackBinary(self.type_raw)

        # human readable protocol
        protocol_map = {'0x0806':"ARP", "0x0800":"IP"}
        if self.proto_code in protocol_map:
            self.proto = protocol_map[self.proto_code]
        else:
            self.proto = self.proto_code

    def pretty(self):
        return "[ETH] Protocol: %s (%s) -> (%s)" % (self.proto, self.src_mac, self.dst_mac)

class ARPFrame(BaseFrame):
    def parse(self, raw_buffer):
        self.hwtype         = raw_buffer[ :2]
        self.proto_type     = raw_buffer[2:4]
        self.hlen           = raw_buffer[4:5]
        self.plen           = raw_buffer[5:6]
        self.op             = raw_buffer[6:8]
        self.sender_hw_addr = raw_buffer[8:14]
        self.sender_ip_addr = raw_buffer[14:18]
        self.target_hw_addr = raw_buffer[18:24]
        self.target_ip_addr = raw_buffer[24:28]

    def humanReadable(self):
        self.opcode = int.from_bytes(self.op, byteorder='big', signed=False)

        self.sender_mac = decodeMac(self.sender_hw_addr)
        self.target_mac = decodeMac(self.target_hw_addr)

        self.sender_ip = socket.inet_ntoa(self.sender_ip_addr)
        self.target_ip = socket.inet_ntoa(self.target_ip_addr)

        self.oper_map = {1:'request', 2:'reply'}
        self.operation = self.oper_map[self.opcode] if (self.opcode in self.oper_map) else self.opcode

    def pretty(self):
        pretty_string = "[ARP] "

        # ARP request
        if self.opcode == 1:
            pretty_string += "Who has %s (%s)? Tell %s (%s)" % (self.target_ip, self.target_mac, self.sender_ip, self.sender_mac)
        # ARP reply
        else:
            pretty_string += "%s is at %s -> %s (%s)" % (self.sender_ip, self.sender_mac, self.target_ip, self.target_mac)
        return pretty_string
        
class IPFrame(BaseFrame):
    def parse(self, raw_buffer):
        self.v_hl          = raw_buffer[ :1]
        self.stype         = raw_buffer[1:2]
        self.l             = raw_buffer[2:4]
        self.id            = raw_buffer[4:6]
        self.flags_foffset = raw_buffer[6:8]
        self.ttl           = raw_buffer[8:9]
        self.proto_raw     = raw_buffer[9:10]
        self.chksum        = raw_buffer[10:12]
        self.src_ip_raw    = raw_buffer[12:16]
        self.dst_ip_raw    = raw_buffer[16:20]
        self.opts          = raw_buffer[20:23]
        self.pad           = raw_buffer[23:24]
    def humanReadable(self):
        pass
    def pretty(self):
        return vars(self)

class ICMPFrame(BaseFrame):
    def parse(self, raw_buffer):
        self.type   = raw_buffer[ :1]
        self.code   = raw_buffer[1:2]
        self.chksum = raw_buffer[2:4]
        self.id     = raw_buffer[4:6]
        self.sid    = raw_buffer[6:8]
        self.data   = raw_buffer[8:]
    def humanReadable(self):
        pass
    def pretty(self):
        return vars(self)

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
