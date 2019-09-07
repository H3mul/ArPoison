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
            self.addtype("ip", IPFrame(self.eth.payload))

    def pretty(self):
        pretty_strings = []
        for frame_type in self.types:
            if hasattr(self, frame_type):
                pretty_strings.append(str(getattr(self, frame_type).pretty()))
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
    def splitBytes(self, raw_buffer, att_names, boundaries):
        if len(boundaries) < len(att_names) or len(boundaries) > len(att_names)+1:
            raise Exception("Incorrectly assembled name and boundary sequence")

        if len(boundaries) == len(att_names):
            boundaries.append(None)

        for i in range(0, len(boundaries)-1):
            start = boundaries[i]
            end = boundaries[i+1]
            setattr(self, att_names[i], raw_buffer[start:end])

    def humanReadable(self):
        pass
    def pretty(self):
        return str(vars(self))

class EthFrame(BaseFrame):
    def parse(self, raw_buffer):
        conf = {
            'dst_mac_raw' : 0,
            'src_mac_raw' : 6,
            'type_raw'    : 12,
            'payload'     : 14
        }
        self.splitBytes(raw_buffer, list(conf.keys()), list(conf.values()))

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
        pretty_string = "[ETH]"
        if self.proto == self.proto_code:
            pretty_string += "[%s]" % self.proto
        return pretty_string+"\t(%s) -> (%s)" % (self.src_mac, self.dst_mac)

class ARPFrame(BaseFrame):
    def parse(self, raw_buffer):
        att_names = ['hwtype', 'proto_type', 'hlen', 'plen', 'op', 'sender_hw_addr',
                'sender_ip_addr', 'target_hw_addr', 'target_ip_addr' ]
        boundaries = [0,2,4,5,6,8,14,18,24,28]
        self.splitBytes(raw_buffer, att_names, boundaries)

    def humanReadable(self):
        self.opcode = int.from_bytes(self.op, byteorder='big', signed=False)

        self.sender_mac = decodeMac(self.sender_hw_addr)
        self.target_mac = decodeMac(self.target_hw_addr)

        self.sender_ip = socket.inet_ntoa(self.sender_ip_addr)
        self.target_ip = socket.inet_ntoa(self.target_ip_addr)

        self.oper_map = {1:'request', 2:'reply'}
        self.operation = self.oper_map[self.opcode] if (self.opcode in self.oper_map) else self.opcode

    def pretty(self):
        pretty_string = "[ARP]\t"

        # ARP request
        if self.opcode == 1:
            pretty_string += "Who has %s (%s)? Tell %s (%s)" % (self.target_ip, self.target_mac, self.sender_ip, self.sender_mac)
        # ARP reply
        else:
            pretty_string += "%s is at %s -> %s (%s)" % (self.sender_ip, self.sender_mac, self.target_ip, self.target_mac)
        return pretty_string

class IPFrame(BaseFrame):
    def parse(self, raw_buffer):
        att_names = ['v_hl','stype','l','id','flags_foffset','ttl',
                    'proto_raw','chksum','src_ip_raw','dst_ip_raw','opts','pad']
        boundaries = [0,1,2,4,6,8,9,10,12,16,20,23,24]
        self.splitBytes(raw_buffer, att_names, boundaries)
    def humanReadable(self):
        self.src_ip = socket.inet_ntoa(self.src_ip_raw)
        self.dst_ip = socket.inet_ntoa(self.dst_ip_raw)
    def pretty(self):
        return "[IP]\t\t%s -> %s" % (self.src_ip, self.dst_ip)

class ICMPFrame(BaseFrame):
    def parse(self, raw_buffer):
        att_names = ['type','code','chksum','id','sid','data']
        boundaries = [0,1,2,4,6,8]
        self.splitBytes(raw_buffer, att_names, boundaries)
