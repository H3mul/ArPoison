import socket
import struct

# An aggregate factory of Frame objects.
# Sequentially peels layers of frames, stores parsed frame types
# in separate object members.
class Frame():
    def __init__(self, raw_buffer=None, create_type=None):
        self.types = []
        if not raw_buffer:
            if create_type == "arp":
                self.addtype("eth", EthFrame())
                self.addtype("arp", ARPFrame())
            self.assemble()
            return

        self.addtype("eth", EthFrame(raw_buffer))

        if self.eth.proto_code == "0x0806":
            self.addtype("arp", ARPFrame(self.eth.payload))
        elif self.eth.proto_code == "0x0800":
            self.addtype("ip", IPFrame(self.eth.payload))
            if self.ip.proto_code == 1:
                self.addtype("icmp", ICMPFrame(self.ip.payload))

    def process(self):
        types = self.types[::-1]
        for frame_type in types:
            getattr(self, frame_type).process()

        # Set each layer's raw field to previous one's payload
        for i in range(len(types)-1):
            getattr(self, types[i]).payload = getattr(self, types[i+1]).raw

    def assemble(self):
        for frame_type in self.types:
            getattr(self, frame_type).encodeHumanReadable()

        self.process()
        return self.raw()

    def raw(self):
        return getattr(self, self.types[0]).raw

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


# Helper functions
#-----------------

def decodeMac(mac_binary):
    return "%02X:%02X:%02X:%02X:%02X:%02X" % unpackBinary(mac_binary)
def encodeMac(mac):
    return packBinary(mac.lower().split(':'))

def unpackBinary(data):
    return struct.unpack("B"*len(data), data)
def packBinary(data):
    data = [int(byte, 16) for byte in data]
    return struct.pack(str(len(data))+"B", *data)


# Frames
#-----------------

class BaseFrame():
    def __init__(self, raw_buffer=None):
        self.raw = raw_buffer if raw_buffer else b''
        self.setAttributes()
        for i, att in enumerate(self.att_names):
            data = self.defaults[i] if len(self.defaults) > i else None
            setattr(self, att, data)
        if self.raw:
            self.parse()
    def setAttributes(self):
       raise Exception("Must implement frame attributes")

    # parse raw into attrs if parse
    # assemble raw from attrs otherwise
    def process(self, parse=True):
        boundaries = self.boundaries
        att_names = self.att_names
        if len(boundaries) < len(att_names) or len(boundaries) > len(att_names)+1:
            raise Exception("Incorrectly assembled name and boundary sequence")

        if len(boundaries) == len(att_names):
            boundaries.append(None)

        for i in range(0, len(boundaries)-1):
            start = boundaries[i]
            end = boundaries[i+1]
            if parse:
                setattr(self, att_names[i], self.raw[start:end])
            else:
                zeros = struct.pack(str(end-start)+'B', *([0]*(end-start))) 
                self.raw += getattr(self, att_names[i]) or zeros
    def assemble(self):
        self.process(parse=False)

    def parse(self):
        self.process()

    def pretty(self):
        return str(vars(self))

    def getRaw(self):
        self.assemble()
        return self.raw


class EthFrame(BaseFrame):
    def setAttributes(self):
        conf = {
            'dst_mac_raw' : 0,
            'src_mac_raw' : 6,
            'type_raw'    : 12,
            'payload'     : 14
        }
        self.boundaries = list(conf.values())
        self.att_names = list(conf.keys())
        self.protocol_map = {'0x0806':"ARP", "0x0800":"IP"}

    def decodeHumanReadable(self):
        # human readable IP addresses
        self.src_mac = decodeMac(self.src_mac_raw)
        self.dst_mac = decodeMac(self.dst_mac_raw)
        self.proto_code = "0x%02X%02X" % unpackBinary(self.type_raw)

        # human readable protocol
        if self.proto_code in self.protocol_map:
            self.proto = self.protocol_map[self.proto_code]
        else:
            self.proto = self.proto_code

    def encodeHumanReadable(self):
        self.dst_mac_raw = encodeMac(self.dst_mac)
        self.src_mac_raw = encodeMac(self.src_mac)

        proto = self.proto_code
        if proto.startswith('0x'):
            proto = proto[2:]
        self.type_raw = packBinary(proto)

    def pretty(self):
        pretty_string = "[ETH]"
        if self.proto == self.proto_code:
            pretty_string += "[%s]" % self.proto
        return pretty_string+"\t(%s) -> (%s)" % (self.src_mac, self.dst_mac)

class ARPFrame(BaseFrame):
    def setAttributes(self):
        self.att_names = ['hwtype', 'proto_type', 'hlen', 'plen', 'op', 'sender_hw_addr',
                'sender_ip_addr', 'target_hw_addr', 'target_ip_addr' ]
        self.boundaries = [0,2,4,5,6,8,14,18,24,28]
        self.defaults = [
            b'\x00\x01', #hwtype Ethernet
            b'\x08\x00', #protocol IPV4
            b'\x06',     #hw addr size
            b'\x04',     #protocol size
            b'\x00\x01',     #opcode: arp request
        ]
        self.oper_map = {1:'request', 2:'reply'}

    def pretty(self):
        pretty_string = "[ARP]\t"

        # ARP request
        if self.getOpcode() == 1:
            pretty_string += "Who has %s (%s)? Tell %s (%s)" % (self.getTargetIP(), self.getTargetMac(), self.getSenderIP(), self.getSenderMac())
        # ARP reply
        else:
            pretty_string += "%s is at %s -> %s (%s)" % (self.getSenderIP(), self.getSenderMac(), self.getTargetIP(), self.getTargetMac())
        return pretty_string

    #################################

    def getSenderMac(self):
        return decodeMac(self.sender_hw_addr)
    
    def setSenderMac(self, sender_mac):
        self.sender_hw_addr = encodeMac(sender_mac)


    def getSenderIP(self):
        return socket.inet_ntoa(self.sender_ip_addr)
    
    def setSenderIP(self, sender_ip):
        self.sender_ip_addr = socket.inet_aton(sender_ip)


    def getTargetMac(self):
        return decodeMac(self.target_hw_addr)
    
    def setTargetMac(self, target_mac):
        self.target_hw_addr = encodeMac(target_mac)


    def getTargetIP(self):
        return socket.inet_ntoa(self.target_ip_addr)
    
    def setTargetIP(self, target_ip):
        self.target_ip_addr = socket.inet_aton(target_ip)


    def getOpcode(self):
        return int.from_bytes(self.op, byteorder='big', signed=False)

    def setOpcode(self, opcode):
        self.op = bytes([0, opcode])

    def setOperation(self, operation='request'):
        if operation == 'request':
            self.setOpcode(1);
        elif operation == 'response':
            self.setOpcode(2);

    def getOperation(self):
        return self.oper_map[self.opcode] if (self.opcode in self.oper_map) else self.opcode

#####################################

class IPFrame(BaseFrame):

    def setAttributes(self):
        self.att_names = ['v_hl','stype','l','id','flags_foffset','ttl',
                    'proto_raw','chksum','src_ip_raw','dst_ip_raw','payload']
        self.boundaries = [0,1,2,4,6,8,9,10,12,16,20]
        self.proto_map = {1:'icmp'}

    def decodeHumanReadable(self):
        self.src_ip = socket.inet_ntoa(self.src_ip_raw)
        self.dst_ip = socket.inet_ntoa(self.dst_ip_raw)
        self.proto_code = int.from_bytes(self.proto_raw, byteorder='big', signed=False)

        self.proto = self.proto_map[self.proto_code] if (self.proto_code in self.proto_map) else self.proto_code

    def pretty(self):
        pretty_string = "[IP]"
        if self.proto == self.proto_code:
            pretty_string += "[%s]" % (self.proto_code)
        return pretty_string + "\t%s -> %s" % (self.src_ip, self.dst_ip)


class ICMPFrame(BaseFrame):

    def setAttributes(self):
        self.att_names = ['type_raw','code_raw','chksum','data']
        self.boundaries = [0,1,2,4]

    def decodeHumanReadable(self):
        self.type = int.from_bytes(self.type_raw, byteorder='big', signed=False)
        self.code = int.from_bytes(self.code_raw, byteorder='big', signed=False)
        self.message = ""

        if self.type == 0:
            self.message = "Echo Reply"
        elif self.type == 3:
            self.message = "Destination Unreachable"
        elif self.type == 5:
            self.message = "Redirect"
        elif self.type == 8:
            self.message = "Echo Request"

    def pretty(self):
        pretty_string = "[ICMP]"
        if self.message:
            pretty_string += "\t%s" % (self.message)
        else:
            pretty_string += "\tType:%s Code:%s" % (self.type, self.code)
        return pretty_string
