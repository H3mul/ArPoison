import socket
import frames

class Sniffer():
    def __init__(self, sniffer_socket=None, device=None):
        if sniffer_socket:
            self.socket = sniffer_socket
        else:
            if not device:
                device = "eth0"
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
            self.socket.bind((device, socket.SOCK_RAW))

    def sniff(self, filter_func=None, packet_count=1):
        while packet_count > 0:
            raw_frame = self.socket.recv(65565)
            frame = frames.Frame(raw_frame)
            if not filter_func or filter_func(frame):
                packet_count -= 1
                yield frame

    def sniffAll(self, filter_func=None, packet_count=1):
        frames = []
        for frame in sniff(filter_func, packet_count, socket):
            frames.append(frame)
        return frames
