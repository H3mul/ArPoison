import unittest
from lib.frames import *

class TestARPFrame(unittest.TestCase):
    def setUp(self):
        self.raw_arp_request = b'\x00\x01\x08\x00\x06\x04\x00\x01\xac\x84\xc6Q\xe5\x8e\n\x00\x00\x01\x00\x00\x00\x00\x00\x00\n\x00\x00\xcb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.raw_arp_response = b"\x00\x01\x08\x00\x06\x04\x00\x02\xb8'\xebn\xd7\xfa\n\x00\x00\xcb\xac\x84\xc6Q\xe5\x8e\n\x00\x00\x01"
        self.pretty_arp_request = "[ARP]\tWho has 10.0.0.203 (00:00:00:00:00:00)? Tell 10.0.0.1 (AC:84:C6:51:E5:8E)"
        self.pretty_arp_response = "[ARP]\t10.0.0.203 is at B8:27:EB:6E:D7:FA -> 10.0.0.1 (AC:84:C6:51:E5:8E)"

    def test_parse_raw_request(self):
        arpf = ARPFrame(self.raw_arp_request)

        self.request_sender_mac = arpf.getSenderMac()
        self.request_target_mac = arpf.getTargetMac()
        self.request_sender_ip = arpf.getSenderIP()
        self.request_target_ip = arpf.getTargetIP()

        self.assertEqual(arpf.pretty(), self.pretty_arp_request)

    def test_parse_raw_response(self):
        arpf = ARPFrame(self.raw_arp_response)

        self.response_sender_mac = arpf.getSenderMac()
        self.response_target_mac = arpf.getTargetMac()
        self.response_sender_ip = arpf.getSenderIP()
        self.response_target_ip = arpf.getTargetIP()

        self.assertEqual(arpf.pretty(), self.pretty_arp_response)

    def test_assemble_request(self):
        arpf = ARPFrame()

        arpf.setSenderMac(self.request_sender_mac)
        arpf.setTargetMac(self.request_target_mac)
        arpf.setSenderIP(self.request_sender_ip)
        arpf.setTargetIP(self.request_target_ip)

        self.assertEqual(arpf.raw(), self.raw_arp_request)

    def test_assemble_response(self):
        arpf = ARPFrame()

        arpf.setSenderMac(self.response_sender_mac)
        arpf.setTargetMac(self.response_target_mac)
        arpf.setSenderIP(self.response_sender_ip)
        arpf.setTargetIP(self.response_target_ip)

        self.assertEqual(arpf.raw(), self.raw_arp_response)

if __name__ == "__main__":
    unittest.main()
