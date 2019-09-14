import unittest
import tests.fixtures as fixtures
from lib.frames import *

class TestARPFrame(unittest.TestCase):
    def setUp(self):
        self.raw_arp_request = fixtures.ARP_REQUEST_FRAME_RAW
        self.raw_arp_response = fixtures.ARP_RESPONSE_FRAME_RAW
        self.pretty_arp_request = fixtures.ARP_REQUEST_FRAME_PRETTY
        self.pretty_arp_response = fixtures.ARP_RESPONSE_FRAME_PRETTY

        self.request_arpf = ARPFrame(self.raw_arp_request)
        self.request_sender_mac = self.request_arpf.getSenderMac()
        self.request_target_mac = self.request_arpf.getTargetMac()
        self.request_sender_ip = self.request_arpf.getSenderIP()
        self.request_target_ip = self.request_arpf.getTargetIP()

        self.response_arpf = ARPFrame(self.raw_arp_response)
        self.response_sender_mac = self.response_arpf.getSenderMac()
        self.response_target_mac = self.response_arpf.getTargetMac()
        self.response_sender_ip = self.response_arpf.getSenderIP()
        self.response_target_ip = self.response_arpf.getTargetIP()


    def test_parse_raw_request(self):
        self.assertEqual(self.request_arpf.pretty(), self.pretty_arp_request)

    def test_parse_raw_response(self):
        self.assertEqual(self.response_arpf.pretty(), self.pretty_arp_response)

    def test_assemble_request(self):
        arpf = ARPFrame()

        arpf.setOperation('request')
        arpf.setSenderMac(self.request_sender_mac)
        arpf.setTargetMac(self.request_target_mac)
        arpf.setSenderIP(self.request_sender_ip)
        arpf.setTargetIP(self.request_target_ip)

        self.assertEqual(arpf.getRaw(), self.raw_arp_request)

    def test_assemble_response(self):
        arpf = ARPFrame()

        arpf.setOperation('response')
        arpf.setSenderMac(self.response_sender_mac)
        arpf.setTargetMac(self.response_target_mac)
        arpf.setSenderIP(self.response_sender_ip)
        arpf.setTargetIP(self.response_target_ip)

        self.assertEqual(arpf.getRaw(), self.raw_arp_response)

if __name__ == "__main__":
    unittest.main()
