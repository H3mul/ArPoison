import unittest
import tests.fixtures as fixtures
from lib.frames import *

class TestEthFrame(unittest.TestCase):
    def setUp(self):
        self.raw_eth_request = fixtures.ETH_ARP_REQUEST_FRAME_RAW
        self.raw_eth_response = fixtures.ETH_ARP_RESPONSE_FRAME_RAW
        self.raw_arp_request = fixtures.ARP_REQUEST_FRAME_RAW
        self.raw_arp_response = fixtures.ARP_RESPONSE_FRAME_RAW
        self.pretty_eth_request = fixtures.ETH_REQUEST_FRAME_PRETTY
        self.pretty_eth_response = fixtures.ETH_RESPONSE_FRAME_PRETTY

        self.request_ethf = EthFrame(self.raw_eth_request)
        self.request_src_mac = self.request_ethf.getSrcMac()
        self.request_dst_mac = self.request_ethf.getDstMac()

        self.response_ethf = EthFrame(self.raw_eth_response)
        self.response_src_mac = self.response_ethf.getSrcMac()
        self.response_dst_mac = self.response_ethf.getDstMac()


    def test_parse_raw_request(self):
        self.assertEqual(self.request_ethf.pretty(), self.pretty_eth_request)

    def test_parse_raw_response(self):
        self.assertEqual(self.response_ethf.pretty(), self.pretty_eth_response)

    def test_assemble_request(self):
        ethf = EthFrame()

        ethf.setProtoCode('0x0806')
        ethf.setSrcMac(self.request_src_mac)
        ethf.setDstMac(self.request_dst_mac)
        ethf.setPayload(self.raw_arp_request)

        self.assertEqual(ethf.getRaw(), self.raw_eth_request)

    def test_assemble_response(self):
        ethf = EthFrame()

        ethf.setProtoCode('0x0806')
        ethf.setSrcMac(self.response_src_mac)
        ethf.setDstMac(self.response_dst_mac)
        ethf.setPayload(self.raw_arp_response)

        self.assertEqual(ethf.getRaw(), self.raw_eth_response)

if __name__ == "__main__":
    unittest.main()
