import unittest
from packet_sniffer import start_sniffing
from protocol_analyzer import analyze_packet
from threat_detector import ThreatDetector
from scapy.all import IP, TCP, Ether
class TestIDSComponents(unittest.TestCase):
    def test_sniffing(self):
        packets = start_sniffing(count=5)
        self.assertTrue(len(packets) > 0)
    def test_analyze_tcp(self):
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        info = analyze_packet(pkt)
        self.assertEqual(info["src_ip"], "192.168.1.1")
        self.assertEqual(info["protocol"], "TCP")
    def test_dos_detection(self):
        det = ThreatDetector()
        pkt_info = {"src_ip": "192.168.1.100"}
        for _ in range(55):
            res = det.detect_dos(pkt_info)
        self.assertIn("DoS", res)

if __name__ == "__main__":
    unittest.main()