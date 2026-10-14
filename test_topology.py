import unittest

from scapy.all import ICMP, IP

import backend


class NetworkTopologyTest(unittest.TestCase):
    def test_topology_returns_real_network_details(self):
        topology = backend.get_local_network_topology()
        self.assertIsInstance(topology, list)
        self.assertGreater(len(topology), 0)
        self.assertIn('name', topology[0])
        self.assertIn('ip', topology[0])

    def test_topology_uses_gateway_and_local_host_labels(self):
        topology = backend.get_local_network_topology()
        names = {item['name'] for item in topology}
        self.assertIn('Gateway', names)
        self.assertIn('Local Host', names)

    def test_raw_packet_data_contains_captured_fields(self):
        backend.packets = [{
            'timestamp': '12:00:00',
            'sourceIp': '192.168.1.10',
            'destinationIp': '192.168.1.100',
            'sourcePort': 1234,
            'destinationPort': 80,
            'protocol': 'TCP',
            'packetLength': 64,
            'ttl': 64,
            'flags': 'SYN',
            'status': 'NORMAL',
            'prediction': 'NORMAL',
        }]
        packet_data = backend.get_raw_packet_data()
        self.assertEqual(packet_data[0]['sourceIp'], '192.168.1.10')
        self.assertEqual(packet_data[0]['protocol'], 'TCP')

    def test_icmp_ping_packets_are_preserved_in_live_buffer(self):
        original_packets = backend.packets[:]
        original_monitoring = backend.monitoring
        backend.monitoring = True
        backend.packets = []

        try:
            for i in range(20):
                packet = IP(src='10.0.0.1', dst='8.8.8.8') / ICMP(type=8)
                backend.packet_callback(packet)
            live_packets = backend.get_raw_packet_data()
            self.assertGreater(len(live_packets), 8)
            self.assertTrue(any(packet.get('protocol') == 'ICMP' for packet in live_packets))
            self.assertTrue(any(packet.get('status') == 'PING' for packet in live_packets))
        finally:
            backend.packets = original_packets
            backend.monitoring = original_monitoring


if __name__ == '__main__':
    unittest.main()
