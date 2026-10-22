import socket
import struct
import unittest
from unittest.mock import patch

import natpmp


GATEWAY = ("10.2.0.1", 5351)


def mapping_response(protocol="TCP", internal=32849, external=32849,
                     lifetime=60, result=0, version=0):
    opcode = 130 if protocol == "TCP" else 129
    return struct.pack("!BBHIHHL", version, opcode, result, 100,
                       internal, external, lifetime)


def address_response():
    return struct.pack("!BBHI4s", 0, 128, 0, 100, socket.inet_aton("192.0.2.1"))


class FakeClock:
    now = 10.0

    def monotonic(self):
        return self.now


class FakeSocket:
    """Datagrams have delivery delays; None represents a dropped reply."""

    def __init__(self, clock, events=(), repeated_event=None):
        self.clock = clock
        self.events = list(events)
        self.repeated_event = repeated_event
        self.sent = []
        self.closed = False
        self.timeout = None

    def settimeout(self, timeout):
        if timeout <= 0:
            raise ValueError("FakeSocket expects a positive receive timeout")
        self.timeout = timeout

    def sendto(self, data, address):
        self.sent.append((self.clock.now, data, address))

    def recvfrom(self, size):
        event = self.events.pop(0) if self.events else self.repeated_event
        if event is None:
            self.clock.now += self.timeout
            raise socket.timeout()
        delay, data, address = event
        if delay > self.timeout:
            self.clock.now += self.timeout
            self.events.insert(0, (delay - self.timeout, data, address))
            raise socket.timeout()
        self.clock.now += delay
        return data[:size], address

    def close(self):
        self.closed = True


class NatPmpTests(unittest.TestCase):
    def client(self, events=(), timeout=3.0, repeated_event=None):
        self.clock = FakeClock()
        self.sock = FakeSocket(self.clock, events, repeated_event)
        clock_patch = patch.object(natpmp.time, "monotonic", self.clock.monotonic)
        socket_patch = patch.object(natpmp.socket, "socket", return_value=self.sock)
        clock_patch.start()
        socket_patch.start()
        self.addCleanup(clock_patch.stop)
        self.addCleanup(socket_patch.stop)
        client = natpmp.NatPmpClient(GATEWAY[0], timeout=timeout)
        self.addCleanup(client.close)
        return client

    def test_public_address_request(self):
        client = self.client([(0.01, address_response(), GATEWAY)])

        self.assertEqual(client.get_public_address(), "192.0.2.1")
        self.assertEqual(self.sock.sent[0][1:], (b"\x00\x00", GATEWAY))

    def test_proton_can_assign_internal_port_for_zero_request(self):
        client = self.client([(0.15, mapping_response(), GATEWAY)])

        mapping = client.create_port_mapping("TCP", lifetime=60)

        self.assertEqual(mapping["internal_port"], 32849)
        self.assertEqual(mapping["external_port"], 32849)
        self.assertEqual(mapping["lifetime"], 60)
        self.assertEqual(mapping["granted_at"], 10.0)
        self.assertEqual(mapping["expires_at"], 70.0)
        self.assertLess(mapping["granted_at"], self.clock.now)
        request = struct.unpack("!BBHHHL", self.sock.sent[0][1])
        self.assertEqual(request, (0, 2, 0, 0, 0, 60))

    def test_lost_reply_is_retried_before_lease_expiry(self):
        client = self.client([None, (0.01, mapping_response(), GATEWAY)])

        mapping = client.create_port_mapping("TCP")

        self.assertEqual(len(self.sock.sent), 2)
        self.assertEqual(self.sock.sent[0][1], self.sock.sent[1][1])
        self.assertAlmostEqual(self.sock.sent[1][0] - self.sock.sent[0][0], 0.25)
        self.assertAlmostEqual(self.clock.now, 10.26)
        self.assertEqual(mapping["expires_at"], 70.0)

    def test_udp_mapping_accepts_its_own_opcode_and_granted_lifetime(self):
        client = self.client([(0.01, mapping_response(protocol="UDP", lifetime=30), GATEWAY)])

        mapping = client.create_port_mapping("UDP", internal_port=32849,
                                             external_port=32849, lifetime=60)

        self.assertEqual(mapping["protocol"], "UDP")
        self.assertEqual(mapping["lifetime"], 30)
        self.assertEqual(mapping["expires_at"], 40.0)
        self.assertEqual(self.sock.sent[0][1][1], 1)

    def test_unrelated_datagrams_do_not_replace_the_mapping(self):
        invalid = [
            (mapping_response(internal=12000), ("10.2.0.2", 5351)),
            (mapping_response(internal=12000), (GATEWAY[0], 12345)),
            (mapping_response(protocol="UDP", internal=12000), GATEWAY),
            (mapping_response(internal=12000, version=1), GATEWAY),
            (mapping_response(internal=12001), GATEWAY),
            (mapping_response(internal=12000)[:-1], GATEWAY),
            (mapping_response(internal=12000) + b"extra", GATEWAY),
            (b"", GATEWAY),
        ]
        events = [(0.01, data, address) for data, address in invalid]
        events.append((0.01, mapping_response(internal=12000), GATEWAY))
        client = self.client(events)

        mapping = client.create_port_mapping("TCP", internal_port=12000)

        self.assertEqual(mapping["internal_port"], 12000)
        self.assertEqual(len(self.sock.sent), 1)

    def test_gateway_error_is_reported_without_retry(self):
        client = self.client([(0.01, mapping_response(internal=12000, result=2), GATEWAY)])

        with self.assertRaises(natpmp.NatPmpError) as error:
            client.create_port_mapping("TCP", internal_port=12000)

        self.assertEqual(error.exception.error_code, 2)
        self.assertEqual(len(self.sock.sent), 1)

    def test_public_address_error_is_reported(self):
        error_response = struct.pack("!BBHI4s", 0, 128, 3, 100, b"\x00" * 4)
        client = self.client([(0.01, error_response, GATEWAY)])

        with self.assertRaises(natpmp.NatPmpError) as error:
            client.get_public_address()

        self.assertEqual(error.exception.error_code, 3)

    def test_socket_failure_is_reported(self):
        client = self.client()
        with patch.object(self.sock, "sendto", side_effect=OSError("Network unreachable")):
            with self.assertRaisesRegex(natpmp.NatPmpError, "Network unreachable"):
                client.get_public_address()

    def test_invalid_grants_are_rejected(self):
        for field in ("internal", "external", "lifetime"):
            with self.subTest(field=field):
                client = self.client([(0.01, mapping_response(**{field: 0}), GATEWAY)])
                with self.assertRaisesRegex(natpmp.NatPmpError, "invalid port mapping grant"):
                    client.create_port_mapping("TCP")

    def test_missing_replies_have_a_bounded_total_timeout(self):
        client = self.client(timeout=3.0)

        with self.assertRaisesRegex(natpmp.NatPmpError, "timed out"):
            client.create_port_mapping("TCP")

        self.assertAlmostEqual(self.clock.now, 13.0)
        self.assertEqual(len(self.sock.sent), 5)
        self.assertEqual([sent[0] for sent in self.sock.sent], [10.0, 10.25, 10.75, 11.75, 12.75])

    def test_unexpected_packet_stream_does_not_extend_deadline(self):
        client = self.client(
            timeout=0.5,
            repeated_event=(0.01, mapping_response(protocol="UDP"), GATEWAY),
        )

        with self.assertRaisesRegex(natpmp.NatPmpError, "timed out"):
            client.create_port_mapping("TCP")

        self.assertAlmostEqual(self.clock.now, 10.5)
        self.assertEqual(len(self.sock.sent), 2)

    def test_hostname_is_resolved_once_and_replies_use_resolved_address(self):
        client = self.client([(0.01, address_response(), GATEWAY)])
        with patch.object(natpmp.socket, "gethostbyname", return_value=GATEWAY[0]) as resolve:
            client = natpmp.NatPmpClient("vpn-gateway.example")
            self.addCleanup(client.close)
            self.assertEqual(client.get_public_address(), "192.0.2.1")
        resolve.assert_called_once_with("vpn-gateway.example")
        self.assertEqual(self.sock.sent[0][2], GATEWAY)

    def test_context_manager_closes_socket_on_failure(self):
        client = self.client(timeout=0.1)

        with self.assertRaises(natpmp.NatPmpError), client:
            client.get_public_address()

        self.assertTrue(self.sock.closed)
        self.assertIsNone(client.sock)


if __name__ == "__main__":
    unittest.main()
