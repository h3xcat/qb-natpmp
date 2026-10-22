import unittest
from unittest.mock import Mock, patch

import run
from natpmp import NatPmpError


class Clock:
    now = 0.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def mapping(now=0.0, port=32849, lifetime=60):
    return {'public_ip': '192.0.2.1', 'listen_port': port, 'external_port': port,
            'expires_at': now + lifetime, 'renew_at': now + lifetime / 2}


def grant(now=0.0, port=32849, lifetime=60):
    return {'internal_port': port, 'external_port': port, 'lifetime': lifetime,
            'granted_at': now, 'expires_at': now + lifetime}


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.client_patch = patch.object(run, 'NatPmpClient')
        self.client = self.client_patch.start().return_value.__enter__.return_value
        self.client.get_public_address.return_value = '192.0.2.1'
        self.addCleanup(self.client_patch.stop)
        self.clock_patch = patch.object(run.time, 'monotonic', return_value=110.0)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

    def test_uses_shortest_lease_and_accounts_for_elapsed_time(self):
        self.client.create_port_mapping.side_effect = [grant(100), grant(105, lifetime=20)]
        result = run.refresh_mappings('10.2.0.1')
        self.assertEqual(result['renew_at'], 115)
        self.assertEqual(result['expires_at'], 125)

    def test_mismatched_grants_are_rejected(self):
        for field in ('internal_port', 'external_port'):
            with self.subTest(field=field):
                tcp, udp = grant(100), grant(105)
                udp[field] = 40000
                self.client.create_port_mapping.side_effect = [tcp, udp]
                with self.assertRaisesRegex(NatPmpError, 'differ'):
                    run.refresh_mappings('10.2.0.1')

    def test_expired_grant_is_rejected(self):
        self.client.create_port_mapping.side_effect = [grant(40), grant(105)]
        with self.assertRaisesRegex(NatPmpError, 'expired'):
            run.refresh_mappings('10.2.0.1')


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.clock_patch = patch.object(run.time, 'monotonic', self.clock.monotonic)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.renew_patch = patch.object(run, 'refresh_mappings', side_effect=lambda _: mapping(self.clock.now))
        self.renew = self.renew_patch.start()
        self.addCleanup(self.renew_patch.stop)
        self.health_patch = patch.object(run, 'write_health')
        self.health = self.health_patch.start()
        self.addCleanup(self.health_patch.stop)
        self.clear_patch = patch.object(run, 'clear_health')
        self.clear = self.clear_patch.start()
        self.addCleanup(self.clear_patch.stop)
        self.qb = Mock()
        self.runner = run.PortForwarder('10.2.0.1', self.qb)

    def test_http_time_is_subtracted_from_renewal_delay(self):
        self.qb.update_preferences.side_effect = lambda **kwargs: self.clock.advance(4)
        self.assertEqual(self.runner.step(), 26)
        self.health.assert_called_once_with(60)

    def test_dropped_reply_recovers_before_previous_lease_expires(self):
        self.assertEqual(self.runner.step(), 30)
        self.clock.advance(30)
        def timeout(_):
            self.clock.advance(3)
            raise NatPmpError('timeout')
        self.renew.side_effect = timeout
        self.assertEqual(self.runner.step(), 5)
        self.assertEqual(self.qb.update_preferences.call_count, 1)
        self.clock.advance(5)
        self.renew.side_effect = lambda _: mapping(self.clock.now)
        self.assertEqual(self.runner.step(), 30)
        self.assertLess(self.clock.now, 60)
        self.assertEqual(self.qb.update_preferences.call_count, 2)

    def test_persistent_api_failure_does_not_delay_lease_renewal(self):
        self.qb.update_preferences.side_effect = RuntimeError('API unavailable')
        while self.clock.now < 61:
            self.clock.advance(self.runner.step())
        self.assertEqual(self.renew.call_count, 3)  # t=0,30,60
        self.health.assert_not_called()
        self.assertGreater(self.qb.update_preferences.call_count, 3)

    def test_api_recovers_without_waiting_for_next_lease_renewal(self):
        self.qb.update_preferences.side_effect = [RuntimeError('API unavailable'), None]
        self.assertEqual(self.runner.step(), 5)
        self.clock.advance(5)
        self.assertEqual(self.runner.step(), 25)
        self.renew.assert_called_once()
        self.health.assert_called_once_with(60)

    def test_new_port_invalidates_previous_health_before_api_update(self):
        self.runner.step()
        self.clock.advance(30)
        self.renew.side_effect = lambda _: mapping(self.clock.now, port=40000)
        self.clear.reset_mock()
        self.qb.update_preferences.side_effect = RuntimeError('API unavailable')
        self.runner.step()
        self.clear.assert_called_once()
        self.qb.update_preferences.assert_called_with(
            listen_port=40000, random_port=False, upnp=False, natpmp=False,
        )
        self.assertEqual(self.health.call_count, 1)

    def test_failed_mapping_does_not_update_qbittorrent_or_health(self):
        self.renew.side_effect = NatPmpError('mismatched grants')
        self.assertEqual(self.runner.step(), 5)
        self.clear.assert_called_once()
        self.qb.update_preferences.assert_not_called()
        self.health.assert_not_called()


if __name__ == '__main__':
    unittest.main()
