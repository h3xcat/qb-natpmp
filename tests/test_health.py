import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import health


class HealthTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "health.json"
        self.monotonic = patch.object(health.time, "monotonic", return_value=100.0)
        self.wall_clock = patch.object(health.time, "time", return_value=1_700_000_000.0)
        self.monotonic_mock = self.monotonic.start()
        self.wall_clock_mock = self.wall_clock.start()
        self.addCleanup(self.monotonic.stop)
        self.addCleanup(self.wall_clock.stop)

    def test_missing_marker_is_unhealthy(self):
        self.assertFalse(health.check_health(self.path))

    def test_complete_refresh_publishes_success_and_lease_timestamps(self):
        health.write_health(160.0, path=self.path)

        self.assertEqual(json.loads(self.path.read_text()), {
            "last_success": 1_700_000_000.0,
            "last_success_monotonic": 100.0,
            "expires_at": 160.0,
        })
        self.assertTrue(health.check_health(self.path))

    def test_expiry_uses_the_granted_lease_deadline(self):
        health.write_health(160.0, path=self.path)

        for now, expected in ((159.9, True), (160.0, False), (161.0, False)):
            with self.subTest(now=now):
                self.monotonic_mock.return_value = now
                self.assertEqual(health.check_health(self.path), expected)

    def test_monotonic_clock_rollback_is_unhealthy(self):
        health.write_health(160.0, path=self.path)
        self.monotonic_mock.return_value = 99.0

        self.assertFalse(health.check_health(self.path))

    def test_wall_clock_adjustments_do_not_change_lease_validity(self):
        health.write_health(160.0, path=self.path)

        for wall_time in (0.0, 2_000_000_000.0):
            with self.subTest(wall_time=wall_time):
                self.wall_clock_mock.return_value = wall_time
                self.assertTrue(health.check_health(self.path))
                self.monotonic_mock.return_value = 160.0
                self.assertFalse(health.check_health(self.path))
                self.monotonic_mock.return_value = 100.0

    def test_corrupt_or_incomplete_marker_is_unhealthy(self):
        for body in ("", "{", "null", "[]", "{}", '{"expires_at": 160}'):
            with self.subTest(body=body):
                self.path.write_text(body)
                self.assertFalse(health.check_health(self.path))

    def test_invalid_timestamp_values_are_unhealthy(self):
        state = {
            "last_success": 1_700_000_000.0,
            "last_success_monotonic": 100.0,
            "expires_at": 160.0,
        }
        for field in state:
            for invalid in (None, "100", True, -1, 10 ** 1000, float("inf"), float("nan")):
                with self.subTest(field=field, invalid=invalid):
                    self.path.write_text(json.dumps({**state, field: invalid}))
                    self.assertFalse(health.check_health(self.path))

    def test_non_utf8_marker_is_unhealthy(self):
        self.path.write_bytes(b"\xff")

        self.assertFalse(health.check_health(self.path))

    def test_invalid_or_expired_lease_is_not_published(self):
        for expires_at in (99, 100, None, "160", True, float("nan"), float("inf")):
            with self.subTest(expires_at=expires_at):
                with self.assertRaises(ValueError):
                    health.write_health(expires_at, path=self.path)
                self.assertFalse(self.path.exists())

    def test_replacement_exposes_only_complete_markers(self):
        health.write_health(160.0, path=self.path)
        old_contents = self.path.read_text()
        original_replace = health.os.replace

        def inspect_replace(source, destination):
            self.assertEqual(self.path.read_text(), old_contents)
            self.assertEqual(Path(source).parent, self.path.parent)
            self.assertEqual(json.loads(Path(source).read_text())["expires_at"], 190.0)
            original_replace(source, destination)

        with patch.object(health.os, "replace", side_effect=inspect_replace):
            health.write_health(190.0, path=self.path)

        self.assertEqual(json.loads(self.path.read_text())["expires_at"], 190.0)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_failed_replacement_keeps_old_marker_and_removes_temporary_file(self):
        health.write_health(160.0, path=self.path)
        old_contents = self.path.read_text()

        with patch.object(health.os, "replace", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                health.write_health(190.0, path=self.path)

        self.assertEqual(self.path.read_text(), old_contents)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_startup_clear_discards_previous_success(self):
        health.write_health(160.0, path=self.path)

        health.clear_health(self.path)
        health.clear_health(self.path)

        self.assertFalse(health.check_health(self.path))

    def test_cli_exit_status_matches_health(self):
        for healthy, expected in ((True, 0), (False, 1)):
            with self.subTest(healthy=healthy):
                with patch.object(health, "check_health", return_value=healthy), \
                        patch("sys.stderr"):
                    self.assertEqual(health.main(), expected)


if __name__ == "__main__":
    unittest.main()
