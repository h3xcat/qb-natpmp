import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

import urllib3

from qbittorrent import QbittorrentClient


def response(status, body=b"", cookie=None):
    headers = {"Set-Cookie": cookie} if cookie else {}
    return urllib3.HTTPResponse(status=status, body=body, headers=headers)


class QbittorrentTests(unittest.TestCase):
    def setUp(self):
        self.client = QbittorrentClient("http://127.0.0.1:9080", "admin", "admin")
        self.http = Mock()
        self.http_patch = patch.object(self.client, "http", self.http)
        self.http_patch.start()
        self.addCleanup(self.http_patch.stop)
        self.addCleanup(self.client.close)

    def test_legacy_and_no_content_logins_forward_session_cookie(self):
        for status, body in ((200, b"Ok."), (204, b"")):
            with self.subTest(status=status):
                self.client.session_cookie = None
                self.http.reset_mock()
                self.http.request.side_effect = [
                    response(status, body, "SID=test-session; HttpOnly; path=/"),
                    response(200),
                ]

                self.client.update_preferences(listen_port=32849)

                login, update = self.http.request.call_args_list
                self.assertEqual(login.args, ("POST", f"{self.client.url}/api/v2/auth/login"))
                self.assertEqual(update.args, ("POST", f"{self.client.url}/api/v2/app/setPreferences"))
                self.assertEqual(update.kwargs["headers"]["Cookie"], "SID=test-session")
                for request in (login, update):
                    self.assertFalse(request.kwargs["retries"])
                    self.assertFalse(request.kwargs["redirect"])
                settings = json.loads(parse_qs(update.kwargs["body"])["json"][0])
                self.assertEqual(settings, {"listen_port": 32849})

    def test_failed_login_never_updates_preferences(self):
        for status, body, error in (
            (200, b"Fails.", "Invalid credentials"),
            (200, b"", "Invalid credentials"),
            (403, b"Forbidden", "HTTP 403"),
            (500, b"Server error", "HTTP 500"),
        ):
            with self.subTest(status=status, body=body):
                self.client.session_cookie = None
                self.http.reset_mock()
                self.http.request.return_value = response(status, body)

                with self.assertRaisesRegex(Exception, error):
                    self.client.update_preferences(listen_port=32849)

                self.http.request.assert_called_once()
                self.assertIsNone(self.client.session_cookie)

    def test_no_cookie_login_preserves_authentication_bypass(self):
        self.http.request.side_effect = [response(204), response(200)]

        self.client.update_preferences(listen_port=32849)

        self.assertNotIn("Cookie", self.http.request.call_args.kwargs["headers"])
        self.assertEqual(self.client.session_cookie, "logged_in")

    def test_login_encodes_reserved_characters_in_credentials(self):
        self.http.request.return_value = response(204, cookie="SID=test-session")
        self.client.username = "user+name"
        self.client.password = "a&b=c%+"
        self.client.login()

        self.assertEqual(
            parse_qs(self.http.request.call_args.kwargs["body"]),
            {"username": ["user+name"], "password": ["a&b=c%+"]},
        )

    def test_no_content_preference_update_succeeds(self):
        self.client.session_cookie = "SID=test-session"
        self.http.request.return_value = response(204)

        self.client.update_preferences(listen_port=32849)

        self.http.request.assert_called_once()

    def test_expired_session_reauthenticates_with_no_content_login(self):
        self.client.session_cookie = "SID=expired"
        self.http.request.side_effect = [
            response(403),
            response(204, cookie="SID=renewed"),
            response(204),
        ]

        self.client.update_preferences(listen_port=32849)

        self.assertEqual(self.http.request.call_count, 3)
        self.assertEqual(self.http.request.call_args.kwargs["headers"]["Cookie"], "SID=renewed")

    def test_failed_preference_update_is_rejected(self):
        self.client.session_cookie = "SID=test-session"
        self.http.request.return_value = response(500)

        with self.assertRaisesRegex(Exception, "Failed to update qBittorrent: HTTP 500"):
            self.client.update_preferences(listen_port=32849)

    def test_only_sid_is_forwarded_from_multiple_cookies(self):
        headers = urllib3.HTTPHeaderDict()
        headers.add("Set-Cookie", "theme=dark; path=/")
        headers.add("Set-Cookie", "SID=test-session; HttpOnly; SameSite=Strict; path=/")
        self.http.request.side_effect = [
            urllib3.HTTPResponse(status=204, headers=headers), response(204)
        ]

        self.client.update_preferences(listen_port=32849)

        self.assertEqual(self.http.request.call_args.kwargs["headers"]["Cookie"], "SID=test-session")

    def test_reauthentication_is_attempted_only_once(self):
        self.client.session_cookie = "SID=expired"
        self.http.request.side_effect = [
            response(403), response(204, cookie="SID=renewed"), response(403)
        ]

        with self.assertRaisesRegex(RuntimeError, "Failed to update qBittorrent: HTTP 403"):
            self.client.update_preferences(listen_port=32849)

        self.assertEqual(self.http.request.call_count, 3)


if __name__ == "__main__":
    unittest.main()
