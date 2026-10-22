import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

import urllib3

import run


def response(status, body=b"", cookie=None):
    headers = {"Set-Cookie": cookie} if cookie else {}
    return urllib3.HTTPResponse(status=status, body=body, headers=headers)


class QbittorrentTests(unittest.TestCase):
    def setUp(self):
        self.http = Mock()
        self.http_patch = patch.object(run, "_http", self.http)
        self.cookie_patch = patch.object(run, "_session_cookie", None)
        self.http_patch.start()
        self.cookie_patch.start()
        self.addCleanup(self.http_patch.stop)
        self.addCleanup(self.cookie_patch.stop)

    def test_legacy_and_no_content_logins_forward_session_cookie(self):
        for status, body in ((200, b"Ok."), (204, b"")):
            with self.subTest(status=status):
                run._session_cookie = None
                self.http.reset_mock()
                self.http.request.side_effect = [
                    response(status, body, "SID=test-session; HttpOnly; path=/"),
                    response(200),
                ]

                run.update_qbittorrent(listen_port=32849)

                login, update = self.http.request.call_args_list
                self.assertEqual(login.args, ("POST", f"{run.QB_URL}/api/v2/auth/login"))
                self.assertEqual(update.args, ("POST", f"{run.QB_URL}/api/v2/app/setPreferences"))
                self.assertIn("SID=test-session", update.kwargs["headers"]["Cookie"])
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
                run._session_cookie = None
                self.http.reset_mock()
                self.http.request.return_value = response(status, body)

                with self.assertRaisesRegex(Exception, error):
                    run.update_qbittorrent(listen_port=32849)

                self.http.request.assert_called_once()
                self.assertIsNone(run._session_cookie)

    def test_no_cookie_login_preserves_authentication_bypass(self):
        self.http.request.side_effect = [response(204), response(200)]

        run.update_qbittorrent(listen_port=32849)

        self.assertNotIn("Cookie", self.http.request.call_args.kwargs["headers"])
        self.assertEqual(run._session_cookie, "logged_in")

    def test_login_encodes_reserved_characters_in_credentials(self):
        self.http.request.return_value = response(204, cookie="SID=test-session")
        with patch.object(run, "QB_USER", "user+name"), patch.object(run, "QB_PASS", "a&b=c%+"):
            run._login_qbittorrent()

        self.assertEqual(
            parse_qs(self.http.request.call_args.kwargs["body"]),
            {"username": ["user+name"], "password": ["a&b=c%+"]},
        )

    def test_no_content_preference_update_succeeds(self):
        run._session_cookie = "SID=test-session"
        self.http.request.return_value = response(204)

        run.update_qbittorrent(listen_port=32849)

        self.http.request.assert_called_once()

    def test_expired_session_reauthenticates_with_no_content_login(self):
        run._session_cookie = "SID=expired"
        self.http.request.side_effect = [
            response(403),
            response(204, cookie="SID=renewed"),
            response(204),
        ]

        run.update_qbittorrent(listen_port=32849)

        self.assertEqual(self.http.request.call_count, 3)
        self.assertEqual(self.http.request.call_args.kwargs["headers"]["Cookie"], "SID=renewed")

    def test_failed_preference_update_is_rejected(self):
        run._session_cookie = "SID=test-session"
        self.http.request.return_value = response(500)

        with self.assertRaisesRegex(Exception, "Failed to update qBittorrent: HTTP 500"):
            run.update_qbittorrent(listen_port=32849)

    def test_port_refresh_completes_after_no_content_login(self):
        self.http.request.side_effect = [
            response(204, cookie="SID=test-session"),
            response(200),
        ]
        mapping = {"internal_port": 32849, "external_port": 32849, "lifetime": 60}
        with patch.object(run, "NatPmpClient") as client:
            client.return_value.get_public_address.return_value = "192.0.2.1"
            client.return_value.create_port_mapping.return_value = mapping

            result = run.refresh_qb_port()

        self.assertEqual(result["tcp_mapping"]["lifetime"], 60)
        self.assertEqual(result["public_ip"], "192.0.2.1")
        client.return_value.close.assert_called_once()
        settings = json.loads(parse_qs(self.http.request.call_args.kwargs["body"])["json"][0])
        self.assertEqual(
            settings,
            {"listen_port": 32849, "random_port": False, "upnp": False, "natpmp": False},
        )


if __name__ == "__main__":
    unittest.main()
