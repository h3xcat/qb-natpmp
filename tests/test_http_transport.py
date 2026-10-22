import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib3

from qbittorrent import QbittorrentClient


class HttpTransportTests(unittest.TestCase):
    def test_stalled_login_and_update_fail_without_retrying(self):
        for operation in ("login", "update"):
            with self.subTest(operation=operation):
                requests = []
                release = threading.Event()

                class Handler(BaseHTTPRequestHandler):
                    def do_POST(self):
                        self.rfile.read(int(self.headers.get("Content-Length", 0)))
                        requests.append(self.path)
                        release.wait(2)

                    def log_message(self, *args):
                        pass

                server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.01},
                    daemon=True,
                )
                thread.start()
                client = QbittorrentClient(
                    f"http://127.0.0.1:{server.server_port}", "admin", "admin",
                    connect_timeout=0.2, read_timeout=0.1,
                )
                try:
                    if operation == "update":
                        client.session_cookie = "SID=existing"
                    started = time.monotonic()
                    with self.assertRaises(urllib3.exceptions.ReadTimeoutError):
                        if operation == "login":
                            client.login()
                        else:
                            client.update_preferences(listen_port=32849)
                    self.assertLess(time.monotonic() - started, 1.5)
                    self.assertEqual(len(requests), 1)
                finally:
                    release.set()
                    client.close()
                    server.shutdown()
                    server.server_close()
                    thread.join(1)

    def test_login_redirect_is_rejected_without_following_it(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/unexpected")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        thread.start()
        client = QbittorrentClient(
            f"http://127.0.0.1:{server.server_port}", "admin", "admin"
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "qBittorrent login failed: HTTP 302"):
                client.login()
            self.assertEqual(requests, ["/api/v2/auth/login"])
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            thread.join(1)


if __name__ == "__main__":
    unittest.main()
