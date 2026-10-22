"""Small, bounded HTTP client for the qBittorrent preferences API."""

import json
import logging
from http.cookies import SimpleCookie
from urllib.parse import urlencode

import urllib3


logger = logging.getLogger(__name__)


class QbittorrentClient:
    def __init__(
        self,
        url,
        username,
        password,
        *,
        connect_timeout=2.0,
        read_timeout=3.0,
    ):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.session_cookie = None
        self.http = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=connect_timeout, read=read_timeout)
        )

    def _post(self, path, body, *, authenticated=False):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if authenticated and self.session_cookie not in (None, "logged_in"):
            headers["Cookie"] = self.session_cookie
        # The refresh loop owns retries. Redirects must not hide a rejected API
        # request or forward credentials to another endpoint.
        return self.http.request(
            "POST",
            f"{self.url}/api/v2/{path}",
            body=body,
            headers=headers,
            retries=False,
            redirect=False,
        )

    def login(self):
        """Authenticate, retaining cookie name/value pairs without attributes."""
        self.session_cookie = None
        response = self._post(
            "auth/login",
            urlencode({"username": self.username, "password": self.password}),
        )
        if response.status not in (200, 204):
            raise RuntimeError(f"qBittorrent login failed: HTTP {response.status}")
        # Older versions return 200/Ok.; newer versions return an empty 204.
        if response.status == 200 and (response.data or b"").strip() != b"Ok.":
            raise RuntimeError("qBittorrent login failed: Invalid credentials")

        cookies = SimpleCookie()
        for value in response.headers.getlist("Set-Cookie"):
            cookies.load(value)
        if cookies:
            # qBittorrent 5.2 uses QBT_SID_<WebUI port>; older versions use
            # SID or a configured name. Preserve the names returned by the
            # server instead of assuming the API URL's port or a fixed name.
            self.session_cookie = "; ".join(
                cookie.OutputString(attrs=[]) for cookie in cookies.values()
            )
            logger.info("Successfully logged into qBittorrent")
            return

        # Authentication bypass can legitimately return success without cookies.
        self.session_cookie = "logged_in"
        logger.info("qBittorrent login successful (no cookie)")

    def update_preferences(self, **kwargs):
        """Update preferences, reauthenticating once if the session expired."""
        if self.session_cookie is None:
            self.login()
        body = urlencode({"json": json.dumps(kwargs)})
        response = self._post("app/setPreferences", body, authenticated=True)
        if response.status == 403:
            logger.info("Got 403, attempting to re-login...")
            self.login()
            response = self._post("app/setPreferences", body, authenticated=True)
        if response.status not in (200, 204):
            raise RuntimeError(f"Failed to update qBittorrent: HTTP {response.status}")
        logger.info("Updated qBittorrent settings: %s", kwargs)

    def close(self):
        self.http.clear()
