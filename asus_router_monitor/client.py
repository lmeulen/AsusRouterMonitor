"""HTTP transport and authentication for Asus routers."""

import base64
from typing import Any
from urllib.parse import urlsplit

import requests

from .exceptions import (
    AuthenticationError,
    RouterConfigurationError,
    RouterConnectionError,
    RouterHTTPError,
    RouterTLSError,
)

_USER_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"


class AsusRouterClient:
    """Authenticated, reusable router HTTP transport.

    A client owns its requests session. Use it as a context manager or call
    :meth:`close` when no longer needed.
    """

    def __init__(
        self,
        address: str,
        username: str,
        password: str,
        verify: bool | str = True,
        timeout: float = 10,
        session: requests.Session | None = None,
    ):
        self.base_url = self.normalize_base_url(address)
        self.login_url = self.base_url + "/login.cgi"
        self.app_url = self.base_url + "/appGet.cgi"
        self.cpu_temperature_url = self.base_url + "/ajax_coretmp.asp"
        self.verify = verify
        self.timeout = timeout
        self._username = username
        self._password = password
        self.session = session or requests.Session()
        self._authenticate()

    @staticmethod
    def normalize_base_url(address: str) -> str:
        address = address.strip().rstrip("/")
        if "://" not in address:
            address = "http://" + address
        parsed = urlsplit(address)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise RouterConfigurationError("Router address must use HTTP or HTTPS")
        if parsed.path or parsed.query or parsed.fragment:
            raise RouterConfigurationError(
                "Router address must not contain a path, query, or fragment"
            )
        return address

    def _request_error(self, action: str, error: requests.RequestException):
        if isinstance(error, requests.exceptions.SSLError):
            return RouterTLSError(f"Unable to {action} because TLS validation failed")
        if isinstance(error, requests.exceptions.HTTPError):
            return RouterHTTPError(f"Router returned an HTTP error while trying to {action}")
        return RouterConnectionError(f"Unable to {action}")

    def _authenticate(self) -> None:
        token = base64.b64encode(f"{self._username}:{self._password}".encode("ascii")).decode(
            "ascii"
        )
        try:
            response = self.session.post(
                self.login_url,
                data=f"login_authorization={token}",
                headers={"user-agent": _USER_AGENT},
                verify=self.verify,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            raise self._request_error("authenticate with router", error) from error
        try:
            result = response.json()
        except ValueError as error:
            raise AuthenticationError("Router returned an invalid login response") from error
        response_token = result.get("asus_token") if isinstance(result, dict) else None
        if not isinstance(response_token, str) or not response_token:
            raise AuthenticationError("Router rejected username or password")
        self.session.headers.update(
            {"user-agent": _USER_AGENT, "cookie": f"asus_token={response_token}"}
        )

    def _post_with_retry(self, url: str, data: str, action: str) -> str:
        for attempt in range(2):
            try:
                response = self.session.post(
                    url, data=data, verify=self.verify, timeout=self.timeout
                )
                response.raise_for_status()
                return response.text
            except requests.exceptions.HTTPError as error:
                response_status = getattr(error.response, "status_code", None)
                if attempt == 0 and response_status in (401, 403):
                    self._authenticate()
                    continue
                raise self._request_error(action, error) from error
            except requests.RequestException as error:
                raise self._request_error(action, error) from error
        raise AuthenticationError("Router authentication expired")

    def hook(self, command: str) -> str:
        """Run one appGet hook, reauthenticating once for 401/403 responses."""
        return self._post_with_retry(self.app_url, f"hook={command}", "request router data")

    def get_cpu_temperature(self) -> str:
        """Fetch raw CPU-temperature endpoint response."""
        try:
            response = self.session.get(
                self.cpu_temperature_url, verify=self.verify, timeout=self.timeout
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as error:
            raise self._request_error("request CPU temperature", error) from error

    def close(self) -> None:
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
