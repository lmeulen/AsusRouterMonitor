"""Public exception hierarchy for Asus router communication."""


class RouterError(Exception):
    """Base class for all AsusRouterMonitor errors."""


class RouterConfigurationError(RouterError, ValueError):
    """Raised when router connection settings are invalid."""


class RouterConnectionError(RouterError):
    """Raised when the router cannot be reached."""


class RouterTLSError(RouterConnectionError):
    """Raised when TLS certificate validation or negotiation fails."""


class RouterHTTPError(RouterError):
    """Raised when the router returns an unexpected HTTP error response."""


class AuthenticationError(RouterError):
    """Raised when router authentication is missing, rejected, or invalid."""


class RouterResponseError(RouterError):
    """Raised when a router response cannot be parsed or validated."""


class UnsupportedFirmwareError(RouterResponseError):
    """Raised when current router firmware does not support a requested feature."""
