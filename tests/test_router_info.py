import json
from unittest.mock import Mock

import pytest
import requests

from asus_router_monitor import (
    AsusRouterClient,
    AuthenticationError,
    RouterConnectionError,
    RouterHTTPError,
    RouterInfo,
    RouterMonitor,
    RouterResponseError,
    RouterTLSError,
    UnsupportedFirmwareError,
)


def authenticated_session():
    session = Mock()
    session.headers = {}
    response = Mock()
    response.json.return_value = {"asus_token": "test-token"}
    session.post.return_value = response
    return session


def test_package_exports_architecture():
    assert RouterInfo.__module__ == "asus_router_monitor.router_info"
    assert issubclass(AsusRouterClient, object)
    assert issubclass(RouterMonitor, object)


def test_client_authenticates_with_injected_session_and_context_manager():
    session = authenticated_session()
    with AsusRouterClient("https://router.local:8443", "admin", "secret", session=session) as client:
        assert client.base_url == "https://router.local:8443"
        assert client.app_url == "https://router.local:8443/appGet.cgi"
        assert session.headers["cookie"] == "asus_token=test-token"
    session.close.assert_called_once_with()
    session.post.assert_called_once_with(
        "https://router.local:8443/login.cgi",
        data="login_authorization=YWRtaW46c2VjcmV0",
        headers={"user-agent": "asusrouter-Android-DUTUtil-1.0.0.245"},
        verify=True,
        timeout=10,
    )


def test_client_maps_connection_tls_and_authentication_errors():
    session = Mock(headers={})
    session.post.side_effect = requests.Timeout("timeout")
    with pytest.raises(RouterConnectionError) as error:
        AsusRouterClient("router.local", "admin", "secret", session=session)
    assert isinstance(error.value.__cause__, requests.Timeout)

    session.post.side_effect = requests.exceptions.SSLError("certificate")
    with pytest.raises(RouterTLSError):
        AsusRouterClient("router.local", "admin", "secret", session=session)

    session.post.side_effect = None
    response = Mock()
    response.json.return_value = {}
    session.post.return_value = response
    with pytest.raises(AuthenticationError, match="rejected"):
        AsusRouterClient("router.local", "admin", "secret", session=session)


def test_client_reauthenticates_only_once_after_unauthorized_hook():
    session = authenticated_session()
    unauthorized = Mock()
    unauthorized_error = requests.HTTPError("unauthorized")
    unauthorized_error.response = Mock(status_code=401)
    unauthorized.raise_for_status.side_effect = unauthorized_error
    successful = Mock(text="uptime:now(1 secs)")
    session.post.side_effect = [session.post.return_value, unauthorized, session.post.return_value, successful]

    client = AsusRouterClient("router.local", "admin", "secret", session=session)
    assert client.hook("uptime()") == "uptime:now(1 secs)"
    assert session.post.call_count == 4


def test_client_maps_hook_http_error():
    session = authenticated_session()
    http_response = Mock()
    http_error = requests.HTTPError("500")
    http_error.response = Mock(status_code=500)
    http_response.raise_for_status.side_effect = http_error
    client = AsusRouterClient("router.local", "admin", "secret", session=session)
    session.post.return_value = http_response

    with pytest.raises(RouterHTTPError) as error:
        client.hook("uptime()")
    assert error.value.__cause__ is http_error


def monitor_with_hooks(values):
    client = Mock()
    client.hook.side_effect = values
    return RouterMonitor(client), client


def test_monitor_parses_metrics_with_injected_transport():
    monitor, _ = monitor_with_hooks([
        "uptime:Thu, 22 Jul 2021(375001 secs)",
        'x' * 17 + '"mem_total": "1", "mem_free": "0", "mem_used": "1"}',
        'x' * 14 + '"cpu1_total": "10", "cpu1_usage": "1"}',
        json.dumps({"netdev": {"INTERNET_tx": "0x40000", "INTERNET_rx": "0x80000"}}),
    ])
    assert monitor.get_uptime_secs() == 375001
    assert monitor.get_memory_usage()["mem_total"] == "1"
    assert monitor.get_cpu_usage()["cpu1_usage"] == "1"
    assert monitor.get_traffic_total() == {"sent": 1.0, "recv": 2.0}


def test_monitor_client_domain_methods_handle_partial_records():
    monitor, _ = monitor_with_hooks([json.dumps({"get_clientlist": {
        "AA:BB:CC:DD:EE:01": {"isOnline": "1", "isWL": "1", "name": "device"},
        "invalid": {"isOnline": "1"},
    }})] * 3)
    assert monitor.get_online_clients() == [{"mac": "AA:BB:CC:DD:EE:01"}]
    assert monitor.get_client_counts()["wifi_2_4_ghz"] == 1
    assert monitor.get_clients_info()[0]["name"] == "device"


def test_monitor_raises_parser_errors_and_unsupported_temperature():
    monitor, _ = monitor_with_hooks(["not json"])
    with pytest.raises(RouterResponseError):
        monitor.get_clients_fullinfo()

    client = Mock()
    client.get_cpu_temperature.return_value = "temperature unavailable"
    with pytest.raises(UnsupportedFirmwareError):
        RouterMonitor(client).get_cpu_temperature()


def test_snapshot_fetches_each_required_source_once_and_keeps_optional_temperature():
    client = Mock()
    client.hook.side_effect = [
        "uptime:now(1 secs)",
        'x' * 17 + '"mem_total": "1", "mem_free": "0", "mem_used": "1"}',
        'x' * 14 + '"cpu1_total": "1", "cpu1_usage": "0"}',
        '{"netdev": {"INTERNET_tx": "0x0", "INTERNET_rx": "0x0"}}',
        "wanlink_status() return 1;\n",
        '{"get_clientlist": {}}',
    ]
    client.get_cpu_temperature.return_value = "temperature unavailable"

    snapshot = RouterMonitor(client).get_snapshot()

    assert snapshot["cpu_temperature"] is None
    assert "timestamp" in snapshot
    assert client.hook.call_count == 6


def test_router_info_is_compatibility_facade(monkeypatch):
    client = Mock(base_url="http://router", login_url="http://router/login.cgi", app_url="http://router/appGet.cgi", cpu_temperature_url="http://router/ajax_coretmp.asp", verify=True, timeout=10)
    client.session.headers = {"cookie": "asus_token=test"}
    monkeypatch.setattr("asus_router_monitor.router_info.AsusRouterClient", Mock(return_value=client))
    router = RouterInfo("router", "admin", "secret")
    router.monitor.get_uptime = Mock(return_value={"since": "now", "uptime": "1"})
    assert router.get_uptime_secs() == 1
    router.close()
    client.close.assert_called_once_with()
