import json
from unittest.mock import patch

import pytest

import ShowRouterInfo
from asus_router_monitor import (
    AuthenticationError,
    RouterConfigurationError,
    RouterConnectionError,
    RouterResponseError,
    UnsupportedFirmwareError,
)


def test_parse_args_reads_router_credentials():
    args = ShowRouterInfo.parse_args(["192.168.1.1", "admin", "secret"])

    assert args.address == "192.168.1.1"
    assert args.username == "admin"
    assert args.password == "secret"
    assert args.ca_bundle is None
    assert args.insecure is False
    assert args.timeout == 10
    assert args.format == "text"


def test_parse_args_reads_https_options():
    args = ShowRouterInfo.parse_args(
        [
            "https://router.local:8443",
            "admin",
            "secret",
            "--ca-bundle",
            "/tmp/router-ca.pem",
            "--timeout",
            "3",
        ]
    )

    assert args.address == "https://router.local:8443"
    assert args.ca_bundle == "/tmp/router-ca.pem"
    assert args.timeout == 3


def test_count_clients_ignores_client_list_metadata():
    full_info = {
        "get_clientlist": {
            "AA:BB:CC:DD:EE:01": {"isOnline": "1"},
            "AA:BB:CC:DD:EE:02": {"isOnline": "0"},
            "maclist": ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
            "ClientAPILevel": "2",
        }
    }

    assert ShowRouterInfo.count_clients(full_info) == 2


def test_count_clients_handles_missing_client_list():
    assert ShowRouterInfo.count_clients({}) == 0


def test_count_online_clients_accepts_native_list():
    online_clients = [{"mac": "AA:BB:CC:DD:EE:01"}, {"mac": "AA:BB:CC:DD:EE:02"}]

    assert ShowRouterInfo.count_online_clients(online_clients) == 2


def test_main_passes_arguments_to_router_info():
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        ShowRouterInfo.main(["router.local", "admin", "secret"])

    router_info.assert_called_once_with("router.local", "admin", "secret", verify=True, timeout=10)


def test_main_outputs_stable_json_status_document(capsys):
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        router = router_info.return_value
        router.get_uptime.return_value = {"since": "now", "uptime": "10"}
        router.get_uptime_secs.return_value = 10
        router.get_memory_usage.return_value = {"mem_total": "1"}
        router.get_cpu_usage.return_value = {"cpu1_usage": "2"}
        router.get_cpu_temperature.return_value = {"cpu_temperature": "50"}
        router.get_traffic_total.return_value = {"sent": 1.0, "recv": 2.0}
        router.get_status_wan.return_value = {"status": "1"}
        router.get_settings.return_value = {"time_zone": "UTC"}
        router.get_lan_ip_address.return_value = "192.0.2.1"
        router.get_lan_netmask.return_value = "255.255.255.0"
        router.get_lan_gateway.return_value = "192.0.2.254"
        router.get_client_counts.return_value = {"total": 0, "radios": {}}
        router.get_dhcp_list.return_value = []

        assert ShowRouterInfo.main(["router.local", "admin", "secret", "--format", "json"]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    status = json.loads(captured.out)
    assert status == {
        "client_counts": {"radios": {}, "total": 0},
        "cpu": {"cpu1_usage": "2"},
        "cpu_temperature": {"cpu_temperature": "50"},
        "dhcp_lease_count": 0,
        "lan": {"gateway": "192.0.2.254", "ip_address": "192.0.2.1", "netmask": "255.255.255.0"},
        "memory": {"mem_total": "1"},
        "settings": {"time_zone": "UTC"},
        "traffic_total": {"recv": 2.0, "sent": 1.0},
        "uptime": {"since": "now", "uptime": "10"},
        "uptime_seconds": 10,
        "wan": {"online": True, "status": "1"},
    }


def test_main_json_uses_null_for_unsupported_cpu_temperature(capsys):
    with patch("ShowRouterInfo._collect_status", return_value={"cpu_temperature": None}):
        ShowRouterInfo._show_status(
            ShowRouterInfo.parse_args(["router.local", "admin", "secret", "--format", "json"])
        )

    assert json.loads(capsys.readouterr().out) == {"cpu_temperature": None}


def test_main_shows_connected_client_counts(capsys):
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        router_info.return_value.get_client_counts.return_value = {
            "total": 8,
            "wired": 2,
            "wireless": 5,
            "wifi_2_4_ghz": 3,
            "wifi_5_ghz": 2,
            "other_wireless": 0,
            "unknown": 1,
            "radios": {"1": 3, "2": 2},
        }
        ShowRouterInfo.main(["router.local", "admin", "secret"])

    output = capsys.readouterr().out
    assert "Connected clients" in output
    assert "Total:" in output and "8" in output
    assert "Wired:" in output and "2" in output
    assert "Wireless:" in output and "5" in output
    assert "Wi-Fi 2.4 GHz:" in output and "3" in output
    assert "Wi-Fi 5 GHz:" in output
    assert "Unknown connection:" in output and "1" in output


def test_text_output_has_human_labels_and_units(capsys):
    status = {
        "uptime": {"since": "2024-01-01", "uptime": "60"},
        "uptime_seconds": 60,
        "memory": {"mem_total": "1024", "mem_used": "512", "mem_free": "512"},
        "cpu": {"cpu1_usage": "17"},
        "cpu_temperature": {"cpu_temperature": "42.5"},
        "traffic_total": {"sent": 1.5, "recv": 2.5},
        "wan": {"status": "1", "online": True},
        "settings": {"time_zone": "UTC"},
        "lan": {"ip_address": "192.0.2.1", "netmask": "255.255.255.0", "gateway": "192.0.2.254"},
        "client_counts": {
            "total": 1,
            "wired": 1,
            "wireless": 0,
            "wifi_2_4_ghz": 0,
            "wifi_5_ghz": 0,
            "other_wireless": 0,
            "unknown": 0,
            "radios": {},
        },
        "dhcp_lease_count": 1,
    }
    ShowRouterInfo._show_text_status(status)

    output = capsys.readouterr().out
    assert "Router status" in output
    assert "Uptime:" in output and "60 seconds" in output
    assert "Memory total:" in output and "1024 KiB" in output
    assert "CPU 1 usage:" in output and "17%" in output
    assert "CPU temperature:" in output and "42.5 °C" in output
    assert "WAN connected:" in output and "yes" in output
    assert "Traffic sent since boot:" in output and "1.5 Mbit" in output
    assert "LAN IP address:" in output


def test_main_shows_unavailable_for_unsupported_cpu_temperature(capsys):
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        router_info.return_value.get_cpu_temperature.side_effect = UnsupportedFirmwareError(
            "Router firmware does not provide CPU temperature"
        )
        ShowRouterInfo.main(["router.local", "admin", "secret"])

    output = capsys.readouterr().out
    assert "CPU temperature:" in output
    assert "unavailable" in output


def test_main_returns_error_for_cpu_temperature_connection_error(capsys):
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        router_info.return_value.get_cpu_temperature.side_effect = RouterConnectionError(
            "Unable to request CPU temperature"
        )
        assert ShowRouterInfo.main(["router.local", "admin", "secret"]) == 1

    assert "Error: Unable to request CPU temperature" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (AuthenticationError("Router rejected username or password"), 1),
        (RouterConnectionError("Unable to authenticate with router"), 1),
        (RouterConfigurationError("Router address must use HTTP or HTTPS"), 2),
        (RouterResponseError("Router returned an invalid response"), 3),
    ],
)
def test_main_returns_documented_error_codes(error, expected_code, capsys):
    with patch("ShowRouterInfo._show_status", side_effect=error):
        assert ShowRouterInfo.main(["router.local", "admin", "secret"]) == expected_code

    captured = capsys.readouterr()
    assert str(error) in captured.err
    assert captured.out == ""


def test_main_returns_zero_on_success():
    with patch("ShowRouterInfo._show_status"):
        assert ShowRouterInfo.main(["router.local", "admin", "secret"]) == 0


def test_main_debug_reraises_router_error():
    error = RouterConnectionError("Unable to authenticate with router")

    with patch("ShowRouterInfo._show_status", side_effect=error):
        with pytest.raises(RouterConnectionError) as raised:
            ShowRouterInfo.main(["router.local", "admin", "secret", "--debug"])

    assert raised.value is error


def test_main_disables_certificate_verification_when_requested():
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        ShowRouterInfo.main(["https://router.local:8443", "admin", "secret", "--insecure"])

    router_info.assert_called_once_with(
        "https://router.local:8443", "admin", "secret", verify=False, timeout=10
    )
