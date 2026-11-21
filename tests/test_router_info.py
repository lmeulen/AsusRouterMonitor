import json
from unittest.mock import Mock, patch

import requests

from RouterInfo import RouterInfo


def router_with_response(response):
    router = RouterInfo.__new__(RouterInfo)
    router._RouterInfo__get = Mock(return_value=response)
    return router


def test_authentication_stores_token_and_app_url():
    response = Mock()
    response.json.return_value = {"asus_token": "test-token"}

    with patch("RouterInfo.requests.post", return_value=response) as post:
        router = RouterInfo("192.168.1.1", "admin", "secret")

    assert router.base_url == "http://192.168.1.1"
    assert router.login_url == "http://192.168.1.1/login.cgi"
    assert router.url == "http://192.168.1.1/appGet.cgi"
    assert router.cpu_temperature_url == "http://192.168.1.1/ajax_coretmp.asp"
    assert router.headers["cookie"] == "asus_token=test-token"
    post.assert_called_once_with(
        url="http://192.168.1.1/login.cgi",
        data="login_authorization=YWRtaW46c2VjcmV0",
        headers={"user-agent": "asusrouter-Android-DUTUtil-1.0.0.245"},
        verify=True,
        timeout=10,
    )
    response.raise_for_status.assert_called_once_with()


def test_https_custom_port_and_ca_bundle_are_used_for_login():
    response = Mock()
    response.json.return_value = {"asus_token": "test-token"}

    with patch("RouterInfo.requests.post", return_value=response) as post:
        router = RouterInfo(
            "https://router.local:8443/",
            "admin",
            "secret",
            verify="/tmp/router-ca.pem",
            timeout=3,
        )

    assert router.base_url == "https://router.local:8443"
    assert router.url == "https://router.local:8443/appGet.cgi"
    assert router.cpu_temperature_url == "https://router.local:8443/ajax_coretmp.asp"
    assert post.call_args.kwargs["url"] == "https://router.local:8443/login.cgi"
    assert post.call_args.kwargs["verify"] == "/tmp/router-ca.pem"
    assert post.call_args.kwargs["timeout"] == 3


def test_router_address_rejects_paths_and_unsupported_schemes():
    for address in ("ftp://router.local", "https://router.local/admin"):
        try:
            RouterInfo(address, "admin", "secret")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid router address was accepted")


def test_get_uptime_parses_router_response():
    router = router_with_response(
        "uptime:Thu, 22 Jul 2021 14:32:38 +0200(375001 secs since boot)"
    )

    assert router.get_uptime() == {
        "since": "Thu, 22 Jul 2021 14:32:38 +0200",
        "uptime": "375001",
    }
    assert router.get_uptime_secs() == 375001


def test_get_traffic_total_converts_hex_bytes_to_megabits():
    router = router_with_response(
        json.dumps({"netdev": {"INTERNET_tx": "0x40000", "INTERNET_rx": "0x80000"}})
    )

    assert router.get_traffic_total() == {"sent": "1.0", "recv": "2.0"}


def test_get_clients_info_returns_only_online_mac_entries():
    router = RouterInfo.__new__(RouterInfo)
    router.get_clients_fullinfo = Mock(
        return_value={
            "get_clientlist": {
                "AA:BB:CC:DD:EE:01": {
                    "name": "phone",
                    "nickName": "Phone",
                    "ip": "192.168.1.10",
                    "mac": "AA:BB:CC:DD:EE:01",
                    "isOnline": "1",
                    "curTx": "1",
                    "curRx": "2",
                    "totalTx": "3",
                    "totalRx": "4",
                },
                "AA:BB:CC:DD:EE:02": {"isOnline": "0"},
                "maclist": ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
            }
        }
    )

    assert router.get_clients_info() == [
        {
            "name": "phone",
            "nickName": "Phone",
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:01",
            "isOnline": "1",
            "curTx": "1",
            "curRx": "2",
            "totalTx": "3",
            "totalRx": "4",
        }
    ]


def test_client_methods_handle_missing_clientlist():
    for response in ({}, {"get_clientlist": None}, None, []):
        router = RouterInfo.__new__(RouterInfo)
        router.get_clients_fullinfo = Mock(return_value=response)

        assert router.get_online_clients() == "[]"
        assert router.get_clients_info() == []
        assert router.get_client_info("AA:BB:CC:DD:EE:FF") is None


def test_get_client_counts_groups_online_clients_by_connection():
    router = RouterInfo.__new__(RouterInfo)
    router.get_clients_fullinfo = Mock(
        return_value={
            "get_clientlist": {
                "AA:BB:CC:DD:EE:01": {"isOnline": "1", "isWL": "0"},
                "AA:BB:CC:DD:EE:02": {"isOnline": "1", "isWL": "1"},
                "AA:BB:CC:DD:EE:03": {"isOnline": "1", "isWL": "2"},
                "AA:BB:CC:DD:EE:04": {"isOnline": "1", "isWL": "3"},
                "AA:BB:CC:DD:EE:05": {"isOnline": "1"},
                "AA:BB:CC:DD:EE:06": {"isOnline": "0", "isWL": "1"},
                "maclist": [],
                "ClientAPILevel": "2",
            }
        }
    )

    counts = router.get_client_counts()

    assert counts == {
        "total": 5,
        "wired": 1,
        "wireless": 3,
        "wifi_2_4_ghz": 1,
        "wifi_5_ghz": 1,
        "other_wireless": 1,
        "unknown": 1,
        "radios": {"1": 1, "2": 1, "3": 1},
    }
    assert counts["total"] == (
        counts["wired"] + counts["wireless"] + counts["unknown"]
    )


def test_get_client_counts_handles_missing_clientlist():
    router = RouterInfo.__new__(RouterInfo)
    router.get_clients_fullinfo = Mock(return_value={})

    assert router.get_client_counts() == {
        "total": 0,
        "wired": 0,
        "wireless": 0,
        "wifi_2_4_ghz": 0,
        "wifi_5_ghz": 0,
        "other_wireless": 0,
        "unknown": 0,
        "radios": {},
    }


def test_client_methods_handle_partial_client_records():
    router = RouterInfo.__new__(RouterInfo)
    router.get_clients_fullinfo = Mock(
        return_value={
            "get_clientlist": {
                "AA:BB:CC:DD:EE:01": {"name": "phone", "isOnline": "1"},
                "maclist": ["AA:BB:CC:DD:EE:01"],
                "ClientAPILevel": "2",
            }
        }
    )

    assert json.loads(router.get_online_clients()) == [
        {"mac": "AA:BB:CC:DD:EE:01"}
    ]
    assert router.get_clients_info() == [
        {
            "name": "phone",
            "nickName": None,
            "ip": None,
            "mac": None,
            "isOnline": "1",
            "curTx": None,
            "curRx": None,
            "totalTx": None,
            "totalRx": None,
        }
    ]


def test_get_cpu_temperature_parses_firmware_response_without_changing_app_url():
    router = RouterInfo.__new__(RouterInfo)
    router.url = "http://192.168.1.1/appGet.cgi"
    router.cpu_temperature_url = "http://192.168.1.1/ajax_coretmp.asp"
    router.headers = {"cookie": "asus_token=test-token"}
    router.verify = True
    router.timeout = 10
    response = Mock(text='curr_coreTmp = "64.568";')

    with patch("RouterInfo.requests.get", return_value=response) as get:
        result = router.get_cpu_temperature()

    assert result == {"cpu_temperature": "64.568"}
    assert router.url == "http://192.168.1.1/appGet.cgi"
    get.assert_called_once_with(
        url="http://192.168.1.1/ajax_coretmp.asp",
        headers=router.headers,
        verify=True,
        timeout=10,
    )
    response.raise_for_status.assert_called_once_with()


def test_get_cpu_temperature_returns_none_for_unsupported_response():
    router = RouterInfo.__new__(RouterInfo)
    router.cpu_temperature_url = "http://192.168.1.1/ajax_coretmp.asp"
    router.headers = {"cookie": "asus_token=test-token"}
    router.verify = True
    router.timeout = 10
    response = Mock(text="temperature unavailable")

    with patch("RouterInfo.requests.get", return_value=response):
        assert router.get_cpu_temperature() is None


def test_get_cpu_temperature_returns_none_on_request_error():
    router = RouterInfo.__new__(RouterInfo)
    router.cpu_temperature_url = "http://192.168.1.1/ajax_coretmp.asp"
    router.headers = {"cookie": "asus_token=test-token"}
    router.verify = True
    router.timeout = 10

    with patch(
        "RouterInfo.requests.get", side_effect=requests.RequestException("connection failed")
    ):
        assert router.get_cpu_temperature() is None


def test_get_client_info_returns_requested_client():
    router = RouterInfo.__new__(RouterInfo)
    client = {"name": "laptop", "isOnline": "1"}
    router.get_clients_fullinfo = Mock(
        return_value={"get_clientlist": {"AA:BB:CC:DD:EE:FF": client}}
    )

    assert router.get_client_info("AA:BB:CC:DD:EE:FF") == client
    assert router.get_client_info("missing") is None
