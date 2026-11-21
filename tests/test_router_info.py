import json
from unittest.mock import Mock, patch

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

    assert router.url == "http://192.168.1.1/appGet.cgi"
    assert router.headers["cookie"] == "asus_token=test-token"
    post.assert_called_once_with(
        url="http://192.168.1.1/login.cgi",
        data="login_authorization=YWRtaW46c2VjcmV0",
        headers={"user-agent": "asusrouter-Android-DUTUtil-1.0.0.245"},
    )


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


def test_get_client_info_returns_requested_client():
    router = RouterInfo.__new__(RouterInfo)
    client = {"name": "laptop", "isOnline": "1"}
    router.get_clients_fullinfo = Mock(
        return_value={"get_clientlist": {"AA:BB:CC:DD:EE:FF": client}}
    )

    assert router.get_client_info("AA:BB:CC:DD:EE:FF") == client
    assert router.get_client_info("missing") is None
