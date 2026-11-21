from unittest.mock import patch

import ShowRouterInfo


def test_parse_args_reads_router_credentials():
    args = ShowRouterInfo.parse_args(["192.168.1.1", "admin", "secret"])

    assert args.address == "192.168.1.1"
    assert args.username == "admin"
    assert args.password == "secret"
    assert args.ca_bundle is None
    assert args.insecure is False
    assert args.timeout == 10


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


def test_count_online_clients_decodes_router_json():
    online_clients = '[{"mac": "AA:BB:CC:DD:EE:01"}, {"mac": "AA:BB:CC:DD:EE:02"}]'

    assert ShowRouterInfo.count_online_clients(online_clients) == 2


def test_main_passes_arguments_to_router_info():
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        ShowRouterInfo.main(["router.local", "admin", "secret"])

    router_info.assert_called_once_with(
        "router.local", "admin", "secret", verify=True, timeout=10
    )


def test_main_disables_certificate_verification_when_requested():
    with patch("ShowRouterInfo.RouterInfo") as router_info:
        ShowRouterInfo.main(
            ["https://router.local:8443", "admin", "secret", "--insecure"]
        )

    router_info.assert_called_once_with(
        "https://router.local:8443", "admin", "secret", verify=False, timeout=10
    )
