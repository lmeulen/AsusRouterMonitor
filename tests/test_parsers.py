from pathlib import Path

import pytest

from asus_router_monitor import ClientCounts, Traffic, TrafficTotals, Uptime
from asus_router_monitor.exceptions import RouterResponseError, UnsupportedFirmwareError
from asus_router_monitor.parsers import (
    parse_client_list,
    parse_cpu_temperature,
    parse_network_counters,
    parse_nvram_value,
    parse_uptime,
    parse_wan_status,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parsers_return_native_typed_contract_shapes():
    uptime: Uptime = parse_uptime("uptime:Thu, 22 Jul 2021 14:32:38 +0200(375001 secs)")
    traffic_totals: TrafficTotals = {"sent": 1.0, "recv": 2.0}
    traffic: Traffic = {"speed": {"tx": 0.5, "rx": 1.0}, "total": traffic_totals}
    counts: ClientCounts = {
        "total": 1,
        "wired": 1,
        "wireless": 0,
        "wifi_2_4_ghz": 0,
        "wifi_5_ghz": 0,
        "other_wireless": 0,
        "unknown": 0,
        "radios": {},
    }

    assert uptime["uptime"] == "375001"
    assert traffic["total"]["recv"] == 2.0
    assert counts["total"] == 1


def test_parsers_parse_sanitized_firmware_responses():
    client_list = (FIXTURES / "sanitized_client_list.json").read_text()
    counters = (FIXTURES / "sanitized_network_counters.json").read_text()

    assert parse_client_list(client_list) == {
        "get_clientlist": {
            "AA:BB:CC:DD:EE:FF": {"name": "device", "isOnline": "1"}
        }
    }
    assert parse_network_counters(counters, "traffic") == {
        "INTERNET_tx": "0x40000", "INTERNET_rx": "0x80000"
    }
    assert parse_nvram_value('{"lan_ipaddr": "192.0.2.1"}', "lan_ipaddr") == "192.0.2.1"
    assert parse_wan_status("wanlink_status() return 1;\n") == {"status": "1"}
    assert parse_cpu_temperature('curr_coreTmp = "64.5";') == {"cpu_temperature": "64.5"}


@pytest.mark.parametrize(
    "parser,args",
    [
        (parse_uptime, ("missing uptime",)),
        (parse_client_list, ("[]",)),
        (parse_network_counters, ("{}", "traffic")),
        (parse_nvram_value, ("{}", "lan_ipaddr")),
    ],
)
def test_parsers_raise_typed_response_errors(parser, args):
    with pytest.raises(RouterResponseError):
        parser(*args)


def test_cpu_temperature_parser_rejects_unsupported_firmware():
    with pytest.raises(UnsupportedFirmwareError):
        parse_cpu_temperature("temperature unavailable")
