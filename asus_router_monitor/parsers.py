"""Pure parsers for Asus router firmware responses."""

import json
import re
from typing import Any

from .exceptions import RouterResponseError, UnsupportedFirmwareError
from .models import CpuUsage, DhcpLeases, MemoryUsage, TrafficTotals, Uptime, WanStatus


def _invalid(operation: str, error: Exception) -> RouterResponseError:
    return RouterResponseError(
        f"Router returned an invalid response for {operation}"
    )


def _decode_json(text: str, operation: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError) as error:
        raise _invalid(operation, error) from error


def parse_uptime(text: str) -> Uptime:
    try:
        since = text.partition(":")[2].partition("(")[0]
        uptime = text.partition("(")[2].partition(" ")[0]
        if not since or not uptime:
            raise ValueError("uptime fields missing")
        return {"since": since, "uptime": uptime}
    except (AttributeError, TypeError, ValueError) as error:
        raise _invalid("uptime", error) from error


def parse_memory_usage(text: str) -> MemoryUsage:
    try:
        return _decode_json("{" + text[17:], "memory usage")
    except TypeError as error:
        raise _invalid("memory usage", error) from error


def parse_cpu_usage(text: str) -> CpuUsage:
    try:
        return _decode_json("{" + text[14:], "CPU usage")
    except TypeError as error:
        raise _invalid("CPU usage", error) from error


def parse_client_list(text: str) -> dict[str, Any]:
    response = _decode_json(text, "client list")
    if not isinstance(response, dict):
        error = TypeError("client list is not an object")
        raise _invalid("client list", error) from error
    return response


def parse_network_counters(text: str, operation: str) -> dict[str, str]:
    response = _decode_json(text, operation)
    try:
        counters = response["netdev"]
        tx = counters["INTERNET_tx"]
        rx = counters["INTERNET_rx"]
        if not isinstance(tx, str) or not isinstance(rx, str):
            raise TypeError("network counters are not strings")
        return {"INTERNET_tx": tx, "INTERNET_rx": rx}
    except (KeyError, TypeError) as error:
        raise _invalid(operation, error) from error


def parse_traffic_totals(text: str) -> TrafficTotals:
    counters = parse_network_counters(text, "total traffic")
    try:
        return {
            "sent": int(counters["INTERNET_tx"], base=16) * 8 / 1024 / 1024 / 2,
            "recv": int(counters["INTERNET_rx"], base=16) * 8 / 1024 / 1024 / 2,
        }
    except ValueError as error:
        raise _invalid("total traffic", error) from error


def parse_wan_status(text: str) -> WanStatus:
    status: WanStatus = {}
    try:
        for line in text.split("\n"):
            if "return" in line and "wanlink_" in line:
                key = line.partition("(")[0].partition("_")[2]
                value = line.rpartition(" ")[-1].rstrip(";").strip("'\"")
                if key:
                    status[key] = value
        return status
    except (AttributeError, TypeError) as error:
        raise _invalid("WAN status", error) from error


def parse_nvram_value(text: str, setting: str) -> str:
    response = _decode_json(text, "settings")
    try:
        value = response[setting]
        if not isinstance(value, str):
            raise TypeError("setting is not a string")
        return value
    except (KeyError, TypeError) as error:
        raise _invalid("settings", error) from error


def parse_dhcp_leases(text: str) -> DhcpLeases:
    response = _decode_json(text, "DHCP leases")
    if not isinstance(response, dict):
        error = TypeError("DHCP leases are not an object")
        raise _invalid("DHCP leases", error) from error
    return response


def parse_cpu_temperature(text: str) -> dict[str, str]:
    try:
        match = re.search(
            r'(?:curr_coreTmp|coreTmp|cpu_temperature)\s*=\s*["\']?(-?\d+(?:\.\d+)?)',
            text,
            re.IGNORECASE,
        )
    except TypeError as error:
        raise _invalid("CPU temperature", error) from error
    if not match:
        raise UnsupportedFirmwareError("Router firmware does not provide CPU temperature")
    return {"cpu_temperature": match.group(1)}
