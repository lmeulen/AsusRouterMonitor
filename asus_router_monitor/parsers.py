"""Pure parsers for Asus router firmware responses."""

import json
import re
from typing import Any, cast

from .exceptions import RouterResponseError, UnsupportedFirmwareError
from .models import CpuUsage, DhcpLeases, MemoryUsage, TrafficTotals, Uptime, WanStatus


def _invalid(operation: str, error: Exception) -> RouterResponseError:
    return RouterResponseError(f"Router returned an invalid response for {operation}")


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
        usage = _decode_json("{" + text[17:], "memory usage")
        if not isinstance(usage, dict):
            raise TypeError("memory usage is not an object")
        return cast(MemoryUsage, usage)
    except TypeError as error:
        raise _invalid("memory usage", error) from error


def parse_cpu_usage(text: str) -> CpuUsage:
    """Parse firmware CPU jiffies and normalize each usage field to percent."""
    try:
        usage = _decode_json("{" + text[14:], "CPU usage")
        if not isinstance(usage, dict):
            raise TypeError("CPU usage is not an object")
        for key, value in list(usage.items()):
            if not key.startswith("cpu") or not key.endswith("_usage"):
                continue
            total_key = f"{key[:-6]}_total"
            total = int(usage[total_key])
            if total <= 0:
                raise ValueError("CPU total must be positive")
            usage[key] = round(int(value) * 100 / total, 1)
        return cast(CpuUsage, usage)
    except (KeyError, TypeError, ValueError) as error:
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


def counter_to_megabits(counter: str) -> float:
    """Convert ASUS byte counter encoded as hexadecimal to Mbit."""
    try:
        return round(int(counter, base=16) * 8 / 1024 / 1024, 1)
    except (TypeError, ValueError) as error:
        raise _invalid("network counter", error) from error


def parse_traffic_totals(text: str) -> TrafficTotals:
    counters = parse_network_counters(text, "total traffic")
    return {
        "sent": counter_to_megabits(counters["INTERNET_tx"]),
        "recv": counter_to_megabits(counters["INTERNET_rx"]),
    }


def parse_wan_status(text: str) -> WanStatus:
    status: dict[str, str] = {}
    try:
        for line in text.split("\n"):
            if "return" in line and "wanlink_" in line:
                key = line.partition("(")[0].partition("_")[2]
                value = line.rpartition(" ")[-1].rstrip(";").strip("'\"")
                if key in WanStatus.__annotations__:
                    status[key] = value
        return cast(WanStatus, status)
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
