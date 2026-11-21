"""High-level Asus router monitoring service."""

from datetime import datetime, timezone
import time
from typing import Any

from .client import AsusRouterClient
from .exceptions import UnsupportedFirmwareError
from .models import ClientCounts, RouterSnapshot, Traffic
from .parsers import (
    parse_client_list,
    parse_cpu_temperature,
    parse_cpu_usage,
    parse_dhcp_leases,
    parse_memory_usage,
    parse_network_counters,
    parse_nvram_value,
    parse_traffic_totals,
    parse_uptime,
    parse_wan_status,
)

_SETTINGS = (
    "time_zone", "time_zone_dst", "time_zone_x", "time_zone_dstoff",
    "ntp_server0", "acs_dfs", "productid", "apps_sq", "lan_hwaddr",
    "lan_ipaddr", "lan_proto", "x_Setting", "label_mac", "lan_netmask",
    "lan_gateway", "http_enable", "https_lanport", "wl0_country_code",
    "wl1_country_code",
)


class RouterMonitor:
    """Domain operations built from transport responses and pure parsers."""

    def __init__(self, client: AsusRouterClient):
        self.client = client

    def get_uptime(self):
        return parse_uptime(self.client.hook("uptime()"))

    def get_uptime_secs(self) -> int:
        return int(self.get_uptime()["uptime"])

    def get_memory_usage(self):
        return parse_memory_usage(self.client.hook("memory_usage()"))

    def get_cpu_usage(self):
        return parse_cpu_usage(self.client.hook("cpu_usage()"))

    def get_clients_fullinfo(self) -> dict[str, Any]:
        return parse_client_list(self.client.hook("get_clientlist()"))

    def get_traffic_total(self):
        return parse_traffic_totals(self.client.hook("netdev(appobj)"))

    def get_traffic(self, sample_seconds: float = 2) -> Traffic:
        first = parse_network_counters(self.client.hook("netdev(appobj)"), "traffic")
        time.sleep(sample_seconds)
        second = parse_network_counters(self.client.hook("netdev(appobj)"), "traffic")
        total = {
            "sent": int(second["INTERNET_tx"], 16) * 8 / 1024 / 1024 / 2,
            "recv": int(second["INTERNET_rx"], 16) * 8 / 1024 / 1024 / 2,
        }
        return {
            "speed": {
                "tx": total["sent"] - int(first["INTERNET_tx"], 16) * 8 / 1024 / 1024 / 2,
                "rx": total["recv"] - int(first["INTERNET_rx"], 16) * 8 / 1024 / 1024 / 2,
            },
            "total": total,
        }

    def get_status_wan(self):
        return parse_wan_status(self.client.hook("wanlink()"))

    def is_wan_online(self) -> bool:
        return self.get_status_wan()["status"] == "1"

    def get_settings(self) -> dict[str, str]:
        return {setting: self.get_setting(setting) for setting in _SETTINGS}

    def get_setting(self, setting: str) -> str:
        return parse_nvram_value(self.client.hook(f"nvram_get({setting})"), setting)

    def get_lan_ip_address(self) -> str:
        return self.get_setting("lan_ipaddr")

    def get_lan_netmask(self) -> str:
        return self.get_setting("lan_netmask")

    def get_lan_gateway(self) -> str:
        return self.get_setting("lan_gateway")

    def get_dhcp_list(self):
        return parse_dhcp_leases(self.client.hook("dhcpLeaseMacList()"))

    def _client_records(self) -> dict[str, Any]:
        response = self.get_clients_fullinfo()
        clients = response.get("get_clientlist")
        return clients if isinstance(clients, dict) else {}

    def get_online_clients(self) -> list[dict[str, str]]:
        return [
            {"mac": client_id}
            for client_id, client in self._client_records().items()
            if len(client_id) == 17 and isinstance(client, dict)
            and client.get("isOnline") == "1"
        ]

    def get_client_counts(self) -> ClientCounts:
        counts: ClientCounts = {
            "total": 0, "wired": 0, "wireless": 0, "wifi_2_4_ghz": 0,
            "wifi_5_ghz": 0, "other_wireless": 0, "unknown": 0, "radios": {},
        }
        for client_id, client in self._client_records().items():
            if len(client_id) != 17 or not isinstance(client, dict) or client.get("isOnline") != "1":
                continue
            counts["total"] += 1
            radio = str(client.get("isWL", "")).strip()
            if radio == "0":
                counts["wired"] += 1
            elif radio.isdigit() and radio != "0":
                counts["wireless"] += 1
                counts["radios"][radio] = counts["radios"].get(radio, 0) + 1
                if radio == "1":
                    counts["wifi_2_4_ghz"] += 1
                elif radio == "2":
                    counts["wifi_5_ghz"] += 1
                else:
                    counts["other_wireless"] += 1
            else:
                counts["unknown"] += 1
        return counts

    def get_clients_info(self) -> list[dict[str, Any]]:
        fields = ("name", "nickName", "ip", "mac", "isOnline", "curTx", "curRx", "totalTx", "totalRx")
        return [
            {field: client.get(field) for field in fields}
            for client_id, client in self._client_records().items()
            if len(client_id) == 17 and isinstance(client, dict) and client.get("isOnline") == "1"
        ]

    def get_client_info(self, clientid: str):
        return self._client_records().get(clientid)

    def get_cpu_temperature(self):
        return parse_cpu_temperature(self.client.get_cpu_temperature())

    def get_snapshot(self) -> RouterSnapshot:
        """Collect one consistent status set; CPU temperature is optional.

        Transport/parser failures abort collection. Unsupported CPU telemetry is
        represented by ``None`` so successful required metrics are retained.
        """
        snapshot: RouterSnapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime": self.get_uptime(),
            "memory": self.get_memory_usage(),
            "cpu": self.get_cpu_usage(),
            "traffic_total": self.get_traffic_total(),
            "wan": self.get_status_wan(),
            "client_counts": self.get_client_counts(),
        }
        try:
            snapshot["cpu_temperature"] = self.get_cpu_temperature()
        except UnsupportedFirmwareError:
            snapshot["cpu_temperature"] = None
        return snapshot
