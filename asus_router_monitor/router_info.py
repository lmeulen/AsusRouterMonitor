"""Backward-compatible facade for :class:`RouterMonitor`."""

from .client import AsusRouterClient
from .monitor import RouterMonitor


class RouterInfo:
    """Compatibility facade delegating router operations to :class:`RouterMonitor`.

    New applications should construct ``AsusRouterClient`` and ``RouterMonitor``
    directly, which enables transport injection and deterministic testing.
    """

    def __init__(self, address, username, password, verify=True, timeout=10):
        self.client = AsusRouterClient(address, username, password, verify, timeout)
        self.monitor = RouterMonitor(self.client)
        # Retained public connection attributes for callers of earlier releases.
        self.base_url = self.client.base_url
        self.login_url = self.client.login_url
        self.url = self.client.app_url
        self.cpu_temperature_url = self.client.cpu_temperature_url
        self.verify = self.client.verify
        self.timeout = self.client.timeout
        self.headers = self.client.session.headers

    @staticmethod
    def _normalize_base_url(address):
        return AsusRouterClient.normalize_base_url(address)

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def get_uptime(self):
        return self.monitor.get_uptime()

    def get_uptime_secs(self):
        return self.monitor.get_uptime_secs()

    def get_memory_usage(self):
        return self.monitor.get_memory_usage()

    def get_cpu_usage(self):
        return self.monitor.get_cpu_usage()

    def get_clients_fullinfo(self):
        return self.monitor.get_clients_fullinfo()

    def get_traffic_total(self):
        return self.monitor.get_traffic_total()

    def get_traffic(self, sample_seconds=2):
        return self.monitor.get_traffic(sample_seconds)

    def get_status_wan(self):
        return self.monitor.get_status_wan()

    def is_wan_online(self):
        return self.monitor.is_wan_online()

    def get_settings(self):
        return self.monitor.get_settings()

    def get_lan_ip_address(self):
        return self.monitor.get_lan_ip_address()

    def get_lan_netmask(self):
        return self.monitor.get_lan_netmask()

    def get_lan_gateway(self):
        return self.monitor.get_lan_gateway()

    def get_dhcp_list(self):
        return self.monitor.get_dhcp_list()

    def get_online_clients(self):
        return self.monitor.get_online_clients()

    def get_client_counts(self):
        return self.monitor.get_client_counts()

    def get_clients_info(self):
        return self.monitor.get_clients_info()

    def get_client_info(self, clientid):
        return self.monitor.get_client_info(clientid)

    def get_cpu_temperature(self):
        return self.monitor.get_cpu_temperature()

    def get_snapshot(self):
        return self.monitor.get_snapshot()
