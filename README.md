# AsusRouterMonitor

A class to access your Asus router. Uses HTTP calls to obtain information from your router.

See also: [Monitor your Asus router in Python](https://leo-vander-meulen.medium.com/monitor-your-asus-router-in-python-171693465fc1)
on Medium.

Example usage:

```
from RouterInfo import RouterInfo

ri = RouterInfo("<router IP>", "<username>", "<password>")
print("Uptime    : {}".format(ri.get_uptime()))
print("Bandwidth : {}".format(ri.get_traffic()))
```

The following methods are available:
```
get_uptime           - Uptime and last time of boot
get_uptime_secs      - Uptime
get_memory_usage     - Memory usage statistics
get_cpu_usage        - CPU usage statistics
get_settings         - get set of most important router settings
get_clients_fullinfo - All info of all connected clients
get_clients_info     - Get most important info on all clients
get_client_info(cid) - Get info of specified client (MAC address)
get_traffic_total    - Total network usage since last boot
get_traffic          - Current network usage and total usage
get_status_wan       - Get WAN status info
is_wan_online        - WAN connected True/False
get_lan_ip_address   - Get router IP address for LAN
get_lan_netmask      - Get network mask for LAN
get_lan_gateway      - Get gateway address for LAN
get_dhcp_list        - List of DHCP leases given out
get_online_clients   - Get list of online clients (MAC address)
get_clients_info     - Get most important info on all clients
get_client_info(cid) - Get info of specified client (MAC address)
```
