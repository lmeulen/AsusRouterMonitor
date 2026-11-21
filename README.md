# AsusRouterMonitor

A class to access your Asus router. Uses HTTP calls to obtain information from your router.

See also: [Monitor your Asus router in Python](https://leo-vander-meulen.medium.com/monitor-your-asus-router-in-python-171693465fc1)
on Medium.

Example usage:

```
from asus_router_monitor import RouterInfo

ri = RouterInfo("<router IP>", "<username>", "<password>")
print("Uptime    : {}".format(ri.get_uptime()))
print("Bandwidth : {}".format(ri.get_traffic()))
```

Run the status application with router address, username, and password. A hostname or IP address defaults to HTTP:

```bash
python3 ShowRouterInfo.py 192.168.1.1 admin secret
```

LAN HTTPS and custom ports are supported with a full base URL:

```bash
python3 ShowRouterInfo.py https://router.local:8443 admin secret
```

HTTPS certificates are verified by default. Use a private CA bundle when needed:

```bash
python3 ShowRouterInfo.py https://router.local:8443 admin secret \
  --ca-bundle /path/to/router-ca.pem
```

For a trusted LAN router with a self-signed certificate, verification can be explicitly disabled:

```bash
python3 ShowRouterInfo.py https://192.168.1.1:8443 admin secret --insecure
```

`--insecure` permits man-in-the-middle attacks. Prefer a CA bundle. Set request timeout with `--timeout SECONDS` (default: 10). WAN access is unsupported; use this tool only from a trusted LAN or through a VPN.

The following methods are available:
```
get_uptime           - Uptime and last time of boot
get_uptime_secs      - Uptime
get_memory_usage     - Memory usage statistics
get_cpu_usage        - CPU usage statistics
get_cpu_temperature  - CPU temperature (supported firmware only)
get_settings         - get set of most important router settings
get_clients_fullinfo - All info of all connected clients
get_client_counts    - Online client counts by connection and wireless radio
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

`get_client_counts()` returns exact wired, wireless, unknown, total, and per-radio counts. Band names are best-effort: Asus commonly maps radio `1` to 2.4 GHz and radio `2` to 5 GHz, but this can differ by router model and firmware. Radio `3` and later are reported as `other_wireless` and remain visible in the `radios` mapping.

## Error handling

The package raises typed errors for invalid configuration, authentication, connection, TLS, HTTP, and unsupported/malformed router responses. Import them from `asus_router_monitor`, for example:

```python
from asus_router_monitor import AuthenticationError, RouterConnectionError, RouterInfo

try:
    router = RouterInfo("https://router.local:8443", "admin", "password")
except AuthenticationError:
    print("Router rejected credentials")
except RouterConnectionError:
    print("Router cannot be reached")
```
