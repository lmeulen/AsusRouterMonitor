import argparse
import json

from asus_router_monitor import RouterInfo


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Show status information from an Asus router.")
    parser.add_argument(
        "address", help="Router hostname, IP address, or HTTP(S) base URL"
    )
    parser.add_argument("username", help="Router username")
    parser.add_argument("password", help="Router password")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-bundle", help="CA bundle used to verify router certificate")
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Disable HTTPS certificate verification (trusted LAN only)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10, help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return args


def count_clients(full_info):
    clients = full_info.get("get_clientlist", {})
    return sum(isinstance(client, dict) for client in clients.values())


def count_online_clients(online_clients):
    if isinstance(online_clients, str):
        online_clients = json.loads(online_clients)
    return len(online_clients)


def main(argv=None):
    args = parse_args(argv)
    verify = args.ca_bundle if args.ca_bundle else not args.insecure
    ri = RouterInfo(
        args.address,
        args.username,
        args.password,
        verify=verify,
        timeout=args.timeout,
    )
    print("Last reboot             : " + str(ri.get_uptime()))
    print("Uptime                  : " + str(ri.get_uptime_secs()))
    print("Memory                  : " + str(ri.get_memory_usage()))
    print("CPU                     : " + str(ri.get_cpu_usage()))
    print("CPU Temperature         : " + str(ri.get_cpu_temperature()))
    print("Data                    : " + str(ri.get_traffic_total()))
    print("WAN ['status']          : " + str(ri.get_status_wan()['status']))
    print("Online                  : " + str(ri.is_wan_online()))
    print("Settings ['time_zone']  : " + str(ri.get_settings()['time_zone']))
    print("IP addr                 : " + str(ri.get_lan_ip_address()))
    print("Netmask                 : " + str(ri.get_lan_netmask()))
    print("Gateway                 : " + str(ri.get_lan_gateway()))
    client_counts = ri.get_client_counts()
    print("Connected Clients       : " + str(client_counts["total"]))
    print("Connected Wired         : " + str(client_counts["wired"]))
    print("Connected Wireless      : " + str(client_counts["wireless"]))
    print("Connected WiFi 2.4 GHz  : " + str(client_counts["wifi_2_4_ghz"]))
    print("Connected WiFi 5 GHz    : " + str(client_counts["wifi_5_ghz"]))
    print("Connected Other WiFi    : " + str(client_counts["other_wireless"]))
    print("Connected Unknown       : " + str(client_counts["unknown"]))
    print("Wireless Radios         : " + str(client_counts["radios"]))
    print("DHCP                    : " + str(len(ri.get_dhcp_list())))


if __name__ == "__main__":
    main()
