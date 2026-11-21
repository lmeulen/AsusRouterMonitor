import argparse
import json
import sys

from asus_router_monitor import (
    AuthenticationError,
    RouterConfigurationError,
    RouterConnectionError,
    RouterError,
    RouterResponseError,
    RouterInfo,
    UnsupportedFirmwareError,
)

EXIT_SUCCESS = 0
EXIT_CONNECTION_OR_AUTH = 1
EXIT_USAGE = 2
EXIT_RESPONSE = 3


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
    parser.add_argument(
        "--debug", action="store_true", help="Show traceback for router errors"
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return args


def count_clients(full_info):
    clients = full_info.get("get_clientlist", {})
    return sum(isinstance(client, dict) for client in clients.values())


def count_online_clients(online_clients):
    return len(online_clients)


def _collect_status(args):
    verify = args.ca_bundle if args.ca_bundle else not args.insecure
    router = RouterInfo(
        args.address,
        args.username,
        args.password,
        verify=verify,
        timeout=args.timeout,
    )
    try:
        cpu_temperature = router.get_cpu_temperature()
    except UnsupportedFirmwareError:
        cpu_temperature = None
    wan = router.get_status_wan()
    settings = router.get_settings()
    return {
        "uptime": router.get_uptime(),
        "uptime_seconds": router.get_uptime_secs(),
        "memory": router.get_memory_usage(),
        "cpu": router.get_cpu_usage(),
        "cpu_temperature": cpu_temperature,
        "traffic_total": router.get_traffic_total(),
        "wan": {"status": wan.get("status"), "online": wan.get("status") == "1"},
        "settings": {"time_zone": settings.get("time_zone")},
        "lan": {
            "ip_address": router.get_lan_ip_address(),
            "netmask": router.get_lan_netmask(),
            "gateway": router.get_lan_gateway(),
        },
        "client_counts": router.get_client_counts(),
        "dhcp_lease_count": len(router.get_dhcp_list()),
    }


def _show_status(args):
    status = _collect_status(args)
    if args.format == "json":
        print(json.dumps(status, indent=2, sort_keys=True))
        return

    print("Last reboot             : " + str(status["uptime"]))
    print("Uptime                  : " + str(status["uptime_seconds"]))
    print("Memory                  : " + str(status["memory"]))
    print("CPU                     : " + str(status["cpu"]))
    print("CPU Temperature         : " + str(status["cpu_temperature"] or "Not available"))
    print("Data                    : " + str(status["traffic_total"]))
    print("WAN ['status']          : " + str(status["wan"]["status"]))
    print("Online                  : " + str(status["wan"]["online"]))
    print("Settings ['time_zone']  : " + str(status["settings"]["time_zone"]))
    print("IP addr                 : " + str(status["lan"]["ip_address"]))
    print("Netmask                 : " + str(status["lan"]["netmask"]))
    print("Gateway                 : " + str(status["lan"]["gateway"]))
    client_counts = status["client_counts"]
    print("Connected Clients       : " + str(client_counts["total"]))
    print("Connected Wired         : " + str(client_counts["wired"]))
    print("Connected Wireless      : " + str(client_counts["wireless"]))
    print("Connected WiFi 2.4 GHz  : " + str(client_counts["wifi_2_4_ghz"]))
    print("Connected WiFi 5 GHz    : " + str(client_counts["wifi_5_ghz"]))
    print("Connected Other WiFi    : " + str(client_counts["other_wireless"]))
    print("Connected Unknown       : " + str(client_counts["unknown"]))
    print("Wireless Radios         : " + str(client_counts["radios"]))
    print("DHCP                    : " + str(status["dhcp_lease_count"]))


def main(argv=None):
    args = parse_args(argv)
    try:
        _show_status(args)
    except (AuthenticationError, RouterConnectionError) as error:
        if args.debug:
            raise
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_CONNECTION_OR_AUTH
    except RouterConfigurationError as error:
        if args.debug:
            raise
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except RouterResponseError as error:
        if args.debug:
            raise
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_RESPONSE
    except RouterError:
        if args.debug:
            raise
        print("Error: Unexpected router error", file=sys.stderr)
        return EXIT_CONNECTION_OR_AUTH
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
