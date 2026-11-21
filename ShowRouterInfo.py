import argparse
import json
import sys

from asus_router_monitor import (
    AuthenticationError,
    RouterConfigurationError,
    RouterConnectionError,
    RouterError,
    RouterInfo,
    RouterResponseError,
    UnsupportedFirmwareError,
)

EXIT_SUCCESS = 0
EXIT_CONNECTION_OR_AUTH = 1
EXIT_USAGE = 2
EXIT_RESPONSE = 3


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Show status information from an Asus router.")
    parser.add_argument("address", help="Router hostname, IP address, or HTTP(S) base URL")
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
    parser.add_argument("--debug", action="store_true", help="Show traceback for router errors")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
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


def _value(value, unavailable="unavailable"):
    return unavailable if value is None else str(value)


def _print_field(label, value):
    print(f"{label:<30} {value}")


def _show_text_status(status):
    memory = status["memory"]
    cpu = status["cpu"]
    temperature = status["cpu_temperature"]
    traffic = status["traffic_total"]
    wan = status["wan"]
    lan = status["lan"]
    client_counts = status["client_counts"]

    print("Router status")
    print("=============")
    _print_field("Last reboot:", _value(status["uptime"].get("since")))
    _print_field("Uptime:", f"{status['uptime_seconds']} seconds")
    print("\nResources")
    print("---------")
    _print_field("Memory total:", f"{_value(memory.get('mem_total'))} KiB")
    _print_field("Memory used:", f"{_value(memory.get('mem_used'))} KiB")
    _print_field("Memory free:", f"{_value(memory.get('mem_free'))} KiB")
    _print_field("CPU 1 usage:", f"{_value(cpu.get('cpu1_usage'))}%")
    if "cpu2_usage" in cpu:
        _print_field("CPU 2 usage:", f"{_value(cpu.get('cpu2_usage'))}%")
    temperature_value = temperature.get("cpu_temperature") if temperature else None
    temperature_display = (
        f"{temperature_value} °C" if temperature_value is not None else "unavailable"
    )
    _print_field("CPU temperature:", temperature_display)
    print("\nNetwork")
    print("-------")
    _print_field("WAN connected:", "yes" if wan["online"] else "no")
    _print_field("WAN status:", _value(wan["status"]))
    _print_field("Traffic sent since boot:", f"{traffic['sent']} Mbit")
    _print_field("Traffic received since boot:", f"{traffic['recv']} Mbit")
    _print_field("LAN IP address:", _value(lan["ip_address"]))
    _print_field("LAN netmask:", _value(lan["netmask"]))
    _print_field("LAN gateway:", _value(lan["gateway"]))
    _print_field("Time zone:", _value(status["settings"]["time_zone"]))
    print("\nConnected clients")
    print("-----------------")
    _print_field("Total:", client_counts["total"])
    _print_field("Wired:", client_counts["wired"])
    _print_field("Wireless:", client_counts["wireless"])
    _print_field("Wi-Fi 2.4 GHz:", client_counts["wifi_2_4_ghz"])
    _print_field("Wi-Fi 5 GHz:", client_counts["wifi_5_ghz"])
    _print_field("Other Wi-Fi:", client_counts["other_wireless"])
    _print_field("Unknown connection:", client_counts["unknown"])
    _print_field("Wireless radios:", _value(client_counts["radios"], "none"))
    _print_field("DHCP leases:", status["dhcp_lease_count"])


def _show_status(args):
    status = _collect_status(args)
    if args.format == "json":
        print(json.dumps(status, indent=2, sort_keys=True))
        return
    _show_text_status(status)


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
