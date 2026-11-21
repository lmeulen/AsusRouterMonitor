import argparse
import json

from RouterInfo import RouterInfo


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Show status information from an Asus router.")
    parser.add_argument("ip_address", help="Router IP address or hostname")
    parser.add_argument("username", help="Router username")
    parser.add_argument("password", help="Router password")
    return parser.parse_args(argv)


def count_clients(full_info):
    clients = full_info.get("get_clientlist", {})
    return sum(isinstance(client, dict) for client in clients.values())


def count_online_clients(online_clients):
    if isinstance(online_clients, str):
        online_clients = json.loads(online_clients)
    return len(online_clients)


def main(argv=None):
    args = parse_args(argv)
    ri = RouterInfo(args.ip_address, args.username, args.password)
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
    print("Clients Full Info       : " + str(count_clients(ri.get_clients_fullinfo())))
    print("Clients Info            : " + str(len(ri.get_clients_info())))
    print("DHCP                    : " + str(len(ri.get_dhcp_list())))
    print("Online Clients          : " + str(count_online_clients(ri.get_online_clients())))


if __name__ == "__main__":
    main()
