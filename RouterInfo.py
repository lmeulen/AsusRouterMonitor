import requests
import base64
import json
import re
import time
from urllib.parse import urlsplit


class RouterInfo:

    def __init__(self, address, username, password, verify=True, timeout=10):
        """
        Create the object and connect with the router.
        Parameters:
            address : Router hostname, IP address, or HTTP(S) base URL
            username : Root user name
            password : Password required to login
            verify : Verify TLS certificates, or path to a CA bundle
            timeout : Request timeout in seconds
        """
        self.base_url = self._normalize_base_url(address)
        self.login_url = self.base_url + '/login.cgi'
        self.url = self.base_url + '/appGet.cgi'
        self.cpu_temperature_url = self.base_url + '/ajax_coretmp.asp'
        self.verify = verify
        self.timeout = timeout
        self.headers = None
        self.__authenticate(username, password)

    @staticmethod
    def _normalize_base_url(address):
        address = address.strip().rstrip('/')
        if '://' not in address:
            address = 'http://' + address
        parsed = urlsplit(address)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise ValueError('Router address must use HTTP or HTTPS')
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError('Router address must not contain a path, query, or fragment')
        return address

    def __authenticate(self, username, password):
        """
        Authenticate the object with the router
        Parameters:
            username : Root user name
            password : Password required to login
        """
        auth = "{}:{}".format(username, password).encode('ascii')
        logintoken = base64.b64encode(auth).decode('ascii')
        payload = "login_authorization={}".format(logintoken)
        headers = {
            'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
        }
        try:
            response = requests.post(
                url=self.login_url,
                data=payload,
                headers=headers,
                verify=self.verify,
                timeout=self.timeout,
            )
            response.raise_for_status()
            r = response.json()
        except (requests.RequestException, ValueError):
            return False
        if "asus_token" in r:
            token = r['asus_token']
            self.headers = {
                'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245",
                'cookie': 'asus_token={}'.format(token)
            }
            return True
        else:
            return False

    def __get(self, command):
        """
        Private get method to execute a hook on the router and return the result
        Parameters:
            command : Command to send to the return
        :returns: string result from the router
        """
        if self.headers:
            payload = "hook={}".format(command)
            try:
                r = requests.post(
                    url=self.url,
                    data=payload,
                    headers=self.headers,
                    verify=self.verify,
                    timeout=self.timeout,
                )
                r.raise_for_status()
            except requests.RequestException:
                return None
            return r.text
        else:
            return None

    def get_uptime(self):
        """
        Return uptime of the router
        Format: {'since': 'Thu, 22 Jul 2021 14:32:38 +0200', 'uptime': '375001'}
        :returns: JSON with last boot time and uptime in seconds
        """
        r = self.__get('uptime()')
        since = r.partition(':')[2].partition('(')[0]
        up = r.partition('(')[2].partition(' ')[0]
        return json.loads('{' + '"since":"{}", "uptime":"{}"'.format(since, up) + '}')

    def get_uptime_secs(self):
        """
        Return uptime of the router in seconds
        :returns: integer - uptime in seconds
        """
        r = self.get_uptime()
        return int(r['uptime'])

    def get_memory_usage(self):
        """
        Return memory usage of the router
        Format: {'mem_total': '262144', 'mem_free': '107320', 'mem_used': '154824'}
        :returns: JSON with memory variables
        """
        s = self.__get('memory_usage()')
        return json.loads('{' + s[17:])

    def get_cpu_usage(self):
        """
        Return CPU usage of the router
        Format: {'cpu1_total': '38106047', 'cpu1_usage': '3395512',
                 'cpu2_total': '38106008', 'cpu2_usage': '2384694'}
        :returns: JSON with CPU load statistics
        """
        s = self.__get('cpu_usage()')
        return json.loads('{' + s[14:])

    def get_clients_fullinfo(self):
        """
        Obtain a list of all clients
        Format: {"get_clientlist":{"AC:84:C6:6C:A7:C0":{"type": "2", "defaultType": "0", "name": "Archer_C1200",
                                                        "nickName": "Router Forlindon", "ip": "192.168.2.175",
                                                        "mac": "AC:84:C6:6C:A7:C0", "from": "networkmapd",
                                                        "macRepeat": "1", "isGateway": "0", "isWebServer": "0",
                                                        "isPrinter": "0", "isITunes": "0", "dpiType": "",
                                                        "dpiDevice": "", "vendor": "TP-LINK", "isWL": "0",
                                                        "isOnline": "1", "ssid": "", "isLogin": "0", "opMode": "0",
                                                        "rssi": "0", "curTx": "", "curRx": "", "totalTx": "",
                                                        "totalRx": "", "wlConnectTime": "", "ipMethod": "Manual",
                                                        "ROG": "0", "group": "", "callback": "", "keeparp": "",
                                                        "qosLevel": "", "wtfast": "0", "internetMode": "allow",
                                                        "internetState": "1", "amesh_isReClient": "1",
                                                        "amesh_papMac": "04:D4:C4:C4:AD:D0"
                                  },
                                  "maclist": ["AC:84:C6:6C:A7:C0"],
                                  "ClientAPILevel": "2" }}
        :returns: JSON with list of clents and a list of mac addresses
        """
        return json.loads(self.__get('get_clientlist()'))

    # Total traffic in Mb/s
    def get_traffic_total(self):
        """
        Get total amount of traffic since last restart (Megabit format)
        Format: {'sent': '15901.92873764038', 'recv': '10926.945571899414'}
        :returns: JSON with sent and received Megabits since last boot
        """
        meas_2 = json.loads(self.__get('netdev(appobj)'))
        tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        return json.loads('{' + '"sent":"{}", "recv":"{}"'.format(tx, rx) + '}')

    # Traffic in Mb/s . Megabit per second
    # Note this method has a 2 second delay to calculate current throughput
    def get_traffic(self):
        """
        Get total and current amount of traffic since last restart (Megabit format)
        Note there is a two second delay to determine current traffic
        Format: {"speed": {"tx": 0.13004302978515625, "rx": 4.189826965332031},
                 "total": {"sent": 15902.060073852539, "recv": 10931.135665893555}}
        :returns: JSON with current up and down stream in Mbit/s and totals since last reboot
        """
        meas_1 = self.__get('netdev(appobj)')
        time.sleep(2)
        meas_2 = self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        persec = {}
        totaldata = {}
        tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['sent'] = tx
        tx -= int(meas_1['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        persec['tx'] = tx
        rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['recv'] = rx
        rx -= int(meas_1['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        persec['rx'] = rx
        return json.dumps({'speed': persec, 'total': totaldata})

    def get_status_wan(self):
        """
        Get the status of the WAN connection
        Format: {"status": "1", "statusstr": "'Connected'", "type": "'dhcp'", "ipaddr": "'192.168.1.2'",
                 "netmask": "'255.255.255.0'", "gateway": "'192.168.1.1'", "dns": "1.1.1.1'",
                 "lease": "86400", "expires": "81967", "xtype": "''", "xipaddr": "'0.0.0.0'",
                 "xnetmask": "'0.0.0.0'", "xgateway": "'0.0.0.0'", "xdns": "''", "xlease": "0",
                 "xexpires": "0"}
        :returns: JSON with status information on the WAN connection
        """
        r = self.__get('wanlink()')
        status = {}
        for f in r.split('\n'):
            if 'return' in f:
                if 'wanlink_' in f:
                    key = f.partition('(')[0].partition('_')[2]
                    value = f.rpartition(' ')[-1][:-2]
                    status[key] = value
        return json.loads(json.dumps(status))

    def is_wan_online(self):
        """
        Returns if the WAN connection in onlise
        :returns: True if WAN is connected
        """
        r = self.get_status_wan()
        return r['status'] == '1'

    def get_settings(self):
        """
        Get settings from the router
        Format:{'time_zone': 'MEZ-1DST', 'time_zone_dst': '1', 'time_zone_x': 'MEZ-1DST,M3.2.0/2,M10.2.0/2',
               'time_zone_dstoff': 'M3.2.0/2,M10.2.0/2', 'ntp_server0': 'pool.ntp.org', 'acs_dfs': '1',
               'productid': 'RT-AC68U', 'apps_sq': '', 'lan_hwaddr': '04:D4:C4:C4:AD:D0',
               'lan_ipaddr': '192.168.2.1', 'lan_proto': 'static', 'x_Setting': '1',
               'label_mac': '04:D4:C4:C4:AD:D0', 'lan_netmask': '255.255.255.0', 'lan_gateway': '0.0.0.0',
               'http_enable': '2', 'https_lanport': '8443', 'wl0_country_code': 'EU', 'wl1_country_code': 'EU'}
        :returns: JSON with Router settings
        """
        settings = {}
        for s in ['time_zone', 'time_zone_dst', 'time_zone_x', 'time_zone_dstoff', 'time_zone',
                  'ntp_server0', 'acs_dfs', 'productid', 'apps_sq', 'lan_hwaddr', 'lan_ipaddr',
                  'lan_proto', 'x_Setting', 'label_mac', 'lan_netmask', 'lan_gateway',
                  'http_enable', 'https_lanport', 'wl0_country_code', 'wl1_country_code']:
            r = self.__get("nvram_get(" + s + ")")
            settings[s] = json.loads(r)[s]
        return settings

    def get_lan_ip_address(self):
        """
        Obtain the IP address of the router
        :return: IP address
        """
        r = self.__get("nvram_get(lan_ipaddr)")
        return json.loads(r)['lan_ipaddr']

    def get_lan_netmask(self):
        """
        Obtain the Netmask for the LAN network
        :return: Netmask
        """
        r = self.__get("nvram_get(lan_netmask)")
        return json.loads(r)['lan_netmask']

    def get_lan_gateway(self):
        """
        Obtain the gateway for the LAN network
        :return: IP address of gateay
        """
        r = self.__get("nvram_get(lan_gateway)")
        return json.loads(r)['lan_gateway']

    def get_dhcp_list(self):
        """
        Obtain a list of DHCP leases
        Format: { "dhcpLeaseMacList":[["00:00:00:00:00:00", "name"], ...]
        :returns: JSON with a list of DHCP leases
        """
        r = self.__get("dhcpLeaseMacList()")
        return json.loads(r)

    def _get_clientlist(self):
        """Return client records, or an empty dictionary for an invalid response."""
        response = self.get_clients_fullinfo()
        if not isinstance(response, dict):
            return {}
        clients = response.get('get_clientlist')
        return clients if isinstance(clients, dict) else {}

    def get_online_clients(self):
        """
        Obtain a list of MAC-addresses from online clients
        Format: [{"mac": "00:00:00:00:00:00"}, ...]
        :returns: JSON list with MAC addresses
        """
        clients = self._get_clientlist()
        online = [
            {"mac": client_id}
            for client_id, client in clients.items()
            if len(client_id) == 17
            and isinstance(client, dict)
            and client.get('isOnline') == '1'
        ]
        return json.dumps(online)

    def get_clients_info(self):
        """
        Obtain info on all clients (limited list of datafields)
        Format: [{"name": "Archer_C1200", "nickName": "Router Forlindon", "ip": "192.168.2.175",
                  "mac": "AC:84:C6:6C:A7:C0", "isOnline": "1", "curTx": "", "curRx": "", "totalTx": ""}, ...]
        :return: JSON list of clients with main characteristics
        """
        clients = self._get_clientlist()
        fields = ('name', 'nickName', 'ip', 'mac', 'isOnline', 'curTx',
                  'curRx', 'totalTx', 'totalRx')
        return [
            {field: client.get(field) for field in fields}
            for client_id, client in clients.items()
            if len(client_id) == 17
            and isinstance(client, dict)
            and client.get('isOnline') == '1'
        ]

    def get_client_info(self, clientid):
        """
        Get info on a single client
        :param clientid: MAC address of the client requested
        :return: JSON with clientinfo (see get_clients_info() for description)
        """
        return self._get_clientlist().get(clientid)

    def get_cpu_temperature(self):
        """
        Get CPU temperature reported by supported Asus router firmware.
        :return: Dictionary with cpu_temperature in degrees Celsius, or None
        """
        if not self.headers:
            return None

        try:
            response = requests.get(
                url=self.cpu_temperature_url,
                headers=self.headers,
                verify=self.verify,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            return None

        match = re.search(
            r'(?:curr_coreTmp|coreTmp|cpu_temperature)\s*=\s*["\']?(-?\d+(?:\.\d+)?)',
            response.text,
            re.IGNORECASE,
        )
        if not match:
            return None
        return {"cpu_temperature": match.group(1)}
