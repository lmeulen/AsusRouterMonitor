import requests
import base64
import json
import time


class RouterInfo:

    def __init__(self, ipaddress, username, password):
        """
        Create the object and connect with the router
        Parameters:
            ipaddress : IP Address of the router
            username : Root user name
            password : Password required to login
        """
        self.ipaddress = ipaddress
        self.url = 'http://{}/appGet.cgi'.format(ipaddress)
        self.headers = None
        self.__authenticate(ipaddress, username, password)

    def __authenticate(self, ipaddress, username, password):
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
            r = requests.post(url='http://{}/login.cgi'.format(ipaddress), data=payload, headers=headers).json()
        except:
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
                r = requests.post(url=self.url, data=payload, headers=self.headers)
            except:
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
        since = r.partition(':')[2].partition('(')[0][1:]
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

    def get_online_clients(self):
        """
        Obtain a list of MAC-addresses from online clients
        Format: [{"mac": "00:00:00:00:00:00"}, ...]
        :returns: JSON list with MAC addresses
        """
        clnts = self.get_clients_fullinfo()
        print(clnts)
        lst = []
        for c in clnts['get_clientlist']:
            if (len(c) == 17) and ("isOnline" in clnts['get_clientlist'][c]) and (clnts['get_clientlist'][c]['isOnline'] == '1'):
                lst.append({"mac": c})
        return json.dumps(lst)

    def get_clients_info(self):
        """
        Obtain info on all clients (limited list of datafields)
        Format: [{"name": "Archer_C1200", "nickName": "Router Forlindon", "ip": "192.168.2.175",
                  "mac": "AC:84:C6:6C:A7:C0", "isOnline": "1", "curTx": "", "curRx": "", "totalTx": ""}, ...]
        :return: JSON list of clients with main characteristics
        """
        clnts = self.get_clients_fullinfo()
        lst = []
        for c in clnts['get_clientlist']:
            # Only walk through the mac-addresses, not the additional datafields
            if (len(c) == 17) and ("isOnline" in clnts['get_clientlist'][c]) and (clnts['get_clientlist'][c]['isOnline'] == '1'):
                lst.append(
                    {
                        "name": clnts['get_clientlist'][c]['name'],
                        "nickName": clnts['get_clientlist'][c]['nickName'],
                        "ip": clnts['get_clientlist'][c]['ip'],
                        "mac": clnts['get_clientlist'][c]['mac'],
                        "isOnline": clnts['get_clientlist'][c]['isOnline'],
                        "curTx": clnts['get_clientlist'][c]['curTx'],
                        "curRx": clnts['get_clientlist'][c]['curRx'],
                        "totalTx": clnts['get_clientlist'][c]['totalTx'],
                        "totalRx": clnts['get_clientlist'][c]['totalRx'],
                    }
                )
        return json.loads(json.dumps(lst))

    def get_client_info(self, clientid):
        """
        Get info on a single client
        :param clientid: MAC address of the client requested
        :return: JSON with clientinfo (see get_clients_info() for description)
        """
        clnts = self.get_clients_fullinfo()['get_clientlist']
        if clientid in clnts:
            return clnts[clientid]
        else:
            return None

    def get_cpu_temperature(self):
        """
        Get cpu temperature
        :return: JSON with cpu temperature
        """
        self.url = 'http://' + self.ipaddress + '/ajax_coretmp.asp'
        try:
            r = requests.get(url=self.url, headers=self.headers)
            cpu_tmp = r.text.split(';')[1].split('"')[1]
            dt = {"cpu_temperature": cpu_tmp}
            return json.loads(json.dumps(dt))
        except:
            return None
