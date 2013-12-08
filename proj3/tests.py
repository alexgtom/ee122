import unittest
import os
import struct
import socket

from firewall import Firewall, get_http_log_data
from main import TAPInterface, RegularInterface, EthernetInterface, Timer

class FirewallTestCase(unittest.TestCase):
    def setup_interfaces(self):
        self.iface_int = TAPInterfaceMock(self.IFNAME_INT)
        self.iface_ext = RegularInterfaceMock(self.IFNAME_EXT)

    def setUp(self):
        self.setup_interfaces()

        self.timer = Timer()

        config = {'rule': 'rules.conf'}
        self.firewall = Firewall(config, self.timer, 
                self.iface_int, self.iface_ext)


class TAPInterfaceMock(TAPInterface):
    def __init__(self, name):
        pass

class RegularInterfaceMock(RegularInterface):
    def __init__(self, name):
        pass

class CountryCodeTestCase(FirewallTestCase):
    IFNAME_INT = 'int'
    IFNAME_EXT = 'ext'
    IP_GATEWAY = '10.0.2.2'

    def assertCountryCodeEqual(self, ip, countryCode):
        self.assertEqual(self.firewall.find_country(ip), countryCode)

    def testCountryCode(self):
        self.assertCountryCodeEqual('2.16.70.0', 'IT')
        self.assertCountryCodeEqual('1.0.0.0', 'AU')
        self.assertCountryCodeEqual('1.0.0.1', 'AU')
        self.assertCountryCodeEqual('223.255.255.0', 'AU')
        self.assertCountryCodeEqual('223.255.255.255', 'AU')
        self.assertCountryCodeEqual('223.255.255.128', 'AU')
        self.assertCountryCodeEqual('222.123.0.255', 'TH')

class HttpDataTestCase(unittest.TestCase):
    def testGetHttpLogData(self):
        request = """GET / HTTP/1.1
Host: google.com
User-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/
Accept_encoding: gzip
Accept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7
Cache-Control: no-cache
Accept-Language: de,en;q=0.7,en-us;q=0.3
"""
        response = """HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
Content-Type: text/html; charset=UTF-8
Date: Mon, 18 Nov 2013 23:58:12 GMT
Expires: Wed, 18 Dec 2013 23:58:12 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 219
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Alternate-Protocol: 80:quic"""
        self.assertEqual(get_http_log_data(response, request)[0], "google.com GET / HTTP/1.1 301 219")

if __name__ == '__main__':
    unittest.main()
