import unittest
import os
import struct
import socket

from firewall import Firewall
from main import TAPInterface, RegularInterface, EthernetInterface, Timer

class TAPInterfaceMock(TAPInterface):
    def __init__(self, name):
        pass

class RegularInterfaceMock(RegularInterface):
    def __init__(self, name):
        pass

class CountryCodeTestCase(unittest.TestCase):
    IFNAME_INT = 'int'
    IFNAME_EXT = 'ext'
    IP_GATEWAY = '10.0.2.2'

    def setup_interfaces(self):
        self.iface_int = TAPInterfaceMock(self.IFNAME_INT)
        self.iface_ext = RegularInterfaceMock(self.IFNAME_EXT)

    def setUp(self):
        self.setup_interfaces()

        self.timer = Timer()

        config = {'rule': 'rules.conf'}
        self.firewall = Firewall(config, self.timer, 
                self.iface_int, self.iface_ext)

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

if __name__ == '__main__':
    unittest.main()
