#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

def ip2long(ip):
    """
    Convert an IP string to long
    """
    # remove slash ip suffex 
    ip = ip.split('/')[0]

    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def port_range(s):
    ports = s.split('-')
    if len(ports) == 2:
        return xrange(int(ports[0]), int(ports[1]))
    else:
        return [int(ports[0])]

class Firewall:
    TCP = 6
    UDP = 17
    ICMP = 1

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext


        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []
        with open(config['rule'], 'r') as f:
            # strip trailing and beginning whitespace from lines
            lines = [l.strip() for l in f.readlines()]

            # strip out blank lines
            lines = [l for l in lines if len(l) > 0]

            # strip out comments
            lines = [l for l in lines if l[0] != "%"]

            self.rules = lines

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pkt_src_ip = pkt[12:16]
        pkt_dst_ip = pkt[16:20]
        pkt_protocol = pkt[9:10]
        pkt_ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)

        if pkt_protocol == self.TCP:
            pkt_header = pkt[24:44]
            pkt_dst_port = pkt_header[2:4]
        elif pkt_protocol == self.UDP:
            pkt_header = pkt[24:28]
            pkt_dst_port = pkt_header[2:4]
        elif pkt_protocol == self.ICMP:
            pkt_header = pkt[24:25]
            pkt_dst_port = None
        else:
            raise Exception("Unknown pkt_protocol: " + str(pkt_protocol))

        self.protocol_map = {
            'tcp': self.TCP,
            'udp': self.UDP,
            'icmp': self.ICMP,
        }

        for rule in self.rules:
            # create tokens and convert them all to lower case
            rule_tuple = tuple([t.lower() for t in rule.split()])

            if len(rule_tuple) == 4:
                # Protocol/IP/Port rules
                verdict, protocol, external_ip_address, external_port = rule_tuple
                external_ip_address = struct.unpack("!L", external_ip_address)

                # protocol
                if self.protocol_map[protocol] != pkt_protocol:
                    continue

                # external IP address
                if external_ip_address == "any":
                    pass
                elif ip2long(external_ip_address) != pkt_dst_ip:
                    continue
                else:
                    # country code
                    raise NotImplementedError

                # external port
                if external_port == "any":
                    pass
                elif int(pkt_dst_port) not in port_range(external_port):
                    continue
                else:
                    raise Exception("Invalid port specified in rules: " + external_port)
            elif len(rule_tuple) == 3 and protocol == self.UDP:
                # DNS Rules
                verdict, dns, domain_name = rule_tuple
                if domain_name[0] == '*':
                    pass
                # elif domain_name == packet domain name
            else:
                raise Exception("Invalid rule specified '" + rule + "'")

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
