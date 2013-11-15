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
        self.geoIP = []
        ips = [l.rstrip('\n') for l in open("geoipdb.txt")]
        ips = [l for l in ips if len(l) > 0]
        ips = [l for l in ips if l[0] != '%']

        self.geoIP = ips

        # TODO: Also do some initialization if needed.

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        if self.handle_rules(pkt_dir pkt):
            if pkt_dir == PKT_DIR_OUTGOING:
                self.self.iface_ext.send_ip_packet(pkt)
            else:
                self.self.iface_int.send_ip_packet(pkt)

    def handle_rules(self, pkt_dir, pkt):
        #Pull all the relavant information out of the packet
        pkt_info = self.read_pkt(pkt)

        #Pass all packets that aren't using ICMP, TCP, or UDP
        if pkt_info['protocol'] = "other":
            return True

        #Pass all DNS packets that fall outside the scope of the project
        if pkt_info['protocol'] = "dns":
            if pkt_info['dns_qtype'] != 1 and pkt_info['dns_qtype'] != 28:
                return True
            if pkt_info['dns_qclass'] != 1:
                return True

        #Handle all of the rules
        for rule in self.rules:
            # TODO: Do shit here to make all of the rules work :((((



    def read_pkt(self, pkt):
        #Create a dictionary to hold of the information on the packet
        pkt_specs = {}
        pkt_specs['valid'] = False

        #If packet is too short, it is corrupted
        if len(pkt) < 8:
            return False

        #Find the version number/Header length
        version_and_length = struct.unpack('!B', pkt[0:1])[0]
        pkt_specs['version'] = version_and_length >> 4
        pkt_specs['header_len'] = version_and_length & 0b00001111

        #Find the total length of the packet
        pkt_specs['total_len'] = struct.unpack('!H', pkt[2:4])

        if validate_ip(header_len, total_len):
            #IP header is valid
            pkt_specs['valid'] = True

            pkt_specs['src_ip'] = socket.inet_ntoa(pkt[12:16])
            pkt_specs['dst_ip'] = socket.inet_ntoa(pkt[16:20])
            protocol_byte = struct.unpack('!B', pkt[9:10])[0]
            pkt_specs['protocol'] = self.match_protocol(protocol_byte, pkt_specs, pkt)
            pkt_specs['ip_id'] = struct.unpack('!H', pkt[4:6])[0]

        return pkt_specs


    def validate_ip(self, header_len, total_len):
        #Check if header meet minimum length requirments
        if header_len < 5:
            return False
        #Check if total_len matches actual packet length
        elif total_len != len(pkt):
            return False
        else:
            return True

    def match_protocol(self, protocol, pkt_specs, pkt):
        #Find the end of the IP Header in bytes
        protocol_header = pkt_specs['header_len'] * 4

        #ICMP Protocol
        if protocol == 1:
            pkt_specs['icmp_type'] = struct.unpack('!B', pkt[protocol_header:protocol_header + 1])[0] 
            return "icmp"

        #TCP Protocol
        if protocol == 6:
            pkt_info['tcp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
            pkt_info['tcp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]
            return "tcp"

        #UDP Protocol
        if protocol == 17:
            pkt_info['udp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
            pkt_info['udp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]

            #Check if the UDP packet contains a DNS packet
            if pckt_info['udp_dst'] == 53:
                DNS_header = protocol_header + 8
                QDCOUNT = struct.unpack('!H', pkt[DNS_header + 4:DNS_header + 6])[0]

                if QDCOUNT != 1:
                    #invalidate the packet
                    pkt_specs['valid_dns'] = False
                else:
                    pkt_specs['valid_dns'] = True
                    DNS_questions = DNS_header + 12
                    pkt_specs['dns_qname'], qname_len = self.find_qname(pkt, DNS_questions)
                    DNS_qtype_location = DNS_questions + qname_len
                    pkt_specs['dns_qtype'] = struct.unpack('!H', pkt[DNS_qtype_location:DNS_qtype_location + 2])[0]
                    pkt_specs['dns_qclass'] = struct.unpack('!H', pkt[DNS_qtype_location + 2:DNS_qtype_location + 4])[0]
                return "dns"

            return "udp"

        return "other"


    def find_qname(self, pkt, dns_questions):
        domain_name = ""
        labels = 0
        qname_len = 0
        dns_questions_payload[pkt[dns_questions:len(pkt)]

        for byte in dns_questions_payload:
            curr = struct.unpack('!B', dns_questions)[0]
            #Reached the end of the domain name
            if curr == 0:
                break

            #Just started or finished looking through the last sequence of bytes
            elif labels != 0:
                dns_domain += chr(curr)
                num_labels -= 1

            else:
                labels = curr
                qname_len = qname_len + curr + 1 #add an extra 1 to acccount for the first label
                #Add in period between groups of labels
                if len(domain_name) > 0:
                    domain_name + "."

        return domain_name, qname_len + 1


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
