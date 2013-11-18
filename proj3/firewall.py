#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct
import socket
import random

DEBUG = False

def debug(s):
    if DEBUG == True:
        print s

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    TCP = 6
    UDP = 17
    ICMP = 1

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.loss_mode = config.has_key("loss")
        if self.loss_mode:
            self.loss_rate = int(config["loss"])


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
        if self.loss_mode:
            loss = 100 * random.random()
            if self.loss_rate > loss:
                #Drop the packet
                return

        if self.handle_rules(pkt_dir, pkt):
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            else:
                self.iface_int.send_ip_packet(pkt)
            debug(True)
        else:
            debug(False)


    """
    =======================================================================================
    The following functions deal with processing rules and comparing information from the
    packet that was recieved against the rules.
    =======================================================================================

    """

    def handle_rules(self, pkt_dir, pkt):
        pass_pkt = False

        #Pull all the relavant information out of the packet
        pkt_info = self.read_pkt(pkt)
        debug(pkt_info)
        if pkt_info == None:
            return False

        #If packet is not well formed, drop it
        if pkt_info['valid'] != True:
            return False

        #Pass all packets that aren't using ICMP, TCP, or UDP
        if pkt_info['protocol'] == "other":
            return True

        #Pass all DNS packets that fall outside the scope of the project
        if pkt_info['protocol'] == "dns" and pkt_info['valid_dns'] == True:
            if pkt_info['dns_qtype'] != 1 and pkt_info['dns_qtype'] != 28:
                return True
            if pkt_info['dns_qclass'] != 1:
                return True

        #Handle all of the rules
        for rule in self.rules:
            debug(rule)
            # TODO: Do shit here to make all of the rules work :((((
            rule_tuple = tuple([t.lower() for t in rule.split()])

            #Handle Transport Layer Rules
            if len(rule_tuple) == 4:
                # Protocol/IP/Port rules
                verdict, protocol, ext_ip_address, ext_port = rule_tuple

                #If the protocol of the rule doesn't match current protocol, go to the next rule
                if protocol != pkt_info['protocol']:
                    continue
                else:
                    # Process all Transport layer rules
                    transport_rules = self.process_transport_rules(verdict, protocol, ext_ip_address, ext_port, pkt_info, pkt_dir) 
                    if transport_rules == True or transport_rules == False:
                        pass_pkt = transport_rules

            #Handle DNS Rules
            elif len(rule_tuple) == 3 and pkt_info['protocol'] == "dns":
                #Only consider well formed DNS requests
                if pkt_info['valid_dns'] == True:
                    verdict, dns, domain_name = rule_tuple
                    dns_rules = self.process_dns_rules(verdict, domain_name, pkt_info['dns_qname'])
                    if dns_rules == True:
                        pass_pkt = dns_rules
                    else:
                        return False
                else:
                    return False
        return pass_pkt


    def process_transport_rules(self, verdict, protocol, ext_ip_address, ext_port,
                                pkt_info, pkt_dir):
        #Find the external port IP of the packet
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_ext_ip_address = pkt_info['dst_ip']
            if protocol == "icmp":
                pkt_ext_port = pkt_info[protocol + "_type"]
            else:
                pkt_ext_port = pkt_info[protocol + '_dst']
        else:
            pkt_ext_ip_address = pkt_info['src_ip']
            if protocol == "icmp":
                pkt_ext_port = pkt_info[protocol + "_type"]
            else:
                pkt_ext_port = pkt_info[protocol + '_src']

        if self.match_ip_addr(ext_ip_address, pkt_ext_ip_address):
            if self.match_port(ext_port, pkt_ext_port):
                if verdict == "pass":
                    return True
                else:
                    return False

        return None


    def match_port(self, ext_port, pkt_ext_port):
        #Case 1: any
        if ext_port == "any":
            return True

        #Case 2: a single value
        elif ext_port == str(pkt_ext_port):
            return True

        #Case 3: a range    
        elif '-' in ext_port:
            port_range = ext_port.split('-')
            min_port = int(port_range[0])
            max_port = int(port_range[1])
            if int(pkt_ext_port) >= min_port and int(pkt_ext_port) <= max_port:
                return True
            else:
                return False
        else:
            return False




    def match_ip_addr(self, ext_ip_address, pkt_ext_ip_address):
        #Case 1: any
        if ext_ip_address == "any":
            return True

        #Case 2: 2-byte country code
        elif len(ext_ip_address) == 2:
            pkt_country = self.find_country(pkt_ext_ip_address)
            if pkt_country != None:
                if ext_ip_address.lower() == pkt_country:
                    return True
            return False

        #Case 3: Single IP Address
        elif ext_ip_address == pkt_ext_ip_address:
            return True

        #Case 4: IP Prefix
        elif "/" in ext_ip_address:
            if self.netmask(ext_ip_address, pkt_ext_ip_address):
                return True
            else:
                return False

        #All other cases
        else:
            return False


    #Do a binary search to find the country code from geoIP
    def find_country(self, pkt_ext_ip_address):
        return self.binary_search_countries(self.geoIP, pkt_ext_ip_address)

    def binary_search_countries(self, geoIP, pkt_ext_ip_address):
        if len(geoIP) == 0:
            return None

        line = geoIP[0].split()
        pkt_ext_ip = pkt_ext_ip_address
        min_ip = struct.unpack('!L', socket.inet_aton(line[0]))[0]
        max_ip = struct.unpack('!L', socket.inet_aton(line[1]))[0]
        country_code = line[2]

        if len(geoIP) == 1:
            if pkt_ext_ip >= min_ip and pkt_ext_ip <= max_ip:
                return country_code
            else:
                return None

        mid = len(geoIP)//2

        #Packet external IP is larger than max bound
        if pkt_ext_ip > max_ip:
            return self.binary_search_countries(geoIP[mid + 1:len(geoIP)], pkt_ext_ip)

        #Packet external IP is smaller than min bound
        elif pkt_ext_ip < min_ip:
            return self.binary_search_countries(geoIP[0:mid], pkt_ext_ip)

        #Packet external IP is within the this range
        else:
            return country_code


    def netmask(self, ext_ip_range, pkt_ext_ip_address):
        ip_range = ext_ip_range.split("/")
        lower_ext_ip_address = ip_range[0]
        network_mask = ip_range[1]
        host_bits = 32 - int(network_mask)

        #Find the upper bound of the ip range
        lower_ext_ip_range = struct.unpack('!L', socket.inet_aton(lower_ext_ip_address))[0]
        upper_ip = int(lower_ext_ip_range + (host_bits**2 - 1))
        
        #Make sure everything is binary
        lower_ip = struct.unpack('!L', socket.inet_aton(lower_ext_ip_address))
        pkt_ip_address = struct.unpack('!L', socket.inet_aton(pkt_ext_ip_address))

        if pkt_ip_address >= lower_ip and pkt_ip_address <= upper_ip:
            return True
        else:
            return False


    def process_dns_rules(self, verdict, domain_name, pkt_domain_name):
        if self.regex_interpreter(domain_name, pkt_domain_name) != None:
            if verdict == "pass":
                return True
            else:
                return False
        else:
            # no dns rules match, pass packet
            return True


    def regex_interpreter(self, domain_name, pkt_domain_name):
        #Check if two domain names match
        if domain_name == pkt_domain_name:
            return True

        #Handle regex's
        elif '*' in domain_name:
            #Make sure regex is well formed
            if '*' != domain_name[0]:
                return False
            else:
                if domain_name[1:len(domain_name)] in pkt_domain_name:
                    return True

        else:
            return None


    """
    =======================================================================================
    The following functions deal with reading the necessary information from the 
    incoming packet
    =======================================================================================
    
    """


    def read_pkt(self, pkt):
        #Create a dictionary to hold of the information on the packet
        pkt_specs = {}
        pkt_specs['valid'] = False

        #If packet is too short, it is corrupted
        if len(pkt) < 8:
            return None

        #Find the version number/Header length
        version_and_length = struct.unpack('!B', pkt[0:1])[0]
        pkt_specs['version'] = version_and_length >> 4
        pkt_specs['header_len'] = version_and_length & 0b00001111

        #Find the total length of the packet
        pkt_specs['total_len'] = struct.unpack('!H', pkt[2:4])[0]

        if self.validate_ip(pkt_specs['header_len'], pkt_specs['total_len'], pkt):
            #IP header is valid
            pkt_specs['valid'] = True

            pkt_specs['src_ip'] = socket.inet_ntoa(pkt[12:16])
            pkt_specs['dst_ip'] = socket.inet_ntoa(pkt[16:20])
            protocol_byte = struct.unpack('!B', pkt[9:10])[0]
            pkt_specs['protocol'] = self.match_protocol(protocol_byte, pkt_specs, pkt)
            pkt_specs['ip_id'] = struct.unpack('!H', pkt[4:6])[0]

        return pkt_specs


    def validate_ip(self, header_len, total_len, pkt):
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
            pkt_specs['tcp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
            pkt_specs['tcp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]
            return "tcp"

        #UDP Protocol
        if protocol == 17:
            pkt_specs['udp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
            pkt_specs['udp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]

            #Check if the UDP packet contains a DNS packet
            if pkt_specs['udp_dst'] == 53:
                try: 
                    dns_header = protocol_header + 8
                    QDCOUNT = struct.unpack('!H', pkt[dns_header + 4:dns_header + 6])[0]

                    if QDCOUNT != 1:
                        #invalidate the packet
                        pkt_specs['valid_dns'] = False
                    else:
                        pkt_specs['valid_dns'] = True
                        dns_questions = dns_header + 12
                        pkt_specs['dns_qname'], qname_len = self.find_qname(pkt, dns_questions)
                        DNS_qtype_location = dns_questions + qname_len
                        pkt_specs['dns_qtype'] = struct.unpack('!H', pkt[DNS_qtype_location:DNS_qtype_location + 2])[0]
                        pkt_specs['dns_qclass'] = struct.unpack('!H', pkt[DNS_qtype_location + 2:DNS_qtype_location + 4])[0]
                except Exception:
                    pkt_specs['valid_dns'] = False
                return "dns"

            return "udp"

        return "other"


    def find_qname(self, pkt, dns_questions):
        domain_name = ""
        labels = 0
        qname_len = 0
        dns_questions_payload = pkt[dns_questions:len(pkt)]

        for byte in dns_questions_payload:
            curr = struct.unpack('!B', byte)[0]
            #Reached the end of the domain name
            if curr == 0:
                break

            #Just started or finished looking through the last sequence of bytes
            elif labels != 0:
                domain_name += chr(curr)
                labels -= 1

            else:
                labels = curr
                qname_len = qname_len + curr + 1 #add an extra 1 to acccount for the first label
                #Add in period between groups of labels
                if len(domain_name) > 0:
                    domain_name += "."

        return domain_name, qname_len + 1

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
