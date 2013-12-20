#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from collections import defaultdict

import struct
import socket
import random
import re

DEBUG = False
DEBUG_HTTP = False
PASS = 0
DROP = 1
DENY = 2
NO_MATCH = 3

HEADER_DIVIDER = "\r\n\r\n"

SYN = 0
ACK = 1
FIN_ACK = 2
SYN_ACK = 3

SETUP = 4
DATA_TRANSFER = 5
TEARDOWN = 6

SENDING = 7
RECEIVING = 8

ACK_DATA = 9
ACK_NO_DATA = 10

def debug(s):
    if DEBUG == True:
        print s

def debug_http(s):
    if DEBUG_HTTP == True:
        print s

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

def http_log_line(incoming_stream, outgoing_stream):
    """
    Returns the string to write to log file
    """
    outgoing_lines = [line.split() for line in outgoing_stream.split('\n')]
    host_name = re.search(r"Host: (.*)", outgoing_stream, re.IGNORECASE).group(1).strip()
    method = outgoing_lines[0][0].strip()
    path = outgoing_lines[0][1].strip()
    version = outgoing_lines[0][2].strip()

    incoming_lines = [line.split() for line in incoming_stream.split('\n')]
    status_code = incoming_lines[0][1].strip()
    content_length = get_content_length(incoming_stream)

    return "{} {} {} {} {} {}".format(host_name, method, path, version, status_code, content_length)

def get_content_length(incoming_stream):
    if 'Content-Length' in incoming_stream:
        return int(re.search(r"Content-Length: (\d+)", incoming_stream, re.IGNORECASE).group(1))
    else:
        return -1

def has_data(pkt_info):
    return len(pkt_info['data']) > 0

def has_end_of_header(data):
    return re.search(HEADER_DIVIDER, data) != None

def regex_interpreter(domain_name, pkt_domain_name):
    #Check if two domain names match
    pkt_domain_name = pkt_domain_name.lstrip("www.")
    if domain_name == pkt_domain_name:
        return True

    #Handle regex's
    elif '*' in domain_name:
        #Make sure regex is well formed
        if '*' != domain_name[0]:
            return None
        else:
            if domain_name[1:len(domain_name)] in pkt_domain_name:
                return True

    else:
        return None


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

        # http byte stream
        self.expected_seqno = defaultdict(lambda: -1)
        self.http_connections = defaultdict(lambda: HttpConnection())


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

        verdict, pkt_info = self.handle_rules(pkt_dir, pkt)
        protocol = pkt_info['protocol']
        if verdict == PASS:
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            else:
                self.iface_int.send_ip_packet(pkt)
            debug("PASS")
        elif verdict == DENY:
            if protocol == "tcp":
                #TODO: Send a TCP RST packet
                packet = self.make_RST_pkt(pkt_info, pkt)
                if pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_int.send_ip_packet(packet)
                else:
                    self.iface_ext.send_ip_packet(packet)
                debug("DENY TCP")
            elif protocol == "dns":
                #TODO: Send a DNS response packet
                packet = self.make_dns_response(pkt_info, pkt)
                self.iface_int.send_ip_packet(packet)
                debug("DENY DNS")
        else:
            debug("DROP")

    """
    =======================================================================================
    The following code deals with injecting a RST packet and a DNS response
    =======================================================================================
    """

    def make_RST_pkt(self, pkt_info, packet):
        debug("old packet:")
        debug(pkt_info)
        ip_header_len = pkt_info['header_len'] * 4

        #Set new ttl
        ttl = struct.pack('!B', 64)
        packet = packet[0:8] + ttl + packet[9:]

        #Switch source and destination IP Addresses
        src_ip = pkt_info['dst_ip']
        dst_ip = pkt_info['src_ip']
        packet = packet[0:12] + socket.inet_aton(src_ip) + packet[16:]
        packet = packet[0:16] + socket.inet_aton(dst_ip) + packet[20:]

        #Swtich source and destination ports
        src_port = struct.pack('!H', pkt_info['tcp_dst'])
        dst_port = struct.pack('!H', pkt_info['tcp_src'])
        packet = packet[0:ip_header_len] + src_port + packet[ip_header_len+2:]
        packet = packet[0:ip_header_len + 2] + dst_port + packet[ip_header_len + 4:]

        #Update sequence and ack number
        new_seq_num = struct.pack('!L', 0)
        old_seq_num = struct.unpack('!L', packet[ip_header_len + 4:ip_header_len + 8])[0]
        new_ack_num = struct.pack('!L', old_seq_num + 1)
        packet = packet[0:ip_header_len + 4] + new_seq_num + packet[ip_header_len + 8:]
        packet = packet[0:ip_header_len + 8] + new_ack_num + packet[ip_header_len + 12:]

        #Set ACK and RST flags
        ack_flag = 0x10
        rst_flag = 0x04
        flags = struct.pack('!B', ack_flag + rst_flag)
        packet = packet[0:ip_header_len + 13] + flags + packet[ip_header_len + 14:]

        #Make sure total length is correct
        if pkt_info['total_len'] != len(packet):
            packet = packet[0:2] + struct.pack('!H', len(packet)) + packet[4:]

        #compute ip checksum
        ip_checksum = struct.pack('!H', self.compute_ip_checksum(packet))
        packet = packet[0:10] + ip_checksum + packet[12:]

        #compute tcp checksum
        tcp_checksum = struct.pack('!H', self.compute_transport_checksum(packet))
        packet = packet[0:ip_header_len + 16] + tcp_checksum + packet[ip_header_len + 18:]

        if DEBUG == True:
            debug("new packet:")
            packet_specs = {}
            version_and_length = struct.unpack('!B', packet[0:1])[0]
            packet_specs['version'] = version_and_length >> 4
            packet_specs['header_len'] = version_and_length & 0b00001111
            packet_specs['total_len'] = struct.unpack('!H', packet[2:4])[0]
            packet_specs['ip_checksum'] = struct.unpack('!H', packet[10:12])[0]
            packet_specs['src_ip'] = socket.inet_ntoa(packet[12:16])
            packet_specs['dst_ip'] = socket.inet_ntoa(packet[16:20])
            protocol_byte = struct.unpack('!B', packet[9:10])[0]
            packet_specs['ip_id'] = struct.unpack('!H', packet[4:6])[0]
            protocol_header = packet_specs['header_len'] * 4
            packet_specs['tcp_src'] = struct.unpack('!H', packet[protocol_header:protocol_header + 2])[0]
            packet_specs['tcp_dst'] = struct.unpack('!H', packet[protocol_header + 2:protocol_header + 4])[0]
            debug(packet_specs)

        return packet


    def make_dns_response(self, pkt_info, packet):
        ip_header_len = pkt_info['header_len'] * 4
        dns_header = ip_header_len + 8

        debug("old packet")
        debug(pkt_info)

        #Set new ttl
        ttl = struct.pack('!B', 64)
        packet = packet[0:8] + ttl + packet[9:]

        #Switch source and destination IP Addresses
        src_ip = pkt_info['dst_ip']
        dst_ip = pkt_info['src_ip']
        packet = packet[0:12] + socket.inet_aton(src_ip) + packet[16:]
        packet = packet[0:16] + socket.inet_aton(dst_ip) + packet[20:]

        #Swtich source and destination ports
        src_port = struct.pack('!H', pkt_info['udp_dst'])
        dst_port = struct.pack('!H', pkt_info['udp_src'])
        packet = packet[0:ip_header_len] + src_port + packet[ip_header_len+2:]
        packet = packet[0:ip_header_len + 2] + dst_port + packet[ip_header_len + 4:]

        #set qr to 1 for a response
        options = struct.unpack('!H', packet[dns_header + 2:dns_header + 4])[0]
        qr = 0b1 << 15
        options = options | qr
        packet = packet[0:dns_header + 2] + struct.pack('!H', options) + packet[dns_header + 4:]

        #Update ancount to be 1
        packet = packet[0:dns_header + 6] + struct.pack('!H', 1) + packet[dns_header + 8:]

        #print(pkt_info['dns_qname'])
        #packet = packet[0:dns_header + 12] + pkt_info['dns_qname'] + packet[dns_header + 12 + pkt_info['qname_len']:]

        #Make sure QTYPE = A(1) and QCLASS = internet(1)
        qtype_location = dns_header + 12 + pkt_info['qname_len']
        packet = packet[0:qtype_location] + struct.pack('!H', 1) + packet[qtype_location + 2:]
        packet = packet[0:qtype_location + 2] + struct.pack('!H', 1) + packet[qtype_location + 4:]

        #Clear all contents after DNS Questions if any
        packet = packet[0:qtype_location + 4]

        #copy over qname, qtype, and qclass to DNS Answers section and add appropriate fields
        packet += packet[dns_header + 12:]
        packet += struct.pack('!L', 1) #ttl
        packet += struct.pack('!H', 4) #RDLENGTH
        packet += socket.inet_aton('169.229.49.109')

        #calculate correct UDP length
        udp_len = len(packet) - ip_header_len
        packet = packet[0:ip_header_len + 4] + struct.pack('!H', udp_len) + packet[ip_header_len + 6:]

        #Make sure total length is correct
        packet = packet[0:2] + struct.pack('!H', len(packet)) + packet[4:]

        #compute ip checksum
        ip_checksum = struct.pack('!H', self.compute_ip_checksum(packet))
        packet = packet[0:10] + ip_checksum + packet[12:]

        #compute udp checksum
        tcp_checksum = struct.pack('!H', self.compute_transport_checksum(packet))
        packet = packet[0:ip_header_len + 6] + tcp_checksum + packet[ip_header_len + 8:]

        if DEBUG == True:
            debug("new packet:")
            packet_specs = {}
            version_and_length = struct.unpack('!B', packet[0:1])[0]
            packet_specs['version'] = version_and_length >> 4
            packet_specs['header_len'] = version_and_length & 0b00001111
            packet_specs['total_len'] = struct.unpack('!H', packet[2:4])[0]
            packet_specs['ip_checksum'] = struct.unpack('!H', packet[10:12])[0]
            packet_specs['src_ip'] = socket.inet_ntoa(packet[12:16])
            packet_specs['dst_ip'] = socket.inet_ntoa(packet[16:20])
            protocol_byte = struct.unpack('!B', packet[9:10])[0]
            packet_specs['ip_id'] = struct.unpack('!H', packet[4:6])[0]
            packet_specs['dns_qname'] = packet[dns_header + 12: dns_header + 12 + pkt_info['qname_len']]
            packet_specs['udp_src'] = struct.unpack('!H', packet[ip_header_len:ip_header_len + 2])[0]
            packet_specs['udp_dst'] = struct.unpack('!H', packet[ip_header_len + 2:ip_header_len + 4])[0]
            packet_specs['dns_qtype'] = struct.unpack('!H', packet[qtype_location:qtype_location + 2])[0]
            packet_specs['dns_qclass'] = struct.unpack('!H', packet[qtype_location + 2:qtype_location + 4])[0]
            debug(packet_specs)

        return packet


    def compute_ip_checksum(self, packet):
        nleft = header_len = (struct.unpack('!B', packet[0:1])[0] & 0x0F) * 4
        checksum = 0

        while nleft > 1:
            if nleft != 12: 
                checksum += struct.unpack('!H', packet[nleft - 2:nleft])[0]
            nleft -= 2

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = (~checksum) & 0xFFFF

        orig_chksum = struct.unpack('!H', packet[10:12])[0]
        debug("Old and new ip checksum match: " + str(orig_chksum == checksum))

        return checksum


    def compute_transport_checksum(self, packet):
        total_len = struct.unpack('!H', packet[2:4])[0]
        header_len = (struct.unpack('!B', packet[0:1])[0] & 0x0F) * 4
        protocol = struct.unpack('!B', packet[9:10])[0]

        if total_len % 2 != 0:
            new_len = total_len + 1
            packet += struct.pack('!B', 0)
        else:
            new_len = total_len

        checksum = 0
        if (protocol == 6): #TCP
            prot = "tcp"
            orig_chksum = struct.unpack('!H', packet[header_len + 16:header_len + 18])[0] #TCP
            for i in range(header_len, new_len, 2):
                if i != (header_len + 16):
                    checksum += struct.unpack("!H", packet[i: i+ 2])[0]
        elif (protocol == 17): #UDP
            prot = "udp"
            orig_chksum = struct.unpack('!H', packet[header_len + 6:header_len + 8])[0] #UDP
            for i in range(header_len, new_len, 2):
                if i != (header_len + 6):
                    checksum += struct.unpack("!H", packet[i: i+ 2])[0]

        checksum += struct.unpack("!H", packet[12:14])[0] #src address
        checksum += struct.unpack("!H", packet[14:16])[0] #src address
        checksum += struct.unpack("!H", packet[16:18])[0] #dst address
        checksum += struct.unpack("!H", packet[18:20])[0] #dst address

        checksum += protocol #protocol number
        checksum += total_len - header_len #length

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xFFFF

        debug("Old and new " + str(prot) + " checksum match: " + str(orig_chksum == checksum))
        return checksum



    """
    =======================================================================================
    The following functions deal with processing rules and comparing information from the
    packet that was recieved against the rules.
    =======================================================================================
    """

    def handle_rules(self, pkt_dir, pkt):
        pass_pkt = PASS

        #Pull all the relavant information out of the packet
        pkt_info = self.read_pkt(pkt)
        debug(pkt_info)
        if pkt_info == None:
            return DROP, pkt_info

        pkt_protocol = pkt_info['protocol']

        #If packet is not well formed, drop it
        if pkt_info['valid'] != True:
            return DROP, pkt_info

        #Pass all packets that aren't using ICMP, TCP, or UDP
        if pkt_info['protocol'] == "other":
            return PASS, pkt_info

        #Pass all DNS packets that fall outside the scope of the project
        if pkt_protocol == "dns" and pkt_info['valid_dns'] == True:
            if pkt_info['dns_qtype'] != 1 and pkt_info['dns_qtype'] != 28:
                return PASS, pkt_info
            if pkt_info['dns_qclass'] != 1:
                return PASS, pkt_info

        #Handle all of the rules
        for rule in self.rules:
            #debug(rule)
            # TODO: Do shit here to make all of the rules work :((((
            rule_tuple = tuple([t.lower() for t in rule.split()])
            
            #Handle Transport Layer Rules
            if len(rule_tuple) == 4:
                # Protocol/IP/Port rules
                verdict, protocol, ext_ip_address, ext_port = rule_tuple
                if verdict == "deny":
                    debug(rule)

                #If the protocol of the rule doesn't match current protocol, go to the next rule
                if (protocol == "http") and (pkt_info['HTTP'] == True):
                    http_rules = self.process_http_rules(verdict, protocol, ext_ip_address, ext_port)
                    if http_rules != NO_MATCH:
                        pass_pkt = http_rules
                elif protocol != pkt_protocol:
                    continue
                else:
                    # Process all Transport layer rules
                    transport_rules = self.process_transport_rules(verdict, protocol, ext_ip_address, ext_port, pkt_info, pkt_dir) 
                    if transport_rules != NO_MATCH:
                        debug("Pass pkt: " + str(transport_rules))
                        pass_pkt = transport_rules

            # handle logging
            elif len(rule_tuple) == 3 and rule_tuple[0] == "log":
                log, http, domain_name = rule_tuple

                # write to log if tcp_src == 80 or tcp_dst == 80
                if pkt_protocol == "tcp" and (pkt_info['tcp_src'] == 80 or pkt_info['tcp_dst'] == 80):
                    return self.handle_log(rule_tuple, pkt_dir, pkt_info, domain_name), pkt_info

            #Handle DNS Rules
            elif len(rule_tuple) == 3 and pkt_protocol == "dns":
                #Only consider well formed DNS requests
                if pkt_info['valid_dns'] == True:
                    verdict, dns, domain_name = rule_tuple
                    debug("DNS verdict is: " + str(verdict))
                    dns_rules = self.process_dns_rules(verdict, domain_name, pkt_info['dns_qname'])
                    debug("DNS rules: " + str(dns_rules))
                    if dns_rules != NO_MATCH:
                        debug("Pass pkt: " + str(dns_rules))
                        pass_pkt = dns_rules
                else:
                    #print "invalid dns"
                    return DROP, pkt_info
        return pass_pkt, pkt_info

    def process_http_rules(self, verdict, protocol, hostname, path, pkt_info):
        pass


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
                    return PASS
                elif verdict == "drop":
                    return DROP
                else:
                    return DENY

        return NO_MATCH


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
        ip_num = struct.unpack('!L', socket.inet_aton(pkt_ext_ip_address))[0]
        return self.binary_search_countries(self.geoIP, ip_num)

    def binary_search_countries(self, geoIP, pkt_ext_ip_address):
        if len(geoIP) == 0:
            return None

        line = geoIP[0].split()
        pkt_ext_ip = pkt_ext_ip_address
        mid = len(geoIP)//2
        min_ip = struct.unpack('!L', socket.inet_aton(line[0]))[0]
        max_ip = struct.unpack('!L', socket.inet_aton(geoIP[mid].split()[1]))[0]
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
            return self.binary_search_countries(geoIP[0:mid], pkt_ext_ip)


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
        if regex_interpreter(domain_name, pkt_domain_name) != None:
            debug("Domain name matches")
            if verdict == "pass":
                return PASS
            elif verdict == "drop":
                return DROP
            else:
                return DENY
        else:
            debug("no domain names match")
            # no dns rules match
            return NO_MATCH



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

        if DEBUG == True:
            self.compute_ip_checksum(pkt)

        pkt_specs['tos'] = struct.unpack('!B', pkt[1:2])[0]

        #Find the total length of the packet
        pkt_specs['total_len'] = struct.unpack('!H', pkt[2:4])[0]
        pkt_specs['ttl'] = struct.unpack('!B', pkt[8:9])[0]
        pkt_specs['ip_checksum'] = struct.unpack('!H', pkt[10:12])[0]

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
            if DEBUG == True:
                self.compute_transport_checksum(pkt)
            pkt_specs['tcp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
            pkt_specs['tcp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]
            if (pkt_specs['tcp_dst'] == 80) or (pkt_specs['tcp_src'] == 80):
                pkt_specs['HTTP'] = True
            flags = struct.unpack('!B', pkt[protocol_header + 13:protocol_header + 14])[0]
            offset_reserve = struct.unpack('!B', pkt[protocol_header + 12:protocol_header + 13])[0]
            # offset is number of 32-bit words in header
            offset = (offset_reserve >> 4) * 4  # multply by 4 to convert to bytes

            pkt_specs['fin'] = 0x1 & flags == 0x1
            pkt_specs['syn'] = 0x2 & flags == 0x2
            pkt_specs['ack'] = 0x10 & flags == 0x10
            pkt_specs['data'] = pkt[protocol_header + offset:pkt_specs['total_len']]
            pkt_specs['tcp_seqno'] = struct.unpack('!L', pkt[protocol_header + 4:protocol_header + 8])[0]
            pkt_specs['tcp_ackno'] = struct.unpack('!L', pkt[protocol_header + 8:protocol_header + 12])[0]

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
                        if DEBUG == True:
                            self.compute_transport_checksum(pkt)
                        pkt_specs['valid_dns'] = True
                        dns_questions = dns_header + 12
                        pkt_specs['dns_qname'], pkt_specs['qname_len'] = self.find_qname(pkt, dns_questions)
                        DNS_qtype_location = dns_questions + pkt_specs['qname_len']
                        pkt_specs['dns_qtype'] = struct.unpack('!H', pkt[DNS_qtype_location:DNS_qtype_location + 2])[0]
                        pkt_specs['dns_qclass'] = struct.unpack('!H', pkt[DNS_qtype_location + 2:DNS_qtype_location + 4])[0]
                except Exception:
                    #print 'throwing an exception'
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
            debug(curr)
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
            debug(domain_name)

        return domain_name, qname_len + 1

    def increment_expected_seqno(self, stream_id, i):
        self.expected_seqno[stream_id] = (self.expected_seqno[stream_id] + i) % (0xFFFFFFFF + 1)

    def handle_log(self, rule_tuple, pkt_dir, pkt_info, domain_name):
        debug_http("*** handle_log")
        debug_http("rule_tuple: " + str(rule_tuple))
        if pkt_dir == PKT_DIR_INCOMING:
            debug_http("pkt_dir: " + str("INCOMING"))
        else:
            debug_http("pkt_dir: " + str("OUTGOING"))
        l = []
        if pkt_info['syn']:
            l.append("SYN")
        if pkt_info['fin']:
            l.append("FIN")
        if pkt_info['ack']:
            l.append("ACK")
        debug_http(','.join(l))
        debug_http('seqno: ' + str(pkt_info['tcp_seqno']) + '   ackno: ' + str(pkt_info['tcp_ackno']))
        debug_http('src: ' + str(pkt_info['src_ip']) + ":" + str(pkt_info['tcp_src']) + '   dst: ' + str(pkt_info['dst_ip']) + ":" + str(pkt_info['tcp_dst']))
        debug_http('data: ' + repr(pkt_info['data']))

        #debug_http("pkt_info: " + str(pkt_info))

        # determine stream_id
        if pkt_dir == PKT_DIR_OUTGOING:
            stream_id = (pkt_info['src_ip'], pkt_info['tcp_src'])
        else:
            stream_id = (pkt_info['dst_ip'], pkt_info['tcp_dst'])

        debug_http('expected_seqno: ' + str(self.expected_seqno[stream_id]))
        pass_pkt = PASS

        if pkt_dir == PKT_DIR_OUTGOING:
            conn_id = (pkt_info['src_ip'], pkt_info['tcp_src'])
        else:
            conn_id = (pkt_info['dst_ip'], pkt_info['tcp_dst'])
        debug_http("conn_id: " + str(conn_id))
        http_conn = self.http_connections[conn_id]

        if pkt_dir == PKT_DIR_OUTGOING:
            if pkt_info['syn'] == True and pkt_info['ack'] == False and pkt_info['fin'] == False:
                # SYN
                self.expected_seqno[stream_id] = pkt_info['tcp_seqno']
                self.increment_expected_seqno(stream_id, 1)
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # ACK
                self.increment_expected_seqno(stream_id, len(pkt_info['data']))
                http_conn.handle_ack(pkt_info, pkt_dir, domain_name)


            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == True:
                # FIN ACK
                # log http

                self.increment_expected_seqno(stream_id, 1)
            else:
                # error
                pass
        else:
            if self.expected_seqno[stream_id] >= 0:
                if self.expected_seqno[stream_id] < pkt_info['tcp_ackno']:
                    # packet out of order
                    return DROP
                elif self.expected_seqno[stream_id] > pkt_info['tcp_ackno']:
                    # packet retransmission
                    return PASS 

            if pkt_info['syn'] == True and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # SYN ACK
                pass
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # ACK
                http_conn.handle_ack(pkt_info, pkt_dir, domain_name)

            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == True:
                # FIN ACK
                #for conn in self.http_connections.values():
                #    conn.write_to_log(domain_name)
                #del self.http_connections[conn_id]
                pass
            else:
                # error
                pass

        
        return pass_pkt


class HttpConnection(object):
    def __init__(self):
        self.reset()

    def reset(self):
        self.incoming_buffer = ""
        self.incoming_headers = []

        self.outgoing_buffer = ""
        self.outgoing_headers = []

        self.incoming_has_header = False
        self.outgoing_has_header = False
        self.prev_msg_state = None
        self.prev_had_data = False
        self.prev_dir = PKT_DIR_INCOMING

    def append_to_incoming_buffer(self, s):
        self.incoming_buffer += s

    def append_to_outgoing_buffer(self, s):
        self.outgoing_buffer += s

    def get_header_and_clear_incoming_buffer(self):
        self.incoming_headers.append(self.incoming_buffer.split(HEADER_DIVIDER)[0])
        debug_http("incoming_headers: " + repr(self.incoming_headers))
        debug_http("outgoing_headers: " + repr(self.outgoing_headers))
        self.incoming_buffer = ""

    def get_header_and_clear_outgoing_buffer(self):
        self.outgoing_headers.append(self.outgoing_buffer.split(HEADER_DIVIDER)[0])
        debug_http("incoming_headers: " + repr(self.incoming_headers))
        debug_http("outgoing_headers: " + repr(self.outgoing_headers))
        self.outgoing_buffer = ""

    def write_to_log(self, domain_name):
        assert len(self.incoming_headers) == len(self.outgoing_headers), str(len(self.incoming_headers)) + " != " + str(len(self.outgoing_headers)) \
            + "INCOMING HEADERS: " + str(self.incoming_headers) + "\nOUTGOING HEADERS: " + str(self.outgoing_headers)

        log_lines = [http_log_line(self.incoming_headers[i], self.outgoing_headers[i]) for i in xrange(len(self.incoming_headers))]

        for log_line in log_lines:
            # check to make sure we only log the domain specified in the rules
            if regex_interpreter(domain_name, log_line.split()[0]) != None:
                flog = open('http.log', 'a')
                flog.write(log_line + '\n')
                flog.flush()
                flog.close()

        self.reset()

    def handle_ack(self, pkt_info, pkt_dir, domain_name):

        if pkt_dir == PKT_DIR_OUTGOING:
            if has_data(pkt_info):
                debug_http("\n*** OUTGOING DATA ***\n" + repr(pkt_info['data']))

                #if self.prev_msg_state == RECEIVING:
                #    self.outgoing_has_header = False
                
                if self.outgoing_has_header == False:
                    self.append_to_outgoing_buffer(pkt_info['data'])

                if has_end_of_header(pkt_info['data']) and self.outgoing_has_header == False:
                    #self.get_header_and_clear_outgoing_buffer()
                    self.outgoing_has_header = True

                debug_http("prev_msg_state: " + str(self.prev_msg_state))
                debug_http("outgoing_has_header: " + str(self.outgoing_has_header))
                
                #self.prev_msg_state = SENDING
        else:
            if has_data(pkt_info):
                debug_http("\n*** INCOMING DATA ***\n" + repr(pkt_info['data']))

                #if self.prev_msg_state == SENDING:
                #    self.incoming_has_header = False
                
                if self.incoming_has_header == False:
                    self.append_to_incoming_buffer(pkt_info['data'])

                if has_end_of_header(pkt_info['data']) and self.incoming_has_header == False:
                    #self.get_header_and_clear_incoming_buffer()
                    self.incoming_has_header = True

                debug_http("prev_msg_state: " + str(self.prev_msg_state))
                debug_http("incoming_has_header: " + str(self.incoming_has_header))

                #self.prev_msg_state = RECEIVING
            
            #if len(self.incoming_headers) == 1 and len(self.outgoing_headers) == 1:
            #    self.write_to_log(domain_name)

        
        if has_end_of_header(self.incoming_buffer) and has_end_of_header(self.outgoing_buffer):
            self.incoming_headers = [self.incoming_buffer]
            self.outgoing_headers = [self.outgoing_buffer]

            self.write_to_log(domain_name)

        #if pkt_dir == PKT_DIR_OUTGOING:
        #    if has_data(pkt_info) == True and self.prev_had_data == True and self.prev_dir == PKT_DIR_INCOMING:
        #        self.write_to_log(domain_name)
        #    pass
        #else:
        #    pass
        
        self.prev_dir = pkt_dir
        self.prev_had_data = has_data(pkt_info)
