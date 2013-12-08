#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from collections import defaultdict

import struct
import socket
import random
import re

DEBUG = False
DEBUG_HTTP = True
PASS = 0
DROP = 1
DENY = 2
NO_MATCH = 3

HEADER_DIVIDER = "\r\n\r\n"

SYN = 0
ACK = 1
FIN_ACK = 2
SYN_ACK = 3

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

def is_persistent_connection(data):
    """ returns a boolean of whether or not the connection is persistent """
    return re.search('Connection: Keep-Alive', data, re.IGNORECASE) != None
            

def get_header_tokens(data):
    # this method will output tokens in format [header, header, header], the data is discarded

    # tokens are in format [header, dataheader, dataheader, ... , data]
    tokens = data.split(HEADER_DIVIDER)
    fixed_tokens = []
    
    # append the first header
    prev_header = tokens.pop(0)
    fixed_tokens.append(prev_header)

    # len(tokens) - 1 because the last token is data
    for i in xrange(len(tokens)-1):
        dataheader = tokens.pop(0)
        content_length = get_content_length(prev_header)
        if content_length < 0:
            content_length = 0
        header = dataheader[content_length:]
        fixed_tokens.append(header)
        prev_header = header

    return fixed_tokens


def get_http_log_data(incoming_stream, outgoing_stream):
    debug_http("*** BEGIN INCOMING_STREAM ***\n" + incoming_stream + "\n*** END INCOMING STREAM ***")
    debug_http("*** BEGIN OUTGOING_STREAM ***\n" + outgoing_stream + "\n*** END OUTGOING STREAM ***")
    if not is_persistent_connection(outgoing_stream):
        try:
            return [http_log_line(incoming_stream, outgoing_stream)]
        except AttributeError:
            return []
    
    # tokens are in format [header, data, header, data, ...]
    incoming_tokens = get_header_tokens(incoming_stream)
    outgoing_tokens = get_header_tokens(outgoing_stream)

    if len(incoming_tokens) == 0 and len(outgoing_tokens) == 0:
        return []

    assert len(incoming_tokens) == len(outgoing_tokens), str(len(incoming_tokens)) + " != " + str(len(outgoing_tokens)) + \
        "\nINCOMING_TOKENS: " + str(incoming_tokens) + "\nOUTGOING_TOKENS: " + str(outgoing_tokens)

    return [http_log_line(incoming_tokens[i], outgoing_tokens[i]) for i in xrange(len(incoming_tokens))]

def has_complete_header(data):
    """ tries to find a blank line, if there is one then we have the whole header """
    return len(filter(lambda line: len(line.strip()) == 0, data.split('\n'))) > 0


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
        self.outgoing_stream = defaultdict(str)
        self.incoming_stream = defaultdict(str)
        self.expected_seqno = defaultdict(lambda: -1)
        self.last_msg_type = defaultdict(lambda: FIN_ACK)

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
        new_seq_num = struct.pack('!L', 0x00000000)
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
                if protocol != pkt_protocol:
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
                    print "invalid dns"
                    return DROP, pkt_info
        return pass_pkt, pkt_info


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
        if self.regex_interpreter(domain_name, pkt_domain_name) != None:
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


    def regex_interpreter(self, domain_name, pkt_domain_name):
        #Check if two domain names match
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
                    print 'throwing an exception'
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
            stream_id = (pkt_info['dst_ip'], pkt_info['tcp_dst'])
        else:
            stream_id = (pkt_info['src_ip'], pkt_info['tcp_src'])

        debug_http('expected_seqno: ' + str(self.expected_seqno[stream_id]))
        pass_pkt = PASS

        if pkt_dir == PKT_DIR_OUTGOING:
            if pkt_info['syn'] == True and pkt_info['ack'] == False and pkt_info['fin'] == False:
                # SYN
                self.expected_seqno[stream_id] = pkt_info['tcp_seqno']
                self.increment_expected_seqno(stream_id, 1)
                self.last_msg_type[stream_id] = SYN
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # ACK
                self.increment_expected_seqno(stream_id, len(pkt_info['data']))

                if self.last_msg_type[stream_id] == FIN_ACK:
                    # close the connection if we recieved a fin ack
                    # run logging stuff
                    debug_http("### BEGIN LOGGING ###")
                    log_lines = get_http_log_data(self.incoming_stream[stream_id], self.outgoing_stream[stream_id])
                    
                    for log_line in log_lines:
                        # check to make sure we only log the domain specified in the rules
                        if self.regex_interpreter(domain_name, log_line.split()[0]) != None:
                            flog = open('http.log', 'a')
                            flog.write(log_line + '\n')
                            flog.flush();
                            flog.close();
                    self.outgoing_stream[stream_id] = ""
                    self.incoming_stream[stream_id] = ""
                    debug_http("### END LOGGING ###")
                else:
                    self.outgoing_stream[stream_id] += pkt_info['data']

                self.last_msg_type[stream_id] = ACK
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == True:
                # FIN ACK
                self.increment_expected_seqno(stream_id, 1)
                self.last_msg_type[stream_id] = FIN_ACK
            else:
                # error
                pass
        else:
            if self.expected_seqno[stream_id] < pkt_info['tcp_ackno']:
                # packet out of order
                return DROP
            elif self.expected_seqno[stream_id] > pkt_info['tcp_ackno']:
                # packet retransmission
                return PASS

            if pkt_info['syn'] == True and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # SYN ACK
                self.last_msg_type[stream_id] = SYN_ACK
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
                # ACK
                self.incoming_stream[stream_id] += pkt_info['data']
                self.last_msg_type[stream_id] = ACK
            elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == True:
                # FIN ACK
                self.last_msg_type[stream_id] = FIN_ACK
            else:
                # error
                pass
        
        return pass_pkt
    

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
