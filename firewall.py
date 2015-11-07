#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time

# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

# hard coded constants

VERDICTS = ['drop', 'pass']

UDP_PROTOCOL = 17
TCP_PROTOCOL = 6
ICMP_PROTOCOL = 1

UDP_HEADER_LEN = 8
DNS_HEADER_LEN = 12

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []

        # add in rules to self.rules
        with open(config['rule'], 'r') as rulesfile:
            lines = [x.strip() for x in rulesfile]
            lines = [x for x in lines if x != '']
            lines = [x.split() for x in lines if x.split()[0] in VERDICTS]
            rules = []
            for x in lines:
                rule = None
                if x[1] == 'dns':
                    rule = DNSRule(x[0], x[2])
                else:
                    rule = ProtocolRule(x[0], x[1], x[2], x[3])
                rules.append(rule)
        self.rules = rules

    
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

        geos = []
        with open('geoipdb.txt', 'r') as geofile:
            lines = [x.strip() for x in geofile]
            for line in lines:
                x = line.split()
                geos.append(Geo(x[0], x[1], x[2]))
        self.geos = geos

    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        # check the packet against all rules
        verdict = firewall_handle_packet(pkt_dir, pkt, self.rules, self.geos)
        verdict = verdict.lower()
        
        # if verdict != 'pass':
            # print 'verdict: '+verdict+' prot: '+str(get_protocol(pkt))+' port: '+str(get_tcp_external_port(pkt_dir,pkt))
        # if get_protocol(pkt) == UDP_PROTOCOL:
            # print 'udp port '+str(get_protocol(pkt))+' verdict: '+verdict + ', ip: '+str(get_external_ip(pkt_dir, pkt))

        if verdict == 'pass' and pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif verdict == 'pass' and pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.

"""
Everything Here was added by me and is highly likely wrong
"""

def print_packet_info(pkt):
    print get_protocol(pkt)
    print get_udp_port(pkt)
    print dns_qdcount(pkt)
    print dns_qtype(pkt)
    print dns_qclass(pkt)

def packet_matches_rule(pkt_dir, pkt, rule, geos):
    if rule.is_dns():
        if not is_dns(pkt_dir,pkt):
            return False
        else:
            qname, qtype, qclass = dns_qname_qtype_qclass(pkt)
            if not domain_match(rule.domain_name, qname):
                return False
    else:
        packet_protocol = get_protocol(pkt)
        rule_protocol = rule.get_protocol()
        if packet_protocol != rule_protocol:
            return False
        if packet_protocol == TCP_PROTOCOL:
            ip = get_external_ip(pkt_dir, pkt)
            port = get_tcp_external_port(pkt_dir, pkt)
            if not rule.matches_ip(ip, geos) or not rule.matches_port(port):
                return False
        if packet_protocol == ICMP_PROTOCOL:
            icmp_type = get_icmp_type(pkt)
            ip = get_external_ip(pkt_dir, pkt)
            if not rule.matches_port(icmp_type) or not rule.matches_ip(ip, geos):
                return False
        if packet_protocol == UDP_PROTOCOL:
            ip = get_external_ip(pkt_dir, pkt)
            if pkt_dir == PKT_DIR_INCOMING:
                port = get_udp_port(pkt, dst = False)
            if pkt_dir == PKT_DIR_OUTGOING:
                port = get_udp_port(pkt, dst = True)
            if not rule.matches_ip(ip, geos) or not rule.matches_port(port):
                return False
    return True

def firewall_handle_packet(pkt_dir, pkt,rules, geos):
    verdict = 'pass'
    for rule in rules:
        if packet_matches_rule(pkt_dir, pkt, rule, geos):
            # print rule
            verdict = rule.verdict
    return verdict

def domain_match(rule_domain, pkt_domain):
    if rule_domain[0] == '*':
        rd = rule_domain[2:]
        pd = pkt_domain
        while len(pd) > 0 and pd[0] != '.':
            pd = pd[1:]
        pd = pd[1:]
        if pd == rd:
            return True
    else:
        if rule_domain == pkt_domain:
            return True
    return False

"""
methods
"""

# return length in bytes
def get_ip_header_length(pkt):
    ihl = pkt[0:1]
    ihl = struct.unpack('!B', ihl)[0]
    ihl =  ihl&0xF
    return ihl * 4

def get_protocol(pkt):
    protocol = struct.unpack('!B', pkt[9:10])[0]
    return protocol

def get_external_ip(pkt_dir, pkt):
    if pkt_dir == PKT_DIR_OUTGOING:
        # use destination
        ext_ip = struct.unpack('!L', pkt[16:20])[0] 
    if pkt_dir == PKT_DIR_INCOMING:
        # use source
        ext_ip = struct.unpack('!L', pkt[12:16])[0] 
    return ext_ip

def get_tcp_external_port(pkt_dir, pkt):
    pkt_ip_hdrlen = get_ip_header_length(pkt)
    if pkt_dir == PKT_DIR_OUTGOING:
        # use destination
        ext_port = struct.unpack('!H', pkt[pkt_ip_hdrlen+2:pkt_ip_hdrlen+2+2])[0]
    if pkt_dir == PKT_DIR_INCOMING:
        # use source
        ext_port = struct.unpack('!H', pkt[pkt_ip_hdrlen+0:pkt_ip_hdrlen+0+2])[0]
    return ext_port

def get_icmp_type(pkt):
    pkt_ip_hdrlen = get_ip_header_length(pkt)
    icmp_type = struct.unpack('!B', pkt[pkt_ip_hdrlen+0:pkt_ip_hdrlen+1])[0]
    return icmp_type

def get_udp_port(pkt, dst = True):
    udp_header_start = get_ip_header_length(pkt)
    if dst:
        port  = pkt[udp_header_start+2:udp_header_start+4]
    else:
        port  = pkt[udp_header_start+0:udp_header_start+2]
    return struct.unpack('!H', port)[0]

""" DNS Stuff""" 
def dns_qdcount(pkt):
    udp_header_start = get_ip_header_length(pkt)
    qdcount = pkt[udp_header_start+UDP_HEADER_LEN+4:udp_header_start+UDP_HEADER_LEN+4+2]
    qdcount = struct.unpack('!H', qdcount)[0]
    return qdcount

def dns_qname_qtype_qclass(pkt):
    start = get_ip_header_length(pkt)+UDP_HEADER_LEN+DNS_HEADER_LEN
    finished = False
    numbytes = struct.unpack('!B', pkt[start:start+1])[0]
    qname = ''
    while not finished:
        # print 'numbytes:'+str(numbytes)
        while numbytes > 0:
            numbytes -= 1
            start = start+1
            qname += chr(struct.unpack('!B', pkt[start:start+1])[0])
            # print qname
        start += 1
        numbytes = struct.unpack('!B', pkt[start:start+1])[0]
        if numbytes == 0:
            finished = True
        else:
            qname += '.'
    start = start + 1
    qtype = struct.unpack('!H', pkt[start:start+2])[0]
    qclass = struct.unpack('!H', pkt[start+2:start+4])[0]
    return qname, qtype, qclass

def is_dns(pkt_dir, pkt):
    # udp outgoing with dst port 53
    protocol = get_protocol(pkt)
    if pkt_dir != PKT_DIR_OUTGOING or protocol != UDP_PROTOCOL:
        return False
    dst_port = get_udp_port(pkt, dst = True)
    if dst_port != 53:
        return False
    # exactly 1 DNS question entry
    qdcount = dns_qdcount(pkt)
    if qdcount != 1:
        return False
    qname, qtype, qclass = dns_qname_qtype_qclass(pkt)
    # qtype == 1 or qtype == 28 
    if qtype != 1 and qtype != 28:
        return False
    # qclass == 1
    if qclass != 1:
        return False
    return True

"""
Classes
"""
class Geo:
    def __init__(self, a, b, code):
        self.a = a
        self.b = b
        self.code = code.lower()
    def a_int(self):
        return 
    def __repr__(self):
        return self.a + self.b + self.code

class Rule:
    def get_protocol(self):
        if self.protocol.lower() == 'tcp':
            return TCP_PROTOCOL
        if self.protocol.lower() == 'udp':
            return UDP_PROTOCOL 
        if self.protocol.lower() == 'icmp':
            return ICMP_PROTOCOL
        return -1

class ProtocolRule(Rule):
    def __init__(self, verdict = '', protocol='', ext_ip = None, ext_port = None):
        self.verdict = verdict
        self.protocol = protocol
        self.ext_ip = ext_ip
        self.ext_port = ext_port

    def is_dns(self):
        return False

    def get_mask(self):
        if '/' in self.ext_ip:
            return int(self.ext_ip.split('/')[1])
        return 32
    
    def get_cc(self, geoipdb, ip):
        first = 0
        last = len(geoipdb)-1
        found = False
        while first <= last and not found:
            mid = (first + last)//2
            geo = geoipdb[mid]
            ip1, = struct.unpack('!L', socket.inet_aton(geo.a)) 
            ip2, = struct.unpack('!L', socket.inet_aton(geo.b)) 
            if ip1 <= ip and ip2 >= ip:
                return geo.code
            else:
                if ip > ip2:
                    first = mid + 1
                else:
                    last = mid - 1
        return None

    def matches_ip(self, ip, geoipdb):
        if self.ext_ip.lower() == 'any':
            return True
        # is a country code
        if not self.ext_ip.isdigit() and len(self.ext_ip) == 2:
            cc = self.get_cc(geoipdb, ip)
            if cc == None:
                return False
            else:
                if cc == self.ext_ip.lower():
                    return True
                else:
                    return False

        # is a standard ip (may have mask)
        rule_ip = self.ext_ip
        rule_ip = struct.unpack('!L', socket.inet_aton(rule_ip.split('/')[0]))[0]
        rule_ip = rule_ip >> (32-self.get_mask())
        ip = ip >> (32-self.get_mask())
        return ip == rule_ip

    def matches_port(self, port):
        if self.ext_port.lower() == 'any':
            return True
        if '-' in self.ext_port:
            p1 = int(self.ext_port.split('-')[0])
            p2 = int(self.ext_port.split('-')[1])
            if port >= p1 and port <= p2:
                return True
        else:
            p = int(self.ext_port)
            if p == port:
                return True
        return False

    def __repr__(self):
        return 'v: '+self.verdict + ', p: '+self.protocol+', ip: '+self.ext_ip+', port: '+self.ext_port

class DNSRule(Rule):
    def __init__(self, verdict = '', domain_name=''):
        self.verdict = verdict
        self.domain_name = domain_name

    def is_dns(self):
        return True

    def __repr__(self):
        return self.verdict

if __name__=='__main__':
    print 'firewall.py'
