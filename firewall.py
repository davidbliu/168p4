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
packets = []

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

        # save the packet in pickle
        packets.append((pkt, pkt_dir))
        if True and len(packets)%5==0:
            import pickle
            print 'saving packet'
            s = {}
            s['rules'] = self.rules
            s['geos'] = self.geos
            s['packets']=packets
            with open('testpacket.p', 'wb') as outfile:
                pickle.dump(s, outfile)
                print 'saved packets to pickle'
            with open('testpacket.p', 'rb') as pfile:
                print len(pickle.load(pfile)['packets'])
        
        # check the packet against all rules
        verdict = firewall_handle_packet(pkt_dir, pkt, self.rules, self.geos)
        print 'verdict: '+verdict

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
            print 'not implemented'
    else:
        # check if protocol matches
        packet_protocol = get_protocol(pkt)
        rule_protocol = rule.get_protocol()
        # print 'packet: '+str(packet_protocol)+', rule: '+str(rule_protocol)
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
    verdict = 'drop'
    for rule in rules:
        if packet_matches_rule(pkt_dir, pkt, rule, geos):
            print rule
            verdict = rule.verdict
    return verdict

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

def dns_qtype(pkt):
    udp_header_start = get_ip_header_length(pkt)
    qtype = pkt[udp_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+2:udp_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+4]
    qtype = struct.unpack('!H', qtype)[0]
    return qtype

def dns_qclass(pkt):
    udp_header_start = get_ip_header_length(pkt)
    qclass = pkt[udp_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+4:udp_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+6]
    qclass = struct.unpack('!H', qclass)[0]
    return qclass

def is_dns(pkt_dir, pkt):
    # udp outgoing with dst port 53
    protocol = get_protocol(pkt)
    if pkt_dir != PKT_DIR_OUTGOING or protocol != UDP_PROTOCOL:
        # print 'is_dns: wrong dir or protocol'
        return False
    dst_port = get_udp_port(pkt, dst = True)
    if dst_port != 53:
        # print 'is_dns: wrong port'
        return False
    # exactly 1 DNS question entry
    qdcount = dns_qdcount(pkt)
    if qdcount != 1:
        # print 'is_dns: wrong qdcount'
        return False
    # qtype == 1 or qtype == 28 
    qtype = dns_qtype(pkt)
    if qtype != 1 and qtype != 28:
        # print 'is_dns: wrong qtype was '+str(qtype)
        return False
    # qclass == 1
    qclass = dns_qclass(pkt)
    if qclass != 1:
        # print 'is_dns: wrong qclass was '+str(qclass)
        return False
    return True

"""
Classes
"""
class Geo:
    def __init__(self, a, b, code):
        self.a = a
        self.b = b
        self.code = code
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
        return 0

    def matches_ip(self, ip, geoipdb):
        if self.ext_ip.lower() == 'any':
            return True
        if len(self.ext_ip) == 2:
            for geo in geoipdb:
                ip1, = struct.unpack('!L', socket.inet_aton(geo.a))
                ip2, = struct.unpack('!L', socket.inet_aton(geo.b))
                if ip >= ip1 and ip <= ip2:
                    if self.ext_ip.lower() == geo.code.lower():
                        return True
                    else:
                        return False
        rule_ip = self.ext_ip
        rule_ip = struct.unpack('!L', socket.inet_aton(rule_ip.split('/')[0]))[0]
        rule_ip = rule_ip >> self.get_mask()
        ip = ip >> self.get_mask()
        return ip == rule_ip

    def matches_port(self, port):
        if self.ext_port.lower() == 'any':
            return True
        if '-' in self.ext_port:
            p1 = self.ext_port.split('-')[0]
            p2 = self.ext_port.split('-')[1]
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
