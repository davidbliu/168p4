#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import re

# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

# hard coded constants

VERDICTS = ['drop', 'pass', 'deny', 'log']

UDP_PROTOCOL = 17
TCP_PROTOCOL = 6
ICMP_PROTOCOL = 1

UDP_HEADER_LEN = 8
DNS_HEADER_LEN = 12

SYN = 'syn'
SYNACK = 'synack'
ACK = 'ack'
FIN = 'fin'

def get_method(resp):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'UPDATE']
    for method in methods:
        if method in resp:
            return method
    return 'NONE'

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []
        self.logrules = []
        self.connections = {}
        self.assemblies = {}
        # add in rules to self.rules
        with open(config['rule'], 'r') as rulesfile:
            lines = [x.strip() for x in rulesfile]
            lines = [x for x in lines if x != '']
            lines = [x.split() for x in lines if x.split()[0] in VERDICTS]
            rules = []
            for x in lines:
                rule = None
                if x[0].lower() == 'log':
                    logrule = LogRule(x[2])
                    self.logrules.append(logrule)
                elif x[1].lower() == 'dns':
                    rule = DNSRule(x[0], x[2])
                else:
                    rule = ProtocolRule(x[0], x[1], x[2], x[3])
                if rule != None:
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

        # if the packet matches a p4, stop this function
        # the handle_p4_packet method may also send packets + log
        if self.handle_p4_packet(pkt_dir, pkt):
            return
        verdict = firewall_handle_packet(pkt_dir, pkt, self.rules, self.geos)
        verdict = verdict.lower()
        if verdict == 'pass' and pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif verdict == 'pass' and pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def pass_packet(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        else:
            self.iface_ext.send_ip_packet(pkt)

    def handle_p4_packet(self, pkt_dir, pkt):
        # handle if log rule matches
        if is_http(pkt_dir, pkt):
            pass_pkt = self.ass_pkt(pkt_dir, pkt) 
            if pass_pkt:
                self.pass_packet(pkt_dir, pkt)
        # handle TCP and DNS 
        rule = get_matching_p4_rule(pkt_dir, pkt, reversed(self.rules), self.geos)
        if rule == None:
            return False
        if rule.is_dns() and pkt_dir == PKT_DIR_OUTGOING:
            resp = make_dns_response(pkt)
            self.iface_int.send_ip_packet(resp)
            return True
        elif rule.verdict == 'deny' and get_protocol(pkt) == TCP_PROTOCOL: 
            resp = make_tcp_response(pkt)
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_int.send_ip_packet(resp)
            else:
                self.iface_ext.send_ip_packet(resp)
            return True
        else:
            print 'matches some OTHER RULE probably LOG'
        return False
    
    def ass_pkt(self, pkt_dir, pkt):
        ip_hdrlen = get_ip_header_length(pkt)
        tcp_pkt = pkt[ip_hdrlen:]
        tcp_hdrlen = get_tcp_hdrlen(pkt)
        http_pkt = tcp_pkt[tcp_hdrlen:]

        # get seqno and ackno
        seqno = int(struct.unpack('!L', tcp_pkt[4:8])[0])
        ackno = int(struct.unpack('!L', tcp_pkt[8:12])[0])
        iport = get_tcp_internal_port(pkt_dir, pkt)
        ip_addr = get_external_ip(pkt_dir, pkt)
        key = (iport, ip_addr, pkt_dir)
        passPacket = True

        if key in self.assemblies.keys():
            data = self.assemblies[key]
            eseqno = data[0]
            if eseqno == seqno:
                http_data = data[2] + http_pkt
                self.assemblies[key] = (seqno + len(http_pkt), ackno, http_data)
            elif seqno > eseqno:
                passPacket = False
            # check if request and response headers are complete
            ikey = (key[0], key[1], PKT_DIR_INCOMING)
            if key[2] == PKT_DIR_INCOMING:
                ikey = (key[0], key[1], PKT_DIR_OUTGOING)
            if ikey in self.assemblies.keys():
                http2 = self.assemblies[ikey][2]
                http1 = self.assemblies[key][2]
                if '\r\n\r\n' in http1 and '\r\n\r\n' in http2:
                    try:
                        if pkt_dir == PKT_DIR_OUTGOING:
                            resp = http1 + http2
                            resp2 = http2 + http1
                        else:
                            resp = http2 + http1
                            resp2 = http1 + http2
                        # print 'first line of resp'
                        fline =  resp.split('\n')[0]
                        clength = '-1'
                        if 'Content-Length' in resp:
                            clength = resp.split('Content-Length: ')[1].split('\n')[0]
                        if 'Host: ' in resp:
                            hname = resp.split('Host: ')[1].split('\n')[0].strip()
                        else:
                            hname = 'some ip'
                        stuff = fline.split(' ')
                        path = '/'
                        if len(stuff) > 1:
                            path = stuff[1]
                        method = stuff[0]
                        version = 'version'
                        hsplit = resp2.split('\n')[0].split(' ')
                        status_code = hsplit[1]
                        version  = hsplit[0]
                        logentry =  hname.strip() + ' ' + method.strip() + ' ' + path.strip() + ' ' + version.strip() + ' ' + status_code.strip() + ' ' + clength.strip() + '\n'
                        for rule in self.logrules:
                            if domain_match(rule.hostname, hname):
                                # log it also
                                f = open('http.log', 'a')
                                f.write(logentry)
                                # print logentry
                                f.flush()
                                break
                    except:
                        print 'some error occurrred'
                    # remove it from assemblies dict
                    del self.assemblies[key]
                    del self.assemblies[ikey]

        else:
            self.assemblies[key] = (seqno+1, ackno, '')
        return passPacket

# TODO: You may want to add more classes/functions as well.

""" PROJECT 4
"""


def invkey(key):
    if key[2] == PKT_DIR_INCOMING:
        return PKT_DIR_OUTGOING
    return PKT_DIR_INCOMING

def is_http(pkt_dir, pkt):
    if get_protocol(pkt) == TCP_PROTOCOL:
        incoming_port = get_tcp_internal_port(pkt_dir, pkt)
        outgoing_port = get_tcp_external_port(pkt_dir, pkt)
        return incoming_port == 80 or outgoing_port == 80
    return False

def get_matching_p4_rule(pkt_dir, pkt, rules, geos):
    for rule in rules:
        if packet_matches_rule(pkt_dir, pkt, rule, geos) and (rule.verdict == 'deny' or rule.verdict == 'log'):
            return rule
    return None

"""
Everything Here was added by me and is highly likely wrong
"""

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
        if rule.verdict != 'deny' and packet_matches_rule(pkt_dir, pkt, rule, geos):
            verdict = rule.verdict
    return verdict

def domain_match(rule_domain, pkt_domain):
    rsplit = rule_domain.split('.')[::-1]
    psplit = pkt_domain.split('.')[::-1]
    for i in range(len(psplit)):
        p = psplit[i]
        r = rsplit[i]
        if r == '*':
            print pkt_domain + ' matches '+rule_domain
            return True
        if r != p:
            return False
    print pkt_domain + ' matches '+rule_domain
    return True
        
    # if rule_domain[0] == '*':
        # rd = rule_domain[2:]
        # pd = pkt_domain
        # while len(pd) > 0 and pd[0] != '.':
            # pd = pd[1:]
        # pd = pd[1:]
        # if pd == rd:
            # return True
    # else:
        # if rule_domain == pkt_domain:
            # return True
    # return False

"""
methods
"""

# return length in bytes
def get_ip_header_length(pkt):
    ihl = pkt[0:1]
    ihl = struct.unpack('!B', ihl)[0]
    ihl =  ihl&0xF
    return ihl * 4

def get_tcp_hdrlen(pkt):
    ip_hdrlen = get_ip_header_length(pkt)
    tcp = pkt[ip_hdrlen:]
    leng = ((struct.unpack('!B', tcp[12])[0] & 0xF0)>>4)*4
    return leng
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
def get_tcp_internal_port(pkt_dir, pkt):
    pkt_ip_hdrlen = get_ip_header_length(pkt)
    if pkt_dir == PKT_DIR_INCOMING:
        # use destination
        ext_port = struct.unpack('!H', pkt[pkt_ip_hdrlen+2:pkt_ip_hdrlen+2+2])[0]
    if pkt_dir == PKT_DIR_OUTGOING:
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

def dns_qname(pkt):
    i1 = get_ip_header_length(pkt)+UDP_HEADER_LEN+DNS_HEADER_LEN
    start = i1
    finished = False
    numbytes = struct.unpack('!B', pkt[start:start+1])[0]
    qname = ''
    while not finished:
        while numbytes > 0:
            numbytes -= 1
            start = start+1
            qname += chr(struct.unpack('!B', pkt[start:start+1])[0])
        start += 1
        numbytes = struct.unpack('!B', pkt[start:start+1])[0]
        if numbytes == 0:
            finished = True
        else:
            qname += '.'
    i2 = start + 1
    return pkt[i1:i2]
def dns_qname_qtype_qclass(pkt):
    start = get_ip_header_length(pkt)+UDP_HEADER_LEN+DNS_HEADER_LEN
    finished = False
    numbytes = struct.unpack('!B', pkt[start:start+1])[0]
    qname = ''
    while not finished:
        while numbytes > 0:
            numbytes -= 1
            start = start+1
            qname += chr(struct.unpack('!B', pkt[start:start+1])[0])
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
        self.verdict = verdict.lower()
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
        self.verdict = verdict.lower()
        self.domain_name = domain_name

    def is_dns(self):
        return True

    def __repr__(self):
        return self.verdict

# project 4 stuff
class LogRule:
    def __init__(self, hn):
        self.hostname = hn

class Connection:
    def __init__(self, seq, pd, i, o, est):
        self.seqno = seq
        self.pkt_dir = pd
        self.request = i
        self.response = o
        self.flag = est

def get_checksum(data):
  size = len(data)
  cksum = 0
  pointer = 0
  while size > 1:
    cksum += struct.unpack('!H', data[pointer:pointer+2])[0] 
    size -= 2
    pointer += 2
  if size: 
    cksum += struct.unpack('!B', data[pointer])[0]
  cksum = (cksum >> 16) + (cksum & 0xffff)
  cksum += (cksum >> 16)
  return (~cksum) & 0xFFFF

def tcp_checksum(pkt):
  ip_hdrlen = get_ip_header_length(pkt)
  data = ''
  data += pkt[12:20] # ip src and dest
  data += struct.pack('!B', 0) # reserved (0)
  data += pkt[9:10] # protocol
  data += struct.pack('!H', len(pkt)-ip_hdrlen) # TCP Length
  data += pkt[ip_hdrlen:ip_hdrlen+16]
  data += struct.pack('!H', 0) # zero for tcp checkusm
  data += pkt[ip_hdrlen+18:len(pkt)]
  size = len(data)
  return get_checksum(data)

def ip_checksum(pkt):
  ip_hdrlen = get_ip_header_length(pkt)
  data = ''
  data += pkt[:10]
  data += pkt[12:ip_hdrlen]
  size = get_ip_header_length(pkt)
  return get_checksum(data)

def udp_checksum(pkt):
  ip_hdrlen = get_ip_header_length(pkt)
  data = ''
  data += pkt[12:20]
  data += struct.pack('!B', 0)
  data += pkt[9:10]
  data += pkt[ip_hdrlen+4:ip_hdrlen+6]
  data += pkt[ip_hdrlen:ip_hdrlen+6]
  data += pkt[ip_hdrlen+UDP_HEADER_LEN:len(pkt)]
  return get_checksum(data)


def set_string(a,b,i1,i2):
  resp = a[:i1] + b + a[i2:]
  return resp

def make_tcp_response(pkt):
    ip_hdrlen = get_ip_header_length(pkt)
    # create IP header
    ip_hdr = pkt[:ip_hdrlen]
    ip_flags = struct.unpack('!B', pkt[6])[0]
    ip_flags = ip_flags & 0b00011111 # set ip flags to 0
    # set ihl and version
    ihl_str = struct.unpack('!B', ip_hdr[0])
    ip_hdr = set_string(ip_hdr, struct.pack('!B', 0), 1, 2) # TOS = 0
    ip_hdr = set_string(ip_hdr, struct.pack('!B', ip_flags), 6, 7) # ip flags = 0
    ip_hdr = set_string(ip_hdr, pkt[12:16], 16, 20) # switch src dst
    ip_hdr = set_string(ip_hdr, pkt[16:20], 12, 16) # switch src dst
    # create TCP header
    tcp_hdr = pkt[ip_hdrlen: ip_hdrlen + 20]
    seqno = struct.unpack('!L', pkt[ip_hdrlen + 4: ip_hdrlen + 8])[0] # old seqno
    ackno = seqno + 1
    offset = struct.unpack('!B', tcp_hdr[12])[0]
    offset = offset & 0b00001111 
    offset = offset | 0b01010000 # set offset = 5
    tcp_hdr = set_string(tcp_hdr, struct.pack('!L', 0), 4, 8) # seqnum = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!L', ackno), 8, 12) # ackno = oldseqno + 1o
    tcp_hdr = set_string(tcp_hdr, struct.pack('!B', offset), 12, 13) # offset = 5
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', 0), 14, 16) # window = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', 0), 18, 20) # urgent = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!B', 20), 13, 14) # RST flag = 4
    tcp_hdr = set_string(tcp_hdr, pkt[ip_hdrlen:ip_hdrlen+2], 2, 4) # switch src dst
    tcp_hdr = set_string(tcp_hdr, pkt[ip_hdrlen+2:ip_hdrlen+4], 0, 2) # switch src dst
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', tcp_checksum(ip_hdr + tcp_hdr)), 16, 18) # checksum
    # ip hdr length and checksum
    ip_hdr = set_string(ip_hdr, struct.pack('!H', len(ip_hdr+tcp_hdr)), 2, 4) # total length
    ip_hdr = set_string(ip_hdr, struct.pack('!H', ip_checksum(ip_hdr)), 10, 12) # checksum 
    return ip_hdr + tcp_hdr

def make_dns_response(pkt):
  ip_hdrlen = get_ip_header_length(pkt)
  # construct ip header (20bytes)
  ip_hdr = pkt[:ip_hdrlen]
  # switch src and dst
  ip_hdr = set_string(ip_hdr, pkt[12:16], 16, 20)
  ip_hdr = set_string(ip_hdr, pkt[16:20], 12, 16)
  # construct udp header (8bytes)
  udp_hdr = pkt[ip_hdrlen:ip_hdrlen + 8]
  # switch src and dst port
  udp_hdr = set_string(udp_hdr, pkt[ip_hdrlen:ip_hdrlen+2], 2, 4)
  udp_hdr = set_string(udp_hdr, pkt[ip_hdrlen+2:ip_hdrlen+4], 0, 2)
  # construct dns header (12bytes)
  dns_hdr = pkt[ip_hdrlen+8:ip_hdrlen+8+12]
  line2 = struct.unpack('!H', dns_hdr[2:4])[0]
  line2 = line2 | 0b1000000000000000 # set QR = 1
  line2 = line2 & 0b1000011111111111 # set opcode = 0
  line2 = line2 & 0b1111110111111111 # set TC = 0
  line2 = line2 & 0b1111111111110000 # set rcode = 0
  dns_hdr = set_string(dns_hdr, struct.pack('!H', line2), 2, 4) # set second line
  dns_hdr = set_string(dns_hdr, struct.pack('!H', 1), 6, 8) # anscount = 1
  dns_hdr = set_string(dns_hdr, struct.pack('!H', 0), 8, 10) # nscount = 0
  dns_hdr = set_string(dns_hdr, struct.pack('!H', 0), 10, 12) # arcount = 0
  # construct dns data
  dns_data = pkt[ip_hdrlen+20:]
  # construct dns answer
  answer = ''
  qname, qtype, qclass = dns_qname_qtype_qclass(pkt)
  answer += dns_qname(pkt)
  answer += struct.pack('!H', 1) # type
  answer += struct.pack('!H', 1) # class
  answer += struct.pack('!L', 100) # ttl
  answer += struct.pack('!H', 4) # length
  answer += socket.inet_aton('169.229.49.130')
  dns_data = dns_data + answer 
  # loose ends
  ## ip header length and checksum
  ip_hdr = set_string(ip_hdr, struct.pack('!H', len(ip_hdr + udp_hdr + dns_hdr + dns_data)), 2, 4)
  ip_hdr = set_string(ip_hdr, struct.pack('!H', ip_checksum(ip_hdr)), 10, 12)
  ## udp length
  udp_len = len(udp_hdr + dns_hdr + dns_data)
  udp_hdr = set_string(udp_hdr, struct.pack('!H', udp_len) , 4, 6)
  ## udp header checksum
  udp_hdr = set_string(udp_hdr, struct.pack('!H', udp_checksum(ip_hdr + udp_hdr + dns_hdr + dns_data)), 6, 8)
  return ip_hdr + udp_hdr + dns_hdr + dns_data

# eo4
if __name__=='__main__':
    print 'firewall.py'
