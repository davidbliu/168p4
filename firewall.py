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
DNS_PROTOCOL = 17
TCP_PROTOCOL = 6

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []

        # TODO: Load the firewall rules (from rule_filename) here.
        # print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                # config['rule']

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

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pass

        # save the packet in pickle
        if True:
            import pickle
            s = {}
            s['rules'] = self.rules
            s['geos'] = self.geos
            s['pkt_dir'] = pkt_dir
            s['pkt']=pkt
            with open('testpacket.p', 'wb') as outfile:
                pickle.dump(s, outfile)
                print 'saved packet to pickle'
        # need src ip, dst ip, src port, ?
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        print str(ipid)+'<-- is ipid'
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
            # source is outside
        else:
            # destination is outside
            dir_str = 'outgoing'

        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))


        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
        print 'ihl is this'
        print ihl
        print 'ihl is this'
        print ihl

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.

"""
Everything Here was added by me and is highly likely wrong
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
class ProtocolRule:
    def __init__(self, verdict = '', protocol='', ext_ip = None, ext_port = None):
        self.verdict = verdict
        self.protocol = protocol
        self.ext_ip = ext_ip
        self.ext_port = ext_port

    def is_dns(self):
        return False

    def __repr__(self):
        return self.verdict

class DNSRule:
    def __init__(self, verdict = '', domain_name=''):
        self.verdict = verdict
        self.domain_name = domain_name

    def is_dns(self):
        return True

    def __repr__(self):
        return self.verdict

if __name__=='__main__':
    print 'firewall.py'
