from firewall import *
import struct
import socket
import pickle

data = pickle.load(open('testpacket.p', 'rb'))
packets = data['packets']
rules = data['rules']
geos = data['geos']

print packets

pkt = packets[0][0]
print get_protocol(pkt)
print get_udp_port(pkt)
print dns_qdcount(pkt)
print dns_qtype(pkt)
print dns_qclass(pkt)

# print 'testing CIDR'
# ip = '8.8.8.8/16'
# ip2 = '8.8.8.10/16'
# b = socket.inet_aton(ip.split('/')[0])
# b, = struct.unpack('!L', b)
# b = b >> int(ip.split('/')[1])
# b2 = socket.inet_aton(ip2.split('/')[0])
# b2, = struct.unpack('!L',b2)
# b2 = b2  >> int(ip2.split('/')[1])
# print b
# print b2
print 'rule testing stuff'
# 31.6.16.0 31.6.16.255 GB

ip = '31.6.36.15'
ip, = struct.unpack('!L', socket.inet_aton(ip))
rule = ProtocolRule('pass', 'TCP', 'gb', '80')

print rule.ext_ip
print rule.matches_ip(ip, geos)
