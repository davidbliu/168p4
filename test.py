from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import pickle
from firewall import *

UDP_HEADER_LEN = 8
DNS_HEADER_LEN = 12
# length of header in bytes
def get_ip_header_length(pkt):
  ihl = pkt[0:1]
  ihl = struct.unpack('!B', ihl)[0]
  ihl =  ihl&0xF
  return ihl * 4

def is_dns(pkt_dir, pkt):
  # udp outgoing with dst port 53
  protocol = struct.unpack('!B', pkt[9:10])[0]
  if pkt_dir != PKT_DIR_OUTGOING or protocol != DNS_PROTOCOL:
    print 'is_dns: wrong dir or protocol'
    return False
  dns_header_start = get_ip_header_length(pkt)
  dst_port = pkt[dns_header_start+2:dns_header_start+4]
  dst_port = struct.unpack('!H', dst_port)[0]
  if dst_port != 53:
    print 'is_dns: wrong port'
    return False
  # exactly 1 DNS question entry
  qdcount = pkt[dns_header_start+UDP_HEADER_LEN+4:dns_header_start+UDP_HEADER_LEN+4+2]
  qdcount = struct.unpack('!H', qdcount)[0]
  if qdcount != 1:
    print 'is_dns: wrong qdcount'
    return False
  # qtype == 1 or qtype == 28 
  qtype = pkt[dns_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+2:dns_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+4]
  qtype = struct.unpack('!H', qtype)[0]
  if qtype != 1 and qtype != 28:
    print 'is_dns: wrong qtype was '+str(qtype)
    return False
  # qclass == 1
  qclass = pkt[dns_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+4:dns_header_start+UDP_HEADER_LEN+DNS_HEADER_LEN+6]
  qclass = struct.unpack('!H', qclass)[0]
  if qclass != 1:
    print 'is_dns: wrong qclass was '+str(qclass)
    return False
  return True


# hard coded constants
VERDICTS = ['drop', 'pass']

data = pickle.load(open('testpacket.p', 'rb'))
pkt = data['pkt']


# check for dns packet'
print 'is_dns'
print is_dns(PKT_DIR_OUTGOING, pkt)

# get packet header length
print 'header length'
ihl = pkt[0:1]
ihl = struct.unpack('!B', ihl)[0]
ihl =  ihl&0xF
print ihl

# get total length of packet
print 'getting total length'
total_length = pkt[2:4]
total_length = struct.unpack('!H', total_length)[0]
print total_length
print len(pkt)

# get geos
print 'testing geos'
geos = data['geos']
print struct.unpack('!L', socket.inet_aton(geos[0].a))[0]
print struct.unpack('!L', socket.inet_aton(geos[0].b))[0]

# get src ip and destination
print' src ip and destination'
src_ip = socket.inet_ntoa(pkt[12:16])
dst_ip = socket.inet_ntoa(pkt[16:20])
print src_ip
print dst_ip
