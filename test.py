from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import pickle
from firewall import *
from helpers import *

# length of header in bytes

# hard coded constants

data = pickle.load(open('testpacket.p', 'rb'))
packets = data['packets']
rules = data['rules']
geos = data['geos']

for packet in packets:
  prot = get_protocol(packet[0])
  if prot == UDP_PROTOCOL and is_dns(packet[1],packet[0]):
    pkt = packet[0]
    pkt_dir = packet[1]

# print 'testing ip checksum'
# print 'calculated: '+str(ip_checksum(pkt))
# print 'actual: '+str(struct.unpack('!H', pkt[10:12])[0])
# print 'testing tcp checksum'
# print 'calculated: '+str(tcp_checksum(pkt))
# start = get_ip_header_length(pkt) + 16
# print 'actual: '+str(struct.unpack('!H', pkt[start:start+2])[0])

# print 'testing upd checksum'
# print 'calculated: '+str(udp_checksum(pkt))
# start = get_ip_header_length(pkt)+6
# print 'actual: '+str(struct.unpack('!H', pkt[start:start+2])[0])

def set_string(a,b,i1,i2):
  resp = a[:i1] + b + a[i2:]
  return resp

def make_tcp_response(pkt):
  'fuck this stupid ass fucking dumb project'
  return 'assmar'
resp = make_dns_response(pkt)
