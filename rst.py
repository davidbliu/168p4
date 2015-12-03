
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import pickle
from firewall import *


# hard coded constants

data = pickle.load(open('testpacket.p', 'rb'))
packets = data['packets']
rules = data['rules']
geos = data['geos']

for packet in packets:
  prot = get_protocol(packet[0])
  if prot == TCP_PROTOCOL:# and is_dns(packet[1],packet[0]):
    pkt = packet[0]
    pkt_dir = packet[1]

print pkt
def make_tcp_resonse(pkt):
    ip_hdrlen = get_ip_header_length(pkt)
    # create IP header
    ip_hdr = pkt[:ip_hdrlen]
    ip_flags = struct.unpack('!B', pkt[6])[0]
    ip_flags = ip_flags & 0b00011111 # set ip flags to 0
    ip_hdr = set_string(ip_hdr, struct.pack('!B', 0), 1, 2) # TOS = 0
    ip_hdr = set_string(ip_hdr, struct.pack('!B', ip_flags), 6, 7) # ip flags = 0
    ip_hdr = set_string(ip_hdr, struct.pack('!H', ip_hdrlen + 20), 2, 4) # total length
    ip_hdr = set_string(ip_hdr, pkt[12:16], 16, 20) # switch src dst
    ip_hdr = set_string(ip_hdr, pkt[16:20], 12, 16) # switch src dst
    ip_hdr = set_string(ip_hdr, struct.pack('!H', ip_checksum(ip_hdr)), 10, 12) # checksum
    # create TCP header
    tcp_hdr = pkt[ip_hdrlen: ip_hdrlen + 20]
    seqno = struct.unpack('!L', pkt[ip_hdrlen + 4: ip_hdrlen + 8])[0] # old seqno
    ackno = seqno + 1
    offset = struct.unpack('!B', tcp_hdr[12])[0]
    offset = offset & 0b00001111 # set offset = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!L', 0), 4, 8) # seqnum = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!L', ackno), 8, 12) # ackno = oldseqno + 1o
    tcp_hdr = set_string(tcp_hdr, struct.pack('!B', offset), 12, 13) # offset = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', 0), 14, 16) # window = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', 0), 18, 20) # urgent = 0
    tcp_hdr = set_string(tcp_hdr, struct.pack('!B', 4), 13, 14) # RST flag = 4
    tcp_hdr = set_string(tcp_hdr, pkt[ip_hdrlen:ip_hdrlen+2], 2, 4) # switch src dst
    tcp_hdr = set_string(tcp_hdr, pkt[ip_hdrlen+2:ip_hdrlen+4], 0, 2) # switch src dst
    tcp_hdr = set_string(tcp_hdr, struct.pack('!H', tcp_checksum(ip_hdr + tcp_hdr)), 16, 18) # checksum
    return ip_hdr + tcp_hdr
print len(resp)

