
# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import pickle
from firewall import *


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

def make_tcp_response(pkt):
  return pkt

def set_string(a,b,i1,i2):
  resp = a[:i1] + b + a[i2:]
  return resp

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
  answer += qname
  answer += struct.pack('!H', 1) # type
  answer += struct.pack('!H', 1) # class
  answer += struct.pack('!L', 1) # ttl
  answer += struct.pack('!H', 4) # length
  answer += socket.inet_aton('169.229.49.130')
  dns_data = dns_data + answer 
   
  # loose ends
  ## ip header length and checksum
  ip_hdr = set_string(ip_hdr, struct.pack('!H', len(ip_hdr + udp_hdr + dns_hdr + dns_data)), 2, 4)
  ip_hdr = set_string(ip_hdr, struct.pack('!H', ip_checksum(ip_hdr)), 10, 12)
  ## udp header checksum
  udp_hdr = set_string(udp_hdr, struct.pack('!H', udp_checksum(udp_hdr + dns_hdr + dns_data)), 6, 8)
  
  return ip_hdr + udp_hdr + dns_hdr + dns_data
