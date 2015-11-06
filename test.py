from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
import struct
import socket
import time
import pickle
from firewall import *

# length of header in bytes

# hard coded constants

data = pickle.load(open('testpacket.p', 'rb'))
packets = data['packets']
rules = data['rules']
geos = data['geos']

""" main stuff here """
pkt = packets[0][0]
pkt_dir = packets[0][1]

print is_dns(pkt_dir,pkt)

print 'testing domain match'
print domain_match('*.oogle.com', 'www.google.com')
