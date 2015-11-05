

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
print struct.unpack('!L', socket.inet_aton(geos[0].a))[0]
print struct.unpack('!L', socket.inet_aton(geos[0].b))[0]

# # try to use rules
# print 'testing rules'
# for rule in rules:
        # if rule.is_dns():
                # print rule.verdict
                # print rule.domain_name
        # else:
                # print rule.verdict
                # print rule.protocol
                # print rule.ext_ip
                # print rule.ext_port
        # print rule
