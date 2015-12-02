

print is_dns(pkt_dir,pkt)

print 'testing domain match'
print domain_match('*.oogle.com', 'www.google.com')

print 'ip matching'
ip1 = '8.8.8.8'
ip1 = struct.unpack('!L', socket.inet_aton(ip1))[0]
rule = ProtocolRule('pass', 'tcp', '8.8.8.4', '69')
print rule.matches_ip(ip1, geos)

