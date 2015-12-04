

    # TODO: You can add more methods as you want.
    def write_to_log(self, conn, pktKey):
        hname  = re.search('Host:\s+(?P<hostname>\S+)', conn.request)
        hostname = ''
        # regex get hostname
        if hname:
            hostname = hname.group('hostname')
            if type(hostname) == tuple:
                hostname = hostname[0]
        if hostname == '':
            hostname = str(pktKey[1])
        # split the connections request data
        requestData = conn.request.split()
        method = requestData[0]
        path = requestData[1]
        version = requestData[2]
        status_code = conn.response.split()[1]

        # get size with regex
        sizeRegex = 'Content-Length:\s+(?P<objsize>\w+)'
        osizeMatch = re.search(sizeRegex, conn.response)
        osize = -1
        if osizeMatch:
            osize = osizeMatch.group('objsize')
            if type(osize) == tuple:
                osize = osize[0]
        o = [str(hostname), str(method), str(path), str(version), str(status_code), str(osize)]
        output_line = " ".join(o) + '\n'

        # log if matches rules
        for rule in self.logrules:
            if domain_match(rule.hostname, hostname):
                logfile = open('http.log', 'a')
                logfile.write(output_line)
                logfile.flush()
                break
        conn.request = ''
        conn.response = ''
        conn.flag = FIN
        self.connections[pktKey] = conn

    def assemble_http(self, pkt_dir, pkt):
        ip_hdrlen = get_ip_header_length(pkt)

        # split packet into tcp and http segments
        tcp_pkt = pkt[ip_hdrlen:]
        tcp_hdrlen = get_tcp_hdrlen(pkt)
        http_pkt = tcp_pkt[tcp_hdrlen:]

        # get seqno and ackno
        seqno = int(struct.unpack('!L', tcp_pkt[4:8])[0])
        ackno = int(struct.unpack('!L', tcp_pkt[8:12])[0])
        iport = get_tcp_internal_port(pkt_dir, pkt)
        ip_addr = get_external_ip(pkt_dir, pkt)
        pktKey = (iport, ip_addr)

        if pktKey in self.connections.keys():
            # get connection
            conn = self.connections[pktKey]
            if conn.flag  == SYN:
                if pkt_dir == PKT_DIR_INCOMING and ackno == conn.seqno + 1:
                    conn.seqno = conn.seqno + 1
                    conn.flag = SYNACK
                    self.connections[pktKey] = conn
                    return True
                else:
                    return False
            elif conn.flag == SYNACK:
                if pkt_dir == PKT_DIR_OUTGOING and seqno == conn.seqno:
                    conn.flag = ACK
                    self.connections[pktKey] = conn
            elif pkt_dir == PKT_DIR_OUTGOING and seqno == conn.seqno:
                if pkt_dir == conn.pkt_dir:
                    conn.request = conn.request + http_pkt
                    breakRegex = '\r\n\r\n'
                    if re.search(breakRegex, conn.request):
                        conn.pkt_dir = PKT_DIR_INCOMING
                    conn.seqno = seqno + len(http_pkt)
                    self.connections[pktKey] = conn
                return True
            elif pkt_dir == PKT_DIR_INCOMING and ackno == conn.seqno:
                if pkt_dir == conn.pkt_dir:
                    write = False
                    in_data = conn.response + http_pkt
                    endRegex = "Host:\s+\S+.*Content-Length:\s+\w+|Content-Length:\s+\w+.*Host:\s+\S+|\r\n\r\n"
                    if re.search(endRegex, in_data):
                        # switch direction of packets + write to output file
                        conn.pkt_dir = PKT_DIR_OUTGOING
                        write = True
                    conn.seqno = ackno + len(http_pkt)
                    conn.response = in_data
                    self.connections[pktKey] = conn
                    if write and conn.flag == ACK:
                        self.write_to_log(conn, pktKey)
                return True
            elif (pkt_dir == PKT_DIR_OUTGOING and conn.seqno > seqno) or (pkt_dir == PKT_DIR_INCOMING and conn.seqno > ackno):
                return True
            else:
                return False
        else:
            conn = Connection(seqno, pkt_dir, '', '', SYN)
            self.connections[pktKey] = conn
            return True

