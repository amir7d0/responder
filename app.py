from Headers import *

class ARP_responder:

    def __init__(self,packet):
        arp = ARP(packet[14:])
        self.opcode = 2
        self.sender_mac = binascii.unhexlify(arp.target_hardware_address.replace(':', ''))
        self.sender_ip = struct.unpack("!I", socket.inet_aton(arp.target_protocol_addr))[0]
        self.target_mac = binascii.unhexlify(arp.sender_hardware_address.replace(':', ''))
        self.target_ip = struct.unpack("!I", socket.inet_aton(arp.sender_protocol_addr))[0]
        self.dest_ip = arp.sender_protocol_addr

        self.header = struct.pack("! H H  B B H 6s L 6s L", arp.hardware_type,arp.protocol_type,arp.hardware_addr_len,arp.protocol_addr_len,
                                 self.opcode,self.sender_mac,self.sender_ip,self.target_mac,self.target_ip)

    def send_to(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.sendto(self.header, (self.dest_ip, 0))


class ICMP_responder:

    def __init__(self,packet):

        ipv4 = IPv4(packet[14:])
        icmp = ICMP(ipv4.data)


        #   Create IP header
        version = 4
        header_length = 5
        version_header_length = (version << 4) + header_length
        tos = 0  # type of service
        total_length = 20 + 8
        ID = 0xabab
        flags_fragment_offset = 0
        ttl = 64
        protocol = 6  # TCP
        header_checksum = 0
        self.source_address = struct.unpack("!I", socket.inet_aton(ipv4.destination_address))[0]
        self.destination_address = struct.unpack("!I", socket.inet_aton(ipv4.source_address))[0]
        self.dest_ip = ipv4.source_address
        tmp_ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol, header_checksum,
                                    self.source_address,
                                    self.destination_address)
        ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol,
                                self.cal_checksum(tmp_ip_header),self.source_address, self.destination_address)

        # Create ICMP header
        self.icmp_type = 0
        self.code = 0
        self.checksum = 0
        self.id = 1
        self.sequence = 1

        tmp_icmp_header = struct.pack("! B B H H H", self.icmp_type, self.code, self.checksum, self.id, self.sequence)
        icmp_header = struct.pack("! B B H H H", self.icmp_type, self.code, self.cal_checksum(tmp_icmp_header), self.id, self.sequence)

        self.header = ip_header + icmp_header


    def send_to(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.sendto(self.header, (self.dest_ip, 0))


    def cal_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff

        return s


class DNS_responder_TCP:

    def __init__(self, packet):
        ipv4 = IPv4(packet[14:])
        tcp = TCP(ipv4.data)
        dns = DNS(tcp.data)
        #   Create IP header
        version = 4
        header_length = 5
        version_header_length = (version << 4) + header_length
        tos = 0  # type of service
        total_length = 20 + 20 + 12 + 30
        ID = 0xabab
        flags_fragment_offset = 0
        ttl = 64
        protocol = 6
        header_checksum = 0
        self.source_address = struct.unpack("!I", socket.inet_aton(ipv4.destination_address))[0]
        self.destination_address = struct.unpack("!I", socket.inet_aton(ipv4.source_address))[0]
        self.dest_ip = ipv4.source_address
        tmp_ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol, header_checksum,
                                    self.source_address,
                                    self.destination_address)
        ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol,
                                self.cal_checksum(tmp_ip_header), self.source_address, self.destination_address)

        # Create TCP header
        src_port = tcp.dest_port
        dest_port = tcp.src_port
        sequence = 10
        acknowledgment = 0

        window = 250
        checksum = 0
        urgent = 0
        offset = 5
        Reserved = NS = CWR = ECE = URG = PSH = RST = 0
        ACK = SYN = FIN = 0

        flags = (ACK << 4) + (PSH << 3) + (RST << 2) + (SYN << 1) + FIN
        offset_reserved_flag = (offset << 12) + flags

        tmp_tcp_header = struct.pack('! H H L L H H H H', src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, window, checksum, urgent)
        tmp_header = struct.pack("!L L B B H", self.source_address, self.destination_address, 0, 6, len(tmp_tcp_header))  # check sum = 0, proto = 6
        H = tmp_header + tmp_tcp_header
        tcp_header = struct.pack('! H H L L H H H H', src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, window, self.cal_checksum(H), urgent)


        # Create DNS header
        self.id = 123
        self.question_count = 0
        self.answer_count = 1
        self.name_server_count = 0
        self.additional_record_count = 0
        self.opcode = 4
        self.QR = 1
        self.flags_codes = (self.opcode << 11) + (self.QR << 15)

        name = 'www.google.com'
        name = b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00'
        type = 1
        clas = 1
        ttl = 165
        datalength = 4
        address = struct.unpack("!I", socket.inet_aton('108.187.122.147'))[0]

        dns_header = struct.pack('! H H H H H H', self.id, self.flags_codes, self.question_count, self.answer_count, self.name_server_count, self.additional_record_count)
        dns_response = struct.pack('!16s H H L H L', name, type, clas, ttl, datalength, address)
        # dns_response = b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\xa5\x00\x04\x6c\xb1\x7a\x93'

        self.header = ip_header + tcp_header + dns_header + dns_response

    def send_to(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.sendto(self.header, (self.dest_ip, 0))

    def cal_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff

        return s


class DNS_responder_UDP:

    def __init__(self, packet):
        ipv4 = IPv4(packet[14:])
        udp = UDP(ipv4.data)
        dns = DNS(udp.data)
        #   Create IP header
        version = 4
        header_length = 5
        version_header_length = (version << 4) + header_length
        tos = 0  # type of service
        total_length = 20 + 8 + 12 + 30
        ID = 0xabab
        flags_fragment_offset = 0
        ttl = 64
        protocol = 17
        header_checksum = 0
        self.source_address = struct.unpack("!I", socket.inet_aton(ipv4.destination_address))[0]
        self.destination_address = struct.unpack("!I", socket.inet_aton(ipv4.source_address))[0]
        self.dest_ip = ipv4.source_address
        tmp_ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol, header_checksum,
                                    self.source_address,
                                    self.destination_address)
        ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol,
                                self.cal_checksum(tmp_ip_header), self.source_address, self.destination_address)

        # Create UDP header
        src_port = udp.dest_port
        dest_port = udp.src_port
        length = 50
        checksum = 0


        tmp_udp_header = struct.pack('! H H H H', src_port, dest_port, length,checksum)
        tmp_header = struct.pack("!L L B B H", self.source_address, self.destination_address, 0, 17, len(tmp_udp_header))  # check sum = 0, proto = 17
        H = tmp_header + tmp_udp_header
        udp_header = struct.pack('! H H H H', src_port, dest_port, length, self.cal_checksum(H))

        # Create DNS header
        self.id = 123
        self.question_count = 0
        self.answer_count = 1
        self.name_server_count = 0
        self.additional_record_count = 0
        self.opcode = 4
        self.QR = 1
        self.flags_codes = (self.opcode << 11) + (self.QR << 15)

        name = 'www.google.com'
        name = b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00'
        type = 1
        clas = 1
        ttl = 165
        datalength = 4
        address = struct.unpack("!I", socket.inet_aton('108.187.122.147'))[0]

        dns_header = struct.pack('! H H H H H H', self.id, self.flags_codes, self.question_count, self.answer_count, self.name_server_count, self.additional_record_count)
        dns_response = struct.pack('!16s H H L H L', name, type, clas, ttl, datalength, address)
        #dns_response = b'\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\xa5\x00\x04\x6c\xb1\x7a\x93'

        self.header = ip_header + udp_header + dns_header + dns_response

    def send_to(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.sendto(self.header, (self.dest_ip, 0))

    def cal_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff

        return s



# Pcap_header_format = '@ I H H i I I I '
# Global Header Values
PCAP_MAGICAL_NUMBER = 0xa1b2c3d4
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

class Pcap:

    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER,
                                         PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))


    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


if __name__=='__main__':
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        while True:

            raw_data, addr = conn.recvfrom(65535)

            eth = Ethernet(raw_data)

            if (eth.proto == 0x0806):

                arp = ARP(eth.data)
                if arp.opcode == 1:
                    print('\n\n' + "="*100 + '\n')
                    print(f' Ethernet Frame: \t\t\t\t\t\t {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}')

                    ether_type = 'ARP (0x0806)'
                    print('\t - ' + 'Destination: {}, Source: {}, Type: {}'.format(eth.dest_mac, eth.src_mac, ether_type))

                    print('\t - ' + "Address Resolution Protocol (request):")
                    h_type = arp.hardware_type
                    if h_type == 1:
                        h_type = 'Ethernet (1)'

                    print(
                        '\t\t - ' + 'Hardware type: {}, Protocol type: {}'.format(
                            h_type, hex(arp.protocol_type)))
                    print(
                        '\t\t - ' + 'Hardware size: {}, Protocol size: {}, Opcode: {}'.format(arp.hardware_addr_len, arp.protocol_addr_len,
                                                                                              arp.opcode))
                    print('\t\t - ' + 'Sender MAC address: {}, Sender IP address: {}'.format(arp.sender_hardware_address,
                                                                                             arp.sender_protocol_addr))
                    print('\t\t - ' + 'Target MAC address: {}, Target IP address: {}'.format(
                        arp.target_hardware_address,
                        arp.target_protocol_addr))

                    pcap.write(raw_data)
                    arp_responder = ARP_responder(raw_data)
                    arp_responder.send_to()





            if (eth.proto == 0x800):


                ipv4 = IPv4(eth.data)

                if ipv4.protocol == 1 :
                    icmp = ICMP(ipv4.data)

                    if icmp.code == 0 and icmp.icmp_type == 8:
                        print("-----------------------------------------------------------------------------------------------------\n")
                        print(' Ethernet Frame: ')

                        ether_type = 'IPv4 (0x0800)'
                        print('\t - ' + 'Destination: {}, Source: {}, Type: {}'.format(eth.dest_mac, eth.src_mac, ether_type))

                        print('\t - ' + "Internet Protocol Version 4:")
                        h_len = str(ipv4.header_length) + ' bytes (' + str(int(ipv4.header_length / 4)) + ')'
                        print('\t\t - ' + 'Version: {}, Header Length: {}, Type Of Service: {}, Total Lenght: {}'.format(
                            ipv4.version, h_len, ipv4.tos, ipv4.total_length))
                        print('\t\t - ' + 'Identification: {} ({})'.format(hex(ipv4.ID), ipv4.ID))
                        print('\t\t - ' + 'Flags:')
                        print('\t\t\t - ' + 'Reserved bit: {}, Dont Fragment: {}, More Fragment: {}'.format(
                            ipv4.Rb, ipv4.DF, ipv4.MF))
                        print('\t\t - '+'Fragment Offset: {}', ipv4.fragment_Offset)
                        print('\t\t - ' + 'Time to live: {}, Protocol: {} ({}), Header checksum: {}'.format(ipv4.ttl, 'ICMP',
                                                                                                            ipv4.protocol,
                                                                                                            ipv4.header_checksum))
                        print('\t\t - ' + 'Source address: {}'.format(ipv4.source_address))
                        print('\t\t - ' + 'Destination address: {}'.format(ipv4.destination_address))

                        print('\t\t - ' + 'Options: {}'.format(ipv4.options))

                        # ICMP

                        print('\t - ' + 'Intenet Control Message Protocol (Echo Request ):')
                        print('\t\t - ' + 'Type: {}, Code: {}, Checksum: {}'.format(icmp.icmp_type, icmp.code, icmp.checksum))
                        print('\t\t - ' + 'Identifier: {}, Sequence number: {}'.format(icmp.id, icmp.sequence))

                        pcap.write(raw_data)
                        icmp_responder = ICMP_responder(raw_data)
                        icmp_responder.send_to()


                # TCP
                elif ipv4.protocol == 6:
                    tcp = TCP(ipv4.data)
                    if tcp.src_port == 53 or tcp.dest_port == 53:
                        dns = DNS(tcp.data)

                        if dns.QR == 0:

                            print("-----------------------------------------------------------------------------------------------------\n")
                            print(' Ethernet Frame: ')

                            ether_type = 'IPv4 (0x0800)'
                            print('\t - ' + 'Destination: {}, Source: {}, Type: {}'.format(eth.dest_mac, eth.src_mac, ether_type))

                            print('\t - ' + "Internet Protocol Version 4:")
                            h_len = str(ipv4.header_length) + ' bytes (' + str(int(ipv4.header_length / 4)) + ')'
                            print('\t\t - ' + 'Version: {}, Header Length: {}, Type Of Service: {}, Total Lenght: {}'.format(
                                ipv4.version, h_len, ipv4.tos, ipv4.total_length))
                            print('\t\t - ' + 'Identification: {} ({})'.format(hex(ipv4.ID), ipv4.ID))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Reserved bit: {}, Dont Fragment: {}, More Fragment: {}'.format(
                                ipv4.Rb, ipv4.DF, ipv4.MF))
                            print('\t\t - ' + 'Fragment Offset: {}', ipv4.fragment_Offset)
                            print('\t\t - ' + 'Time to live: {}, Protocol: {} ({}), Header checksum: {}'.format(ipv4.ttl, 'ICMP',
                                                                                                                ipv4.protocol,
                                                                                                                ipv4.header_checksum))
                            print('\t\t - ' + 'Source address: {}'.format(ipv4.source_address))
                            print('\t\t - ' + 'Destination address: {}'.format(ipv4.destination_address))

                            print('\t\t - ' + 'Options: {}'.format(ipv4.options))

                            # TCP
                            print('\t - ' + 'Transmission Control Protocol:')
                            print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                            print('\t\t - ' + 'Sequence number: {}, Acknowledgment number: {}'.format(tcp.sequence,tcp.acknowledgment))
                            h_len = str(tcp.offset) + ' bytes (' + str(int(tcp.offset / 4)) + ')'
                            print('\t\t - ' + 'Header Length: {}'.format(h_len))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Reserved: {}, NS: {}, CWR: {}'.format(tcp.Reserved, tcp.NS, tcp.CWR))
                            print('\t\t\t - ' + 'ECE: {}, URG: {}, ACK: {}, PSH: {}'.format(tcp.ECE, tcp.URG, tcp.ACK, tcp.PSH))
                            print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN: {}'.format(tcp.RST, tcp.SYN, tcp.FIN))
                            print('\t\t - ' + 'Window sizr: {}, Checksum: {}'.format(tcp.window, tcp.checksum))
                            print('\t\t - ' + 'Urgent pointer: {}, Options: {}'.format(tcp.urgent, tcp.options))

                            #   DNS
                            print('\t - ' + 'Domain Name System (query):')
                            print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                            print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                dns.AA, dns.TC, dns.RD, dns.RA))

                            print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA, dns.Z, dns.AD))
                            print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD, dns.Rcode))
                            print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                                dns.question_count, dns.answer_count, dns.name_server_count, dns.additional_record_count))

                            pcap.write(raw_data)
                            dns_responder = DNS_responder_TCP(raw_data)
                            dns_responder.send_to()

                # UDP
                elif ipv4.protocol == 17:
                    udp = UDP(ipv4.data)
                    if udp.src_port == 53 or udp.dest_port == 53:
                        dns = DNS(udp.data)
                        if dns.QR == 0:
                            print("-----------------------------------------------------------------------------------------------------\n")
                            print(' Ethernet Frame: ')

                            ether_type = 'IPv4 (0x0800)'
                            print('\t - ' + 'Destination: {}, Source: {}, Type: {}'.format(eth.dest_mac, eth.src_mac, ether_type))

                            print('\t - ' + "Internet Protocol Version 4:")
                            h_len = str(ipv4.header_length) + ' bytes (' + str(int(ipv4.header_length / 4)) + ')'
                            print('\t\t - ' + 'Version: {}, Header Length: {}, Type Of Service: {}, Total Lenght: {}'.format(
                                ipv4.version, h_len, ipv4.tos, ipv4.total_length))
                            print('\t\t - ' + 'Identification: {} ({})'.format(hex(ipv4.ID), ipv4.ID))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Reserved bit: {}, Dont Fragment: {}, More Fragment: {}'.format(
                                ipv4.Rb, ipv4.DF, ipv4.MF))
                            print('\t\t - ' + 'Fragment Offset: {}', ipv4.fragment_Offset)
                            print('\t\t - ' + 'Time to live: {}, Protocol: {} ({}), Header checksum: {}'.format(ipv4.ttl, 'ICMP',
                                                                                                                ipv4.protocol,
                                                                                                                ipv4.header_checksum))
                            print('\t\t - ' + 'Source address: {}'.format(ipv4.source_address))
                            print('\t\t - ' + 'Destination address: {}'.format(ipv4.destination_address))

                            print('\t\t - ' + 'Options: {}'.format(ipv4.options))

                            #   UDP
                            print('\t - ' + 'User Datagram Protocol:')
                            print('\t\t - ' + 'Source Port: {}, Destination Port: {}, Length: {},Checksum: {}'.format(udp.src_port,
                                                                                                                  udp.dest_port,
                                                                                                                  udp.length,
                                                                                                                  udp.checksum))
                            #   DNS
                            print('\t - ' + 'Domain Name System (query):')
                            print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                            print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                    dns.AA, dns.TC, dns.RD, dns.RA))

                            print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA,dns.Z,dns.AD))
                            print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD,dns.Rcode))
                            print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                                    dns.question_count,dns.answer_count,dns.name_server_count,dns.additional_record_count))

                            pcap.write(raw_data)
                            dns_responder = DNS_responder_UDP(raw_data)
                            dns_responder.send_to()


    except KeyboardInterrupt:
        print('\033[32m' + '\n Packet capturing was stopped. Packets were saved in capture.pcap \n')
        pcap.close()
        
        
