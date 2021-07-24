import socket
import struct
import textwrap
import time
import binascii


class Ethernet:
    def __init__(self, r_data):
        dest, src, proto = struct.unpack('!6s6sH', r_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = proto
        self.data = r_data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str)
    return mac_addr


class ARP:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! H H B B H 6s L 6s L", r_data[:28])
        self.hardware_type = tmp[0]
        self.protocol_type = tmp[1]
        self.hardware_addr_len = tmp[2]
        self.protocol_addr_len = tmp[3]
        self.opcode = tmp[4]
        self.sender_hardware_address = get_mac_addr(tmp[5])
        self.sender_protocol_addr = socket.inet_ntoa(struct.pack(">I", tmp[6]))
        self.target_hardware_address = get_mac_addr(tmp[7])
        self.target_protocol_addr = socket.inet_ntoa(struct.pack(">I", tmp[8]))
        self.data = r_data[28:]


class ICMP:
    #identifier & sequence number
    def __init__(self, r_data):
        self.icmp_type, self.code, self.checksum, self.id, self.sequence = struct.unpack('! B B H H H', r_data[:8])
        self.data = r_data[8:]


class DNS:
    def __init__(self, r_data):
        self.id, flags_codes, self.question_count, self.answer_count, self.name_server_count, self.additional_record_count = struct.unpack(
            "! 6H", r_data[:12])
        self.Rcode = flags_codes & 15
        flags_codes = flags_codes >> 4
        self.CD = (flags_codes & 1)
        self.AD = (flags_codes & 2) >> 1
        self.Z = (flags_codes & 4) >> 2
        self.RA = (flags_codes & 8) >> 3
        self.RD = (flags_codes & 16) >> 4
        self.TC = (flags_codes & 32) >> 5
        self.AA = (flags_codes & 64) >> 6
        flags_codes = flags_codes >> 7
        self.opcode = flags_codes & 15
        self.QR = flags_codes >> 4

        self.data = r_data[12:]



class IPv4:

    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! B B H H H B B H L L", r_data[:20])
        version_header_length = tmp[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.tos = tmp[1]  # type of service
        self.total_length = tmp[2]
        self.ID = tmp[3]
        ff = tmp[4]
        self.Rb = (ff & 0x8000) >> 15
        self.MF = (ff & 0x3FFF) >> 13
        self.DF = (ff & 0x7FFF) >> 14
        self.fragment_Offset = (ff & 0x1FFF)
        self.ttl = tmp[5]
        self.protocol = tmp[6]
        self.header_checksum = tmp[7]

        self.source_address = socket.inet_ntoa(struct.pack(">I", tmp[8]))
        self.destination_address = socket.inet_ntoa(struct.pack(">I", tmp[9]))
        self.options = []
        if self.header_length > 20:
            self.options = r_data[20:self.header_length]
        self.data = r_data[self.header_length:]


class TCP:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack('! H H L L H H H H', r_data[:20])
        self.src_port = tmp[0]
        self.dest_port = tmp[1]
        self.sequence = tmp[2]
        self.acknowledgment = tmp[3]
        offset_reserved_flag = tmp[4]
        self.window = tmp[5]
        self.checksum = tmp[6]
        self.urgent = tmp[7]
        self.offset = (offset_reserved_flag >> 12) * 4  # offset is header_length = row count * 32 / 8
        self.Reserved = (offset_reserved_flag & 0xE00) >> 9
        self.NS = (offset_reserved_flag & 256) >> 8
        self.CWR = (offset_reserved_flag & 128) >> 7
        self.ECE = (offset_reserved_flag & 64) >> 6
        self.URG = (offset_reserved_flag & 32) >> 5
        self.ACK = (offset_reserved_flag & 16) >> 4
        self.PSH = (offset_reserved_flag & 8) >> 3
        self.RST = (offset_reserved_flag & 4) >> 2
        self.SYN = (offset_reserved_flag & 2) >> 1
        self.FIN = (offset_reserved_flag & 1)
        self.options = []
        if self.offset > 20:
            self.options = r_data[20:self.offset]
        self.data = r_data[self.offset:]


class UDP:
    def __init__(self, r_data):
        self.src_port, self.dest_port, self.length, self.checksum = struct.unpack('! H H H H', r_data[:8])
        self.data = r_data[8:]
