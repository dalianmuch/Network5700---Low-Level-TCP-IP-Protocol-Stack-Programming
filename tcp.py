#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import struct
import util
import global_data

'''
TCP Header
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''


def build_tcp_header(source_of_tcp_p, dest_of_tcp_p, seq_of_tcp_p, ack_seq_of_tcp_p, d_off_tcp_p, fin_p, syn_p, rst_p, psh_p, ack_p):
    # TCP Header Section
    # source port
    source_port = source_of_tcp_p
    # destination port
    destination_port = dest_of_tcp_p

    seq_num = seq_of_tcp_p
    ack_num = ack_seq_of_tcp_p
    d_offset = 5

    # flags
    fin = fin_p
    syn = syn_p
    rst = rst_p
    psh = psh_p
    ack = ack_p
    urg = 0
    #   size of max allowed window size
    window_size = socket.htons(5840)
    checksum = 0
    urg_pointer = 0

    offset_res_of_tcp = (d_offset << 4) + 0
    flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    tcp_header_p = struct.pack("!HHLLBBHHH", source_port, destination_port, seq_num, ack_num, offset_res_of_tcp, flags, window_size, checksum,
                               urg_pointer)

    source_address = socket.inet_aton(global_data.get_value("local_ip"))

    dest_address = socket.inet_aton(global_data.get_value("server_ip"))

    placeholder = 0

    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header_p) + len(global_data.get_value("http_request"))

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)

    psh = psh + tcp_header_p + global_data.get_value("http_request")

    checksum = util.tcp_checksum(psh)

    # add correct tcp header checksum
    tcp_header = struct.pack('!HHLLBBH', source_port, destination_port, seq_num, ack_num,
                             offset_res_of_tcp, flags, window_size) + struct.pack('H', checksum) + struct.pack('!H', urg_pointer)
    tcp_header = ''.join([tcp_header, global_data.get_value("http_request")])

    # save into global data value
    global_data.set_value("tcp_header", tcp_header)

