#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import struct
import util
import global_data

'''
IP Header
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''


def build_ip_header():
    ihl = 5
    ver = 4
    tos = 0

    id_of_ip_pkt = 54321
    fragm_off = 0
    ttl = 225
    protocol = socket.IPPROTO_TCP
    checksum_for_ip = 0

    source_add_for_ip = socket.inet_aton(global_data.get_value("local_ip"))
    dest_add_for_ip = socket.inet_aton(global_data.get_value("server_ip"))

    ihl_ver = (ver << 4) + ihl
    tot_length = 4 * ihl + len(global_data.get_value("tcp_header"))

    ip_header = struct.pack('!BBHHHBBH4s4s' , ihl_ver, tos, tot_length, id_of_ip_pkt, fragm_off, ttl, protocol, checksum_for_ip, source_add_for_ip, dest_add_for_ip)

    checksum = util.ip_checksum(ip_header)

    """ add checksum into ip header """
    ip_header = struct.pack('!BBHHHBBH4s4s' , ihl_ver, tos, tot_length, id_of_ip_pkt, fragm_off, ttl, protocol, checksum, source_add_for_ip, dest_add_for_ip)

    ip_header = ''.join([ip_header, global_data.get_value("tcp_header")])
    global_data.set_value("ip_header", ip_header)


