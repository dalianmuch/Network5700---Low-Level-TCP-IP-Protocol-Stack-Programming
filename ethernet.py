#!/usr/bin/python
# -*- coding: UTF-8 -*-

import struct
import global_data


""" build ethernet header """


def build_arp_header():
    hardware_type = 1
    protocol_type = 2048
    hardware_length = 6
    protocol_length = 4
    broadcast_mac_address = struct.pack('!6B', 255, 255, 255, 255, 255, 255)

    operation = 1
    arp_pkt = struct.pack('!HHBBH6s4s6s4s', hardware_type, protocol_type, hardware_length, protocol_length, operation,
                          global_data.get_value("local_mac_binary"), global_data.get_value("local_ip_binary"), broadcast_mac_address,
                          global_data.get_value("gateway_ip_binary"))
    return arp_pkt


def build_ethernet_header_for_arp():
    ether_type = 2054  # 0x0806
    broadcast_mac_address = struct.pack('!6B', 255, 255, 255, 255, 255, 255)
    header_of_eth = struct.pack('!6s6sH', broadcast_mac_address, global_data.get_value("local_mac_binary"), ether_type)

    eth_pkt = header_of_eth
    return eth_pkt


def build_ethernet_header_for_ip():
    ether_type = 2048
    header_of_eth = struct.pack('!6s6sH', global_data.get_value("gateway_mac_binary"), global_data.get_value("local_mac_binary"), ether_type)
    eth_header = ''.join([header_of_eth, global_data.get_value("ip_header")])
    global_data.set_value("eth_header", eth_header)

