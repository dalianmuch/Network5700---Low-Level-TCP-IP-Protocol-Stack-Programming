#!/usr/bin/python
# -*- coding: UTF-8 -*-


def init():
    """
    initialize global data to transfer data between each python file
    """
    global global_data
    global_data = {}


def set_value(key, value):
    global_data[key] = value


def get_value(key, default_value=None):
    try:
        return global_data[key]
    except KeyError:
        print "--- key not exists in global data ---:", key
        return default_value


"""
gateway_mac_binary
http_request_length
http_request
tcp_header
ip_header
eth_header ==> in some functions for ethernet header
last_packet_sent_time
acknowledge_number
sequence_number
old_data_length
old_sequence_number
number_of_retransmit_packet_to_be_ACK
current_cwnd_size
local_port
url
downloaded_file_name
server_ip
local_ip
local_ip_binary
local_mac_binary
gateway_ip_binary
main_socket
interface
"""
