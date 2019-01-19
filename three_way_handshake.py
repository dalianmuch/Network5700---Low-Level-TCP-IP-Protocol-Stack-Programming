#!/usr/bin/python
# -*- coding: UTF-8 -*-

import http
import tcp
import ip
import ethernet
import data_transfer
import global_data


""" perform the first and third step in three way handshake with corresponding syn, ack, sequence number """


def handshake_step_one():
    http.build_empty_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, 0, 0, 5, 0, 1, 0, 0, 0)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    data_transfer.send_packet_to_server()


def handshake_step_three():
    http.build_empty_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, 1, global_data.get_value("sequence_number") + 1, 5, 0, 0, 0, 0, 1)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    data_transfer.send_packet_to_server()


