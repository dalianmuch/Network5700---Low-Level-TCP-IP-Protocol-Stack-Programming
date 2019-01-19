#!/usr/bin/python
# -*- coding: UTF-8 -*-

import global_data
import time
import struct
import socket
import util
import http
import ip
import tcp
import ethernet
import time
import sys


"""
transfer data from client to server and receive response data from server to client
"""


def send_data_to_server():
    """
    send http request to server
    """
    http.build_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, 1, int(global_data.get_value("sequence_number")), 5, 0, 0, 0, 1, 1)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    send_packet_to_server()


def receive_data_from_server():
    """
    receive data from the server, for three way handshake and for receive http response data
    """
    downloaded_file_name = global_data.get_value("downloaded_file_name")
    main_socket = global_data.get_value("main_socket")
    local_port = global_data.get_value("local_port")
    server_ip = global_data.get_value("server_ip")
    local_ip = global_data.get_value("local_ip")

    f = open(downloaded_file_name, 'a')
    while True:
        if (time.time() - global_data.get_value("last_packet_sent_time")) > 180:
            print "Program, rawhttpget, does not receive any data from the remote server for three minutes. Please retry again."
            sys.exit(0)

        packet = main_socket.recvfrom(65565)
        packet = packet[0]

        ethernet_header_length = struct.calcsize('!6s6sH')

        ip_header = packet[ethernet_header_length:ethernet_header_length + 20]
        global_data.set_value("ip_header", ip_header)
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        server_as_source_address = socket.inet_ntoa(iph[8])
        local_as_destination_address = socket.inet_ntoa(iph[9])
        tcp_header = packet[ethernet_header_length + iph_length:ethernet_header_length + iph_length + 20]
        global_data.set_value("tcp_header", tcp_header)

        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        server_as_source_port = tcph[0]
        local_as_destination_port = tcph[1]
        sequence_number = tcph[2]
        global_data.set_value("sequence_number", sequence_number)
        acknowledge_number = tcph[3]
        global_data.set_value("acknowledge_number", acknowledge_number)
        data_offset_reserved = tcph[4]
        tcp_flags = tcph[5]

        flag_fin = tcp_flags & int(hex(1), 16)
        flag_syn = (tcp_flags >> 1) & int(hex(1), 16)
        flag_ack = (tcp_flags >> 4) & int(hex(1), 16)

        tcph_length = data_offset_reserved >> 4
        header_size = ethernet_header_length + iph_length + tcph_length * 4
        data_size = len(packet) - header_size
        data = packet[header_size:]

        if local_as_destination_port != local_port or server_as_source_port != 80 \
                or server_as_source_address != server_ip or local_as_destination_address != local_ip:
            continue
        else:
            if flag_ack == 1 and flag_syn == 1:
                old_sequence_number = sequence_number + 1
                global_data.set_value("old_sequence_number", old_sequence_number)
                break

            if data_size > 6 and global_data.get_value("current_cwnd_size") <= 1000:
                if global_data.get_value("old_sequence_number") + global_data.get_value("old_data_length") == \
                        global_data.get_value("sequence_number") and util.tcp_checksum(global_data.get_value("ip_header")) == 0:
                    if (time.time() - global_data.get_value("last_packet_sent_time")) < 60:
                        if data.split('\r\n\r\n')[0] == data:
                            """ directly write data into file """
                            f.write(data)
                        else:
                            data_containing_header = data.split('\r\n\r\n')[0]
                            http_status = data_containing_header.split(' ')[1]
                            if http_status == "200":
                                f.write(data.split('\r\n\r\n')[1])
                            else:
                                print "Only 200 will be considered!"
                                break

                        old_sequence_number = global_data.get_value("sequence_number")
                        global_data.set_value("old_sequence_number", old_sequence_number)
                        old_data_length = data_size
                        global_data.set_value("old_data_length", old_data_length)

                        """ solve the retransmit packet needs to be ACK """
                        if global_data.get_value("number_of_retransmit_packet_to_be_ACK") > 0:
                            new_number_of_retransmit_packet_to_be_ACK = global_data.get_value("number_of_retransmit_packet_to_be_ACK") - 1
                            global_data.set_value("number_of_retransmit_packet_to_be_ACK", new_number_of_retransmit_packet_to_be_ACK)

                        """ normal cwnd size """
                        if 0 < global_data.get_value("current_cwnd_size") + 1 < 1000:
                            new_current_cwnd_size = global_data.get_value("current_cwnd_size") + 1
                            global_data.set_value("current_cwnd_size", new_current_cwnd_size)
                        else:
                            new_current_cwnd_size = 1
                            global_data.set_value("current_cwnd_size", new_current_cwnd_size)

                        send_ack_to_server(global_data.get_value("sequence_number"))
                    else:
                        print "retransmit because the 60 seconds limit"
                        send_ack_retransmit_to_server(global_data.get_value("old_sequence_number"))
                else:
                    if global_data.get_value("current_cwnd_size") + 1 <= 0 or global_data.get_value("current_cwnd_size") + 1 >= 1000:
                        new_current_cwnd_size = 1
                        global_data.set_value("current_cwnd_size", new_current_cwnd_size)
                    else:
                        new_current_cwnd_size = global_data.get_value("current_cwnd_size") + 1
                        global_data.set_value("current_cwnd_size", new_current_cwnd_size)
                    new_number_of_retransmit_packet_to_be_ACK = 1
                    global_data.set_value("number_of_retransmit_packet_to_be_ACK", new_number_of_retransmit_packet_to_be_ACK)
                    print "retransmit because sequence number or checksum error"
                    send_ack_retransmit_to_server(global_data.get_value("old_sequence_number"))

            if flag_fin == 1 and global_data.get_value("number_of_retransmit_packet_to_be_ACK") == 0:
                f.close()
                send_fin_ack_to_server()
                break
                sys.exit(0)


def send_packet_to_server():
    global_data.get_value("main_socket").bind((global_data.get_value("interface"), 0))
    global_data.get_value("main_socket").send(global_data.get_value("eth_header"))
    last_packet_sent_time = time.time()
    global_data.set_value("last_packet_sent_time", last_packet_sent_time)


def send_ack_to_server(seq_no):
    http.build_empty_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, 1 + global_data.get_value("http_request_length"), seq_no + 1, 5, 0, 0, 0, 0, 1)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    send_packet_to_server()


def send_ack_retransmit_to_server(seq_no):
    http.build_empty_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, 1 + global_data.get_value("http_request_length"),
                         seq_no + global_data.get_value("old_data_length"), 5, 0, 0, 0, 0, 1)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    send_packet_to_server()


def send_fin_ack_to_server():
    http.build_empty_http_header()
    tcp.build_tcp_header(global_data.get_value("local_port"), 80, global_data.get_value("acknowledge_number"),
                         int(global_data.get_value("sequence_number")) + 1, 5, 1, 0, 0, 0, 1)
    ip.build_ip_header()
    ethernet.build_ethernet_header_for_ip()
    send_packet_to_server()

