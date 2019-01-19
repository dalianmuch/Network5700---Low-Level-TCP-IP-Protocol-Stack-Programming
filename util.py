#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import random
import global_data
import subprocess
import struct
import ethernet


""" util file to get ip address, mac address, file name and do checksum functions """

def get_local_ip():
    find_local_ip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    find_local_ip_socket.connect(("www.baidu.com", 80))
    local_ip, _port = find_local_ip_socket.getsockname()
    print "local ip:", local_ip
    return local_ip


def get_local_port():
    local_port = int('%04d' % random.uniform(8000, 65000))
    print "local port:", local_port
    return local_port


def get_local_ip_binary():
    local_ip = global_data.get_value("local_ip")
    local_ip_binary = socket.inet_aton(local_ip)
    print "local_ip_binary:", local_ip_binary
    return local_ip_binary


def get_local_mac_binary():
    find_local_mac_binary_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    find_local_mac_binary_socket.bind(("ens33", socket.SOCK_RAW))
    _internet_face_name, _protocol, _packet_type, _hardware_type, local_mac_binary = find_local_mac_binary_socket.getsockname()
    print "local_mac_binary:", local_mac_binary
    return local_mac_binary


def get_gateway_ip_binary():
    shell_value = True
    standard_output = subprocess.PIPE
    parameter_value = "ip r l"
    values_return = subprocess.Popen(parameter_value, shell=shell_value, stdout=standard_output).communicate()
    gateway_ip = values_return[0].split(' ')[2]
    print "gateway_ip:", gateway_ip
    gateway_ip_binary = socket.inet_aton(gateway_ip)
    print "gateway_ip_binary:", gateway_ip_binary
    return gateway_ip_binary


def get_gateway_mac_binary():
    interface = global_data.get_value("interface")
    main_socket = global_data.get_value("main_socket")

    # simulate a broadcast address to find the gateway mac address
    arp_header = ethernet.build_arp_header()
    ethernet_header = ethernet.build_ethernet_header_for_arp()
    ethernet_packet = ''.join([ethernet_header, arp_header])

    # bind with interface
    main_socket.bind((interface, socket.SOCK_RAW))
    # send ethernet packet, so that MAC address of gateway can be retrieved from its response.
    main_socket.send(ethernet_packet)

    # we store the size of struct, will be used while unpacking the packets, corresponding to the given format.
    ethernet_header_length = struct.calcsize('!6s6sH')
    arp_header_length = struct.calcsize('!HHBBH6s4s6s4s')

    while True:
        packet = main_socket.recv(65565)
        # unpack the ethernet_packet
        fields = struct.unpack('!6s6sH', packet[:ethernet_header_length])

        if fields[2] == 2054:
            break

    # unpack arp packet from eth packet
    arp_fields = struct.unpack('!HHBBH6s4s6s4s', packet[ethernet_header_length:][:arp_header_length])
    gateway_mac_binary = arp_fields[5]
    print "gateway_mac_binary:", gateway_mac_binary
    return gateway_mac_binary


def get_server_ip_and_downloaded_file_name(url):
    if url.startswith('http://'):
        url_content = url[7:]
        url_separated_with_slash = url_content.split("/")
        if url_separated_with_slash[0] == url_content:
            downloaded_file_name = "index.html"
            server_web_address = url_content
        else:
            server_web_address = url_separated_with_slash[0]
            url_content_length = len(url_separated_with_slash)
            downloaded_file_name = url_separated_with_slash[url_content_length - 1]
            if downloaded_file_name.find(".") == -1:
                downloaded_file_name = "index.html"
    else:
        print "--- Wrong URL format ---"
        raise Exception
    global_data.set_value("downloaded_file_name", downloaded_file_name)
    server_ip = socket.gethostbyname(server_web_address)
    return server_ip

def tcp_checksum(message):
    counter = 0
    sumValue = 0
    msglength = len(message)
    msg_size_limit = 2

    while msglength >= msg_size_limit:
        w = (ord(message[counter + 1]) << 8) + ord(message[counter])
        sumValue = sumValue + w
        counter = counter + msg_size_limit
        msglength = msglength - msg_size_limit
    if msglength == 1:
        sumValue = sumValue + ord(message[counter])

    carry = (sumValue >> 16) + (sumValue & 0xffff);
    sumValue = carry + (carry >> 16);
    sumValue = ~sumValue & 0xffff
    return sumValue


def ip_checksum(message):
    msglength = len(message)
    sumValue = 0
    msg_size_limit = 2
    for counter in range(0, msglength, msg_size_limit):
        if counter < msglength and (counter + 1) < msglength:
            sumValue += (ord(message[counter]) + (ord(message[counter + 1]) << 8))
        elif counter < msglength and (counter + 1) == msglength:
            sumValue += ord(message[counter])

    carry = (sumValue & 0xffff) + (sumValue >> 16)
    sumValue = (~ carry) & 0xffff
    sumValue = sumValue >> 8 | ((sumValue & 0x00ff) << 8)
    return sumValue

