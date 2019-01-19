#!/usr/bin/python
# -*- coding: UTF-8 -*-

import global_data


""" build http header with 2 types """


def build_empty_http_header():
    http_request = ""
    global_data.set_value("http_request", http_request)


def build_http_header():
    http_header = "GET " + global_data.get_value("url") + " HTTP/1.0\r\n\r\n"
    http_request = http_header
    global_data.set_value("http_request", http_request)

    http_request_length = len(http_header)
    global_data.set_value("http_request_length", http_request_length)
