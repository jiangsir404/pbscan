# -*- coding: utf-8 -*-

""" Capture mitmproxy Request Logs into a file

This module is used to capture mitmproxy Requests and write to a file.

Usage:
    mitmdump -p 443 -s "proxy_mitmproxy.py logs.txt"

"""

import sys
import time

def get_request_info(flow, item):
    request_item = ""
    try:
        if item == "port" and flow.request.port:
            request_item = flow.request.port
    except Exception:
        pass
    try:
        if item == "protocol" and flow.request.scheme:
            request_item = flow.request.scheme
    except Exception:
        pass
    try:
        if item == "path" and flow.request.path:
            request_item = flow.request.path
    except Exception:
        pass
    try:
        if item == "host" and flow.request.host:
            request_item = flow.request.host
    except Exception:
        pass
    try:
        if item == "method" and flow.request.method:
            request_item = flow.request.method
    except Exception:
        pass
    try:
        if item == "post_data" and flow.request.text: # content 会被加上 b'' , 不方便处理
            request_item = flow.request.text
    except Exception:
        pass
    try:
        if item == "time" and flow.request.timestamp_start:
            request_item = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(flow.request.timestamp_start))
    except Exception:
        pass
    try:
        if item == "accept" and flow.request.headers['accept']:
            request_item = flow.request.headers['accept']
    except Exception:
        pass
    try:
        if item == "accept_language" and flow.request.headers['accept-language']:
            request_item = flow.request.headers['accept-language']
    except Exception:
        pass
    try:
        if item == "accept_encoding" and flow.request.headers['accept-encoding']:
            request_item = flow.request.headers['accept-encoding']
    except Exception:
        pass
    try:
        if item == "cookie" and flow.request.headers['cookie']:
            request_item = flow.request.headers['cookie']
    except Exception:
        pass
    try:
        if item == "referer" and flow.request.headers['referer']:
            request_item = flow.request.headers['referer']
    except Exception:
        pass
    try:
        if item == "user_agent" and flow.request.headers['user-agent']:
            request_item = flow.request.headers['user-agent']
    except Exception:
        pass
    try:
        if item == "content_type" and flow.request.headers['content-type']:
            request_item = flow.request.headers['content-type']
    except Exception:
        pass
    return request_item

def request(flow):
    request = {}
    request['time'] = get_request_info(flow, 'time')
    request['protocol'] = get_request_info(flow, 'protocol')
    request['host'] = get_request_info(flow, 'host')
    request['path'] = get_request_info(flow, 'path')
    request['method'] = get_request_info(flow, 'method')
    request['port'] = get_request_info(flow, 'port')
    request['user_agent'] = get_request_info(flow, 'user_agent')
    request['cookie'] = get_request_info(flow, 'cookie')
    request['referer'] = get_request_info(flow, 'referer')
    request['content_type'] = get_request_info(flow, 'content_type')
    request['accept'] = get_request_info(flow, 'accept')
    request['accept_language'] = get_request_info(flow, 'accept_language')
    request['accept_encoding'] = get_request_info(flow, 'accept_encoding')
    request['post_data'] = get_request_info(flow, 'post_data')
    print(request)
    log_file_name = sys.argv[-1]
    log_file = open(log_file_name, 'a')
    for k, v in request.items():
        log_file.write("%s: %s\n"%(k,v))
    log_file.write("======================================================\n\n\n")
    log_file.close()
