# -*- coding: utf-8 -*-

""" Parse mitmproxy Request Log

This module is used to parse mitmproxy Requests and insert into MySQL DB.

Usage:
    python parser_mitmproxy.py logs.txt

"""

import sys
import re
import hashlib
import time

ENVIRONMENT = "Linux"
scanApi = 'http://127.0.0.1:7001/scan/?token={0}'
#ENVIRONMENT = "Windows"

def get_item_info(line, item, delim):
    if item in line:
        item_info = line.split(delim, 1)[1].strip()
        reg = '^b\'(.*?)\'$'
        match = re.search(reg, item_info)
        if match:
            item_info = match.group(1)
    else:
        item_info = ''
    return item_info

def is_contained(rtext, excludes):
    if len(excludes):
        excludes_str = '|'.join(excludes)
        reg = '.*({}).*'.format(excludes_str)
        res = re.search(reg, rtext)
        if res:
            return True
        else:
            return False
    else:
        return False

def get_file_to_array(log_file):
    with open(log_file, 'rb') as f:  # Note: Here is 'rb' rather than 'r'
        contents = f.readlines()
    num_of_delim = 0
    requests = []
    request_str = ''
    for i in range(len(contents)):
        if num_of_delim == 1:
            requests.append(request_str.strip('\r\n'))
            request_str = ''
            num_of_delim = 0
        if '======================================================' in contents[i]:
            num_of_delim += 1
        request_str += contents[i]
    return requests

def parse_request_info(request_info):
    if ENVIRONMENT == "Linux":
        lines = request_info.split('\n') # For Linux
    elif ENVIRONMENT == "Windows":
        lines = request_info.split('\n') # For Windows
    request = {}
    for line in lines:
        k = line.split(': ')[0]
        v = line.split(':')[1].strip() if len(line.split(':')) == 2 else ''
        request[k] = v
    if request['port'] == '': #port默认值为80
        request['port'] = 80
    return request

def build_request(request_info):
    request = request_info['method'] + ' ' + request_info['path'] + ' HTTP/1.1\r\n'
    request = request + 'Host: ' + request_info['host'] + ':' + str(request_info['port']) + '\r\n'
    request = request + 'User-Agent: ' + request_info['user_agent'] + '\r\n'
    request = request + 'Accept: ' + request_info['accept'] + '\r\n'
    request = request + 'Referer: ' + request_info['referer'] + '\r\n'
    request = request + 'Cookie: ' + request_info['cookie'] + '\r\n'
    if request_info['method'].lower() == 'post':
        request = request + 'Content-Type:' + request_info['content_type'] + '\r\n'
        request = request + '\r\n\r\n' + request_info['post_data']
    return request

def sendToScanApi(data,token):
    global scanApi
    scanApi = scanApi.format(token)
    import requests
    print data
    rep = requests.post(url=scanApi, data=data)
    print(rep.text)

def parse_log(log_file):
    requests = get_file_to_array(log_file)
    print 'do work'
    for request in requests:
        request_info = request.split('======================================================')[0]
        request_info_parsed = parse_request_info(request_info)
        if request_info_parsed['host'] and request_info_parsed['method']:
            request_data = build_request(request_info_parsed)
            # print(request_data)
            print("======================")
            sendToScanApi(request_data,'mitmproxy')

def main():
    import sys
    log_file = sys.argv[-1]
    parse_log(log_file)

if __name__ == "__main__":
    main()
