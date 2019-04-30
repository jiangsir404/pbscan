# -*- coding: utf-8 -*-

""" XSS Scanner

This module provides functions that scan XSS.

"""

import requests
import re
import time
from lib.db_operation import db_query, update_scan_result, fetch_request, get_request_info, is_checked_vulnerable, fetch_exclusion_scan, get_scan_exclusion_info, fetch_exclusion_cookie, get_cookie_exclusion_info
from lib.utils import highlight
from lib.hack_requests import HackRequests


# Define Lib for HackRequests class
LIB_1 = 'PHANTOMJS'
LIB_2 = 'REQUESTS'

# Fetch the exclusions for cookie parameters from database
cookie_exclusion = get_cookie_exclusion_info(fetch_exclusion_cookie()[0])

# Load payloads from file into a list for scan
payloads = []
lines = open('payloads/xss.txt','rb')
for line in lines:
    payloads.append(line.strip())
lines.close()

def verify_xss(rhtml, verification):
    if verification in rhtml:
        result = 'vulnerable'
    else:
        result = 'not vulnerable'
    return result

def print_scan_result(type, response, payload_str, verification, request_info):
    """ Print Scan Result

        Args:
            type: Type of POC, it is a string, e.g. "Cookie", "Path", "Post"
            response: The response content of request
            payload_str: The real payload of XSS based on parameters, it is a string, e.g. "value=<script>alert(1)</script>"
            verification: The verification of XSS, it can be a string or list
            request_info: The info of request, it is a dict

    """
    result_xss = ""
    if response:
        res = "[XSS] request id: {}\n\t[-] host: {}\n\t[-] method: {}\n\t[-] payload: {}\n\n[*] result: {}\n\n".format(request_info['rid'], request_info['host'], request_info['method'], payload_str, verify_xss(response, verification))
        result_xss = verify_xss(response, verification)
    else:
        res = "[XSS] request id: {}\n\t[-] host: {}\n\t[-] method: {}\n\t[-] payload: {}\n\n[*] result: {}\n\n".format(request_info['rid'], request_info['host'], request_info['method'], payload_str, "not vulnerable")
        result_xss = "not vulnerable"
    poc_xss = "{}: {}".format(type, payload_str)
    update_scan_result(request_info['rid'], 'scan_xss', 'result_xss', result_xss, 'poc_xss', poc_xss, 'response_xss', response)
    print highlight(res, 'green')
    return result_xss


def scan_request_from_cookie(request_info):
    """ Scan all cookies except exclusions in list 'cookie_exclusion' for GET/POST request

    Examples:
        POST /dvwa/login.php HTTP/1.1
        Host: test.avfisher.win
        Cookie: security=low; PHPSESSID=a93qmi370veagks0j81k3rlu32

        Cookies:
            security
            PHPSESSID

    """

    cookie = request_info['cookie']
    if cookie:
        cookies = cookie.split('; ')
        for ck in cookies:
            if ck and ck.strip().split('=', 1)[0].lower() not in cookie_exclusion:
                for payload in payloads:
                    payload_cookie = "{}{}".format(ck, payload)
                    cookie_str = cookie.replace(ck, payload_cookie)
                    request_info['cookie'] = cookie_str.strip()
                    type = "Cookie"
                    if request_info['method'] == "GET":
                        r_1 = HackRequests(request_info, LIB_1).get_request()
                        r_2 = HackRequests(request_info, LIB_2).get_request()
                        if print_scan_result(type, r_1, cookie_str, payload, request_info) == "vulnerable" or print_scan_result(type, r_2, cookie_str, payload, request_info) == "vulnerable":
                            break
                    elif request_info['method'] == "POST":
                        r = HackRequests(request_info).post_request()
                        if print_scan_result(type, r, cookie_str, payload, request_info) == "vulnerable":
                            break

def scan_get_request_from_path(request_info):
    """Scan all parameters in url for GET request

    Examples:
        GET /dvwa/vulnerabilities/xss_r/?name=helloworld HTTP/1.1
        Host: test.avfisher.win
        Cookie: security=low; PHPSESSID=a93qmi370veagks0j81k3rlu32

        Parameters in URL:
            name

    """
    print 'starat get scan'
    path = request_info['path']
    #if "?" in path and "&" in path:
    if path and "?" in path:  # Example of path: http://abc.xyz/index.html?para=test
        paras = path.split('?')[-1].split('&')
        for para in paras:
            if para:
                for payload in payloads:
                    payload_para = "{}{}".format(para, payload)
                    path_str = path.replace(para, payload_para)
                    request_info['path'] = path_str.strip()
                    type = "Path"
                    r_1 = HackRequests(request_info, LIB_1).get_request()
                    r_2 = HackRequests(request_info, LIB_2).get_request()
                    if print_scan_result(type, r_1, path_str, payload, request_info) == "vulnerable" or print_scan_result(type, r_2, path_str, payload, request_info) == "vulnerable":
                        break

def scan_post_request_from_post_data(request_info):
    print 'starat post scan'
    """Scan all parameters in post data for POST request

    Examples:
        POST /dvwa/vulnerabilities/xss_s/ HTTP/1.1
        Host: test.avfisher.win
        Cookie: security=impossible; security=low; PHPSESSID=a93qmi370veagks0j81k3rlu32
        Post Data:txtName=whatsup&mtxMessage=man&btnSign=Sign+Guestbook&user_token=b1ce437384e1bb75bdc8a3f02babe157

        Parameters in post data:
            txtName
            mtxMessage
            btnSign
            user_token

    """

    post_data = request_info['post_data']
    if post_data and "&" in post_data:
        paras = request_info['post_data'].split('&')
        for para in paras:
            if para:
                for payload in payloads:
                    payload_para = "{}{}".format(para, payload)
                    post_data_str = post_data.replace(para, payload_para)
                    request_info['post_data'] = post_data_str.strip()
                    type = "Post"
                    r = HackRequests(request_info).post_request()
                    if print_scan_result(type, r, post_data_str, payload, request_info) == "vulnerable":
                        break

def scan_get_request(request_info):
    if not is_checked_vulnerable(request_info['rid'], 'result_xss'):
        #scan_request_from_cookie(request_info)
        scan_get_request_from_path(request_info)

def scan_post_request(request_info):
    if not is_checked_vulnerable(request_info['rid'], 'result_xss'):
        #scan_request_from_cookie(request_info)
        scan_post_request_from_post_data(request_info)

def scanner(request):
    request_info = get_request_info(request)
    if request_info['method'] == "GET":
        scan_get_request(request_info)
    elif request_info['method'] == "POST":
        scan_post_request(request_info)

def main():
    exclude = get_scan_exclusion_info(fetch_exclusion_scan(0)[0])
    limit_num = 10000 # Number of limit of requests
    scan_type = 'scan_xss'
    requests = fetch_request(exclude, scan_type, limit_num)
    print len(requests)

    if requests:
        for request in requests:
            print 'request:',request
            try:
                scanner(request)
            except Exception, err:
                print highlight("[!] scanner failed: {}".format(str(err)), 'red')
                pass
    else:
        print highlight("[!] no new request found", 'yellow')


if __name__ == "__main__":
    while True:
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        delim = '.............................................'
        print "[*][{}] Time: {}\n{}".format('XSS Scan', highlight(str(now), 'green'), delim)
        main()
        time.sleep(5)
        print delim, '\n'
