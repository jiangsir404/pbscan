# -*- coding: utf-8 -*-

""" SQL Injection Scanner

This module provides functions that scan SQL Injection.

"""
import sys
sys.path.append('../')
import time, random
from lib.db_operation import db_query, update_scan_result, fetch_request, is_checked, get_request_info, fetch_exclusion_scan, get_scan_exclusion_info, get_sqlmap_info, fetch_sqlmap
from lib.utils import highlight
from lib.hack_sqlmapapi import HackSqlmapApi


def scan_sqli_request(request_info, sqlmapapi_server):
    delim = '.............................................\n'
    try:
        if not is_checked(request_info['rid'], 'scan_sqli'):
            print highlight('[*] request id: {}'.format(request_info['rid']), 'green')
            print highlight('[*] sqlmapapi server: {}'.format(sqlmapapi_server), 'green')
            run_scan_sqli = HackSqlmapApi(sqlmapapi_server, request_info)
            run_scan_sqli.run()
            if len(run_scan_sqli.data) == 0:
                result_sqli = 'not vulnerable'
                poc_sqli = ''
            else:
                result_sqli = 'vulnerable'
                poc_sqli = str(run_scan_sqli.data)
            update_scan_result(request_info['rid'], 'scan_sqli', 'result_sqli', result_sqli, 'poc_sqli', poc_sqli, 'response_sqli', poc_sqli)
            print delim
    except Exception, err:
        print highlight('[!] error: {}'.format(str(err)), 'red')
        print delim
        pass

def scanner(request):
    sqlmapapi_servers = []
    sqlmaps = fetch_sqlmap()
    for sqlmap in sqlmaps:
        sqlmap_info = get_sqlmap_info(sqlmap)
        sqlmapapi = "http://{}:{}/".format(sqlmap_info['ip'], sqlmap_info['port'])
        sqlmapapi_servers.append(sqlmapapi)
    if len(sqlmapapi_servers) > 0:
        sqlmapapi_server = random.sample(sqlmapapi_servers, 1)[0]
    else:
        sqlmapapi_server = 'http://127.0.0.1:8775/'
    request_info = get_request_info(request)
    scan_sqli_request(request_info, sqlmapapi_server)

def main():
    exclude = get_scan_exclusion_info(fetch_exclusion_scan(1)[0])
    limit_num = 10000 # Number of limit of requests
    scan_type = 'scan_sqli'
    requests = fetch_request(exclude, scan_type, limit_num)
    if requests:
        for request in requests: #requests是一个二元数组。
            scanner(request)
    else:
        print highlight("[!] no new request found", 'yellow')


if __name__ == "__main__":
    data = json.loads(sys.argv[-1])
    request_raw = data['body']
    token = data['token']


