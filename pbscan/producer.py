# -*- coding: utf-8 -*-

""" Parse Burp Request Log

This module is used to parse Burp Requests and insert into MySQL DB.

Usage:
    python parser_burp.py logs.txt

"""

import sys
import re
import MySQLdb
import hashlib
import time
import json
import urlparse
import urllib
from lib.db_operation import db_insert, db_query
from lib.utils import highlight, escape_content
from config import white_rules, scan_rules, black_rules,mydb
from pika_mq import send, send2

# 导入bottle api所需的依赖库
sys.path.append('./core/thirdpart/Paste-3.0.5')
sys.path.append('./core/thirdpart/six-1.12.0')
import paste
from core.bottle import route, run, get, post, request
from lib.parse_request import parse_request_info, parse_url_info,getRid,parse_request_service,request_filter,up

debug = 0
ENVIRONMENT = "Linux"
# ENVIRONMENT = "Windows"
# 不期待的文件后缀
IGNORE_EXT = ['css', 'js', 'jpg', 'png', 'gif', 'rar', 'pdf', 'doc', 'html']
# 期待的文件后缀
EXPECT_EXT = ['php', 'jsp', 'asp', 'aspx']


def is_duplicate(table, rid):
    try:
        sql = "SELECT COUNT(*) FROM {} where rid ='{}'".format(table, rid.strip())
        query_result = mydb.query(sql)
        count = [row[0] for row in query_result]
        if count[0] >= 1:
            return True
        else:
            return False
    except Exception, e:
        print highlight('[!] {}'.format(str(e)), 'red')
        return False





def insert_request(request, raw):
    if raw.startswith('\\r\\n'):
        raw = raw.lstrip('\\r\\n')
    try:
        # feeds = []
        # for key, value in request.items():
        #     if key != 'time':
        #         feeds.append(escape_content(value))
        # feeds_str = ",".join(feeds)
        # rid = hashlib.sha256(feeds_str).hexdigest()
        rid = getRid(raw)
        if not is_duplicate('requests', rid):
            now = str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
            table_request = 'requests'
            request['rid'] = rid
            request['update_time'] = now
            request['raw'] = raw

            table_response = 'responses'
            args_response = {}
            args_response['rid'] = rid
            args_response['update_time'] = now

            flag = 'insert'
        else:
            now = str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
            table_request = 'requests'
            args_request = {}
            args_request['update_time'] = now
            cons_request = {}
            cons_request['rid'] = rid

            table_response = 'responses'
            args_response = {}
            args_response['update_time'] = now
            cons_response = {}
            cons_response['rid'] = rid

            flag = 'update'
        if flag == 'insert':
            if db_insert(table_request, request) and db_insert(table_response, args_response):
                print highlight(
                    '[+] {} request rid: {}, url: {}://{}{}'.format(flag, rid, request['protocol'], request['host'],
                                                                    request['path']), 'green')
                return True
            else:
                return False
    except Exception, e:
        print highlight('[!] {}'.format(str(e)), 'red')
        return False


def get_file_to_array(log_file):
    with open(log_file, 'rb') as f:  # Note: Here is 'rb' rather than 'r'
        contents = f.readlines()
    num_of_delim = 0
    requests = []
    request_str = ''
    for i in range(len(contents)):
        if num_of_delim == 3:
            requests.append(request_str.strip('\r\n'))
            request_str = ''
            num_of_delim = 0
        if '======================================================' in contents[i]:
            num_of_delim += 1
        request_str += contents[i]
    return requests



# 发送消息到队列
def sendToMQ(data):
    #print data
    for k, v in scan_rules.items():
        if k == 'burp':
            send(json.dumps(data))  # 普通消息调度
        if k == 'poc':
            data['poc_name'] = v
            send2(json.dumps(data))  # 消息发布


'''
@两种数据包的来源方式
    1. parse_log 解析burpsuite 的代理日志
    2. api()  通过api的方式获取数据包
'''


# 解析burpsuite 的代理日志
def parse_log(log_file, token):
    requests = get_file_to_array(log_file)
    for request in requests:
        url_info = request.split('======================================================')[1]
        request_raw = request.split('======================================================')[2]
        url_info_parsed = parse_url_info(url_info)
        request_info_parsed = parse_request_info(request_raw)  # raw to dict
        request_parsed = dict(url_info_parsed, **request_info_parsed)
        request_parsed['token'] = token
        if request_filter(request_parsed, '', black_rules):
            insert_result = insert_request(request_parsed, request_raw)  # Insert Burp requests into Database
            if insert_result:  # 如果插入/更新成功，就将数据包存入队列，不具备去重
                if request_raw.startswith('\r\n'):
                    request_raw = request_raw.lstrip('\r\n')
                if not is_duplicate('results', getRid(request_raw)):  # 去重，如果以及扫描过了，就不再进行扫描(不区分token去重))
                    data = {'token': 'parse_burp_log', 'body': request_raw}  # 给parse_log 设置一个专门的token叫parse_burp_log
                    sendToMQ(data)  # 用json序列化字典

            # print 'filter:',request_parsed['method'],request_parsed['path'],request_parsed['host']


# 使用api的方式获取数据包
def api():
    @route('/scan/', method='POST')
    def scan():
        token = request.query.token
        if token:
            postdata = request.body.read()
            flag1 = request_filter(parse_request_service(postdata),'',black_rules) #url 去重
            flag2 = is_duplicate('results', getRid(postdata))  # results 表去重，如果以及扫描过了，就不再进行扫描(不区分token去重))
            flag3 = is_duplicate('requests',getRid(postdata)) # requests 表去重
            if flag1 == True:
                if flag2 == flag3 == False:
                    data = {'token': token, 'body': postdata}
                    sendToMQ(data)
                    return 'send to burp scan'
                else:
                    return 'fail:repeat scan'
            else:
                return 'fail: %s'%flag1

    # bottle+paste 实现非阻塞的web服务器
    run(server='paste', host='0.0.0.0', port=7001, debug=True)


def main1():
    while True:
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        delim = '.............................................'
        print "[*][{}] Time: {}\n{}".format('Requests Analysis', highlight(str(now), 'green'), delim)
        parse_log('log/burp.log', 'parse_burp_log')
        time.sleep(5)
        print delim, '\n'


def main():
    op = sys.argv[1]
    if op == 'parselog':
        main1()
    if op == 'auto':
        print 'start listen 7000'
        api()


if __name__ == "__main__":
    main()