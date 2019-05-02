# -*- coding: utf-8 -*-

import sys
import re
import hashlib
import time
import json
import urlparse
import urllib

sys.path.append('../')
from lib.parse_request import parse_request_service
from config import black_rules,white_rules



debug = 1


up = lambda x: urlparse.urlparse(x)


def front_netloc(url):
    if len(url.split('.')) == 2:
        return url
    return url.partition('.')[-1]  # 这样取当前子域的上一级域名。


def request_filter(request_info, _white_rules, _black_rules):
    if not request_info.has_key('host'):  # method,path,host 必须有
        return False
    path = request_info['path']
    method = request_info['method']
    host = request_info['host']
    if debug:
        print method, host, path
    if ':' in host:  # 如果有端口，则之获取前半部分
        host = host.split(':')[0]
    url_struct = up(path)
    ext = url_struct[2].split('.')[-1]
    if ext in IGNORE_EXT:
        return False
    if method == 'GET' and url_struct.query == '':  # 过滤伪静态或纯静态页面
        return False


    if _black_rules:
        for black_rule in _black_rules:
            if black_rule.startswith('*'):  # 通配符方式
                pattern = '.*' + front_netloc(black_rule)
                if re.match(pattern, host):  # 如果再黑名单中，则返回False
                    if debug:
                        print 'blackrule filter'
                    return False
            else:
                if black_rule == host:  # 同上
                    if debug:
                        print 'blackrule filter'
                    return False

    if _white_rules:
        for white_rule in _white_rules:
            if white_rule.startswith('*'):
                pattern = '.*' + front_netloc(white_rule)
                if re.match(pattern, host):  # 如果再白名单中，返回True
                    return True
            else:
                if white_rule == host:
                    return True
        if debug:
            print 'white rule filter'
        return False

    if debug:
        print 'bypass'
    return True

postdata = open('../data.txt').read()

white_rules = [
]

black_rules = [
]

print request_filter(parse_request_service(postdata),'',black_rules)