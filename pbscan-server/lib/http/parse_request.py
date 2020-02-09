# -*- coding: utf-8 -*-

'''解析request请求函数封装脚本
功能:
    1. parse_request_info解析数据包字段到一个字典
    2. parse_url_info 解析url基本信息: host,port,method,path
'''

import re
import hashlib
import urlparse


ENVIRONMENT = "Linux"
# ENVIRONMENT = "Windows"
# 不期待的文件后缀
IGNORE_EXT = ['css', 'js', 'jpg', 'png', 'gif', 'rar', 'pdf', 'doc', 'html']
# 期待的文件后缀
EXPECT_EXT = ['php', 'jsp', 'asp', 'aspx']


def getRid(request_raw):
    """获取请求包的hash
    """
    content = request_raw.replace('\n', '').replace('\r', '')
    rid = hashlib.sha1(content).hexdigest()
    return rid


def get_item_info(line, item, delim):
    if item in line:
        item_info = line.split(delim)[1].strip()
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

def parse_url_info(url_info):
    urlinfo = {}
    if len(url_info.strip('\r\n').split('  ')) == 3:
        time, url, ip = url_info.strip('\r\n').split('  ')
    else:
        time, url = url_info.strip('\r\n').split('  ')
        ip = ""
    if url:
        protocol = url.split(':')[0]
        port = url.split(':')[-1]
    if ip:
        se = re.search('.*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}?)\].*', ip)
        if se:
             ip = se.group(1).strip()
             urlinfo['time'], urlinfo['protocol'], urlinfo['port'], urlinfo['ip'] = time, protocol, port, ip
    else:
        urlinfo['time'], urlinfo['protocol'], urlinfo['port'] = time, protocol, port
    return urlinfo

def parse_request_info(request_info):
    """将数据包解析成dict字典类型"""
    if ENVIRONMENT == "Linux":
        lines = request_info.split('\r\n') # For Linux
    elif ENVIRONMENT == "Windows":
        lines = request_info.split('\n') # For Windows
    requestinfo = {}
    for line in lines[1:]:
        if 'HTTP/' in line:
            method = line.split(' ')[0]
            path = line.split(' ')[1]
        host = get_item_info(line, 'Host:', ': ')
        user_agent = get_item_info(line, 'User-Agent:', ': ')
        accept = get_item_info(line, 'Accept:', ': ')
        accept_language = get_item_info(line, 'Accept-Language:', ': ')
        accept_encoding = get_item_info(line, 'Accept-Encoding:', ': ')
        content_type = get_item_info(line, 'Content-Type:', ': ')
        referer = get_item_info(line, 'Referer:', ': ')
        cookie = get_item_info(line, 'Cookie:', ': ')
        if method:
            requestinfo['method'] = method
        if path:
            requestinfo['path'] = path
        if host:
            requestinfo['host'] = host
        if user_agent:
            requestinfo['user_agent'] = user_agent
        if accept:
            requestinfo['accept'] = accept
        if accept_language:
            requestinfo['accept_language'] = accept_language
        if accept_encoding:
            requestinfo['accept_encoding'] = accept_encoding
        if content_type:
            requestinfo['content_type'] = content_type
        if referer:
            requestinfo['referer'] = referer
        if cookie:
            requestinfo['cookie'] = cookie
    if requestinfo['method'] == "POST":
        post_data = lines[-2]
        requestinfo['post_data'] = post_data
    return requestinfo

def parse_request_service(request_raw):
    """解析数据包的基本信息
        :return:
        {
            "host":"",
            "port":"",
            "method":"",
            "path":"",
            "body":""
        }
    """
    if '\r\n' in request_raw:
        lines = request_raw.split('\r\n')  # For Linux
    else:
        lines = request_raw.split('\n')  # For Windows
    print lines
    requestinfo = {}
    method = lines[0].split(' ')[0]
    path = lines[0].split(' ')[1]
    for line in lines:
        if line.startswith('Host'):
            host = line.partition(':')[-1]
            if ':' in host:
                requestinfo['host'] = host.split(':')[0].strip()
                requestinfo['port'] = int(host.split(':')[-1].strip())
            else:
                requestinfo['host'] = host.strip()
                requestinfo['port'] = 80
            if method:
                requestinfo['method'] = method
            if path:
                requestinfo['path'] = path
            if '\r\n' in request_raw:  # linux
                request = request_raw.split('\r\n\r\n')
                if len(request) > 1:
                    body = request[1]
                else:
                    body = None
            else:  # window
                request = request_raw.split('\n\n')
                #print request
                if len(request) > 1:
                    body = request[1]
                else:
                    body = None
            if body:
                requestinfo['body'] = body
            return requestinfo
    return None


# ----------------------数据去重-----------------------

up = lambda x: urlparse.urlparse(x)
debug = 0

def front_netloc(url):
    if len(url.split('.')) == 2:
        return url
    return url.partition('.')[-1]  # 这样取当前子域的上一级域名。


def request_filter(request_info, _white_rules, _black_rules):
    """数据去重
        1. 黑白名单过滤
        2. 过滤静态资源后缀
        3. 过滤get请求没有参数的数据包
    :param request_info: 解析后的request请求数据包
    :param _white_rules:
    :param _black_rules:
    :return: True/False
    """
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
        return 'not expect ext'
    if method == 'GET' and url_struct.query == '':  # 过滤伪静态或纯静态页面
        return 'static page'


    if _black_rules:
        for black_rule in _black_rules:
            if black_rule.startswith('*'):  # 通配符方式
                pattern = '.*' + front_netloc(black_rule)
                if re.match(pattern, host):  # 如果再黑名单中，则返回False
                    return 'blackrule filter'
            else:
                if black_rule == host:  # 同上
                    return 'blackrule filter'

    if _white_rules:
        for white_rule in _white_rules:
            if white_rule.startswith('*'):
                pattern = '.*' + front_netloc(white_rule)
                if re.match(pattern, host):  # 如果再白名单中，返回True
                    return True
            else:
                if white_rule == host:
                    return True

        return 'white rule filter'

    return True