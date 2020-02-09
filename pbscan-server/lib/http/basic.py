#!/usr/bin/env python
#coding:utf-8

"""辅助性函数封装
1. detect_url_live: url存活性检测
"""

import requests


def detect_url_live(url):
    '''探测url存活性'''
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/43.0.2357.134 Safari/537.36',
            'Accept': 'text/html;q=0.9,*/*;q=0.8',
            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
            'Accept-Encoding': 'gzip, deflate'
        }
        res = requests.head(url=url, headers=headers, timeout=15)
        return True
    except:
        return False