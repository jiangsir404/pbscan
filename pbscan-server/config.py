#!/usr/bin/env python
#coding:utf-8
from lib.db.mysql import Mysql

hostname = 'http://localhost'
debug = False
dbuser = 'root'
dbpass = 'root'
dbname = 'pbscan'
mydb = Mysql(dbuser, dbpass, dbname)

scan_rules = {
    "burp":3,
    "poc":"sqlmapapi.py"
}

white_rules = [
]

black_rules = [
    '*.baidu.com',
    '*.google.com',
    '*.github.com'
]
