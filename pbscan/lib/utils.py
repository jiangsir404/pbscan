# -*- coding: utf-8 -*-

import MySQLdb
import smtplib
import time
from email.mime.text import MIMEText

def highlight(content, color, ENVIRONMENT='Linux'):
    if ENVIRONMENT=='Linux':
        if color == "red":
            content = "\033[1;31;40m{}\033[0m".format(content)
        if color == "green":
            content = "\033[1;32;40m{}\033[0m".format(content)
        if color == "yellow":
            content = "\033[1;33;40m{}\033[0m".format(content)
        if color == "blue":
            content = "\033[1;34;40m{}\033[0m".format(content)
    return content

def escape_content(content):
    content = MySQLdb.escape_string(content)
    return content

def logging(log_file, content):
    f=open(log_file,'a')
    now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    f.write(str(now)+': '+content.strip()+'\n')
    f.close
