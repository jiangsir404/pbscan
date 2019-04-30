#!/usr/bin/env python		
#coding:utf-8

import hashlib
import sys

with open('../data.txt') as f:
    data = f.read()



def getRid(request_raw):
    content = request_raw.replace('\n','').replace('\r','')
    print content
    rid = hashlib.sha1(content).hexdigest()
    print rid 

getRid(data)
    