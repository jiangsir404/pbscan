#!/usr/bin/env python		
#coding:utf-8

import requests
import sys
import json

token = 'parse_burp_log'

with open('../data.txt') as f:
	data = f.read()

option = sys.argv[1]
if len(sys.argv) == 3:
	token = sys.argv[2]

scan_api = "http://localhost:8084/scan/?token="+token
getStatus_api = 'http://localhost:8084/get/status/?token='+token

if option == 'scan':
	rep = requests.post(url=scan_api,data=data)
	print rep.text
if option == 'get':
	rep = requests.get(url=getStatus_api)
	
	data = json.loads(rep.text)
	print 'reveive data',len(data)
	print data
	#print rep.text

