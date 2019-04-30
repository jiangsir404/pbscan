# -*- coding: utf-8 -*-



import sys
import re
import requests

token = 'tttttttttttttttttttt'
scanApi = 'http://192.168.23.129:7001/scan/?token=%s'%token

with open('data.txt') as f:
	data = f.read()

option = sys.argv[-1]
if option == 'scan':
	rep = requests.post(url=scanApi,data=data)
	print rep.text


