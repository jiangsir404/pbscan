# -*- coding: utf-8 -*-



import sys
import re
import requests

token = 'tttttttttttttttttttt'
scanApi = 'http://127.0.0.1:7001/scan/?token=%s'%token

with open('./data.txt') as f:
	data = f.read()


rep = requests.post(url=scanApi,data=data)
print rep.text


