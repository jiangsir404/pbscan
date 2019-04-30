#!/usr/bin/env python		
#coding:utf-8


import requests
from  threading import Thread
url = 'http://localhost:8084/scan/11'

data = 'POST /myctf/xss/form.php HTTP/1.1\r\nHOST:127.0.0.1\r\n\r\n'

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'}


def sendpost():
	html = requests.post(url,data=data,headers=headers,timeout=5)

for i in range(10):
	Thread(target=sendpost).start()
	#print html.content