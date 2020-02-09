#!/usr/bin/env python		
#coding:utf-8

import sys
sys.path.append('./')
sys.path.append('./Paste-3.0.5')
sys.path.append('./six-1.12.0')
print sys.path
import paste
from bottle import route,run,get,post,request
import time

@route('/hello')
def hello():
	return 'Hello,World!'

@route('/scan/<rid>',method = 'POST')
def scan(rid = None):
	if rid:
		print rid
		print request.body.read()
		time.sleep(3)


run(server='paste',host='0.0.0.0',port=8084,debug=True)