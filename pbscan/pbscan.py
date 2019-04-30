#!/usr/bin/env python
# coding:utf-8

import argparse
import os.path
import os,sys

runHeadless = False
debug = False
proxy = False
auto = 0
burpPath = 'burpsuite_pro_v1.7.32.jar'

def runBurp(file):
	if file and os.path.isfile(file):
		file  = os.getcwd()+'/'+file
	os.chdir('./core')
	isdebug = ' -debug' if(debug == True) else ''
	isproxy = ' -proxy' if(proxy == True) else ''
	isauto = ' -auto=%s'%auto if(auto) else ''
	if runHeadless == True and file:
		cmd = 'java -jar  -Xbootclasspath/p:burp-loader-keygen.jar -Djava.awt.headless=true '+burpPath+' --config-file=burp.json --user-config-file=UserConfigPro.json -f=%s'%file + isdebug + isproxy + isauto
	elif runHeadless == False and file:
		cmd = 'java -jar -Xbootclasspath/p:burp-loader-keygen.jar '+burpPath+' --config-file=burp.json --user-config-file=UserConfigPro.json -f=%s'%file + isdebug + isproxy + isauto
	elif runHeadless == True and proxy:
		cmd =  'java -jar -Xbootclasspath/p:burp-loader-keygen.jar -Djava.awt.headless=true '+burpPath+' --config-file=proxy.json --user-config-file=UserConfigPro.json' + isdebug + isproxy
	elif runHeadless == False and proxy:
		cmd =  'java -jar -Xbootclasspath/p:burp-loader-keygen.jar '+burpPath+' --config-file=proxy.json --user-config-file=UserConfigPro.json' + isdebug + isproxy
	elif runHeadless == True and auto:
		cmd =  'java -jar -Xbootclasspath/p:burp-loader-keygen.jar -Djava.awt.headless=true '+burpPath+' --config-file=burp.json --user-config-file=UserConfigPro.json' + isdebug  + isauto
	elif runHeadless == False and auto:
		cmd =  'java -jar -Xbootclasspath/p:burp-loader-keygen.jar '+burpPath+' --config-file=burp.json --user-config-file=UserConfigPro.json' + isdebug  + isauto
	print cmd
	os.system(cmd)

parser = argparse.ArgumentParser(description='Burp automator')
parser.add_argument('-f',  help='File containing Domain names or IP addresses')
parser.add_argument('-headless', action='store_true', help='Run Burp headless')
parser.add_argument('-debug', action='store_true', help='debug')
parser.add_argument('-proxy', action='store_true', help='open proxy')
parser.add_argument('-auto', default=0, help='auto')
args = parser.parse_args()

if args.f == None and args.proxy == False and args.auto == False:
	print "\n[!] Please run 'python2.7 pbscan.py -h'\n"
	sys.exit()
else:
	if args.headless:
		#global runHeadless
		runHeadless=True
	if args.debug:
		debug = True
	if args.auto:
		auto = args.auto
		runBurp(args.f)
	if args.proxy:
		proxy = True
		runBurp(args.f)
	if args.f:
	    runBurp(args.f)
	else:
		print "\n[!] Please check your input filename.\n"
		sys.exit()

