#!/usr/bin/env python        
# coding:utf-8


# burpsuite 接口
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
# from java.net import URL
from java.io import File

# python 标准库
from colorprint import Logger
import time
import os
import urlparse
import urllib
import hashlib
import sys
import json

# 导入bottle api所需的依赖库
sys.path.append('./thirdpart/Paste-3.0.5')
sys.path.append('./thirdpart/six-1.12.0')
import paste
from bottle import route, run, get, post, request

'''
@burpsuite scan api plugin (base headless)

	-f=data.txt 添加file, 读取数据包，然后发送给scanner
	-proxy: 开启代理，将流量保存到../log/burp.log中
	-debug: 开启调试
	-auto:  开启内置bottle服务器对api接口监听
'''

logger = Logger()


class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def __init__(self):
        # 参数
        self.debug = 0
        self.file = 0
        self.proxy = 0  # 默认不启用监听功能
        self.auto = 0  # 默认手动输入扫描数据包

        # httpservice 信息
        self.scheme = ''
        self.port = 80
        self.host = ''

        # 扫描数据
        self.queueItems = []
        self.spider_results = []
        self.spider_all_results = []
        self.scanner_results = []
        self.packet_timeout = 300  # 发包超时时间5min
        self.scan_timeout = 600 #扫描超时时间10min

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Carbonator")
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.issueAlert("Loaded Successfull.")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerListener(self)
        self.last_packet_seen = int(time.time())  # 初始化

        if not self.processCLI():  # 接受命令行
            return None

        # -f/-file 参数读取数据包
        if self.file:
            print 'send file %s to scanner' % self.file
            base_request = ''
            with open(self.file) as f:
                base_request = f.read()
            self.sendScanner(base_request)
            self.monitorQueue()  # 这个函数是耗时的，不要放到sendScanner中去,如果auto，则不会到这一步。
            self._callbacks.issueAlert("remove Listener")
            self._callbacks.removeHttpListener(self)
            self._callbacks.removeScannerListener(self)

            self._callbacks.issueAlert("Generating Report")
            self.generateReport('HTML')

            self._callbacks.exitSuite(True)

        # -proxy设置代理
        if self.proxy:
            self._callbacks.issueAlert("start proxy listener")

        # -auto 开启bottle内置服务器api
        if self.auto:
            self.api()

    # -------------------------- burpsuite 内置api接口 ---------------------------------
    # 使用内嵌函数，非闭包
    def api(self):
        @route('/scan/', method='POST')
        def scan():
            token = request.query.token
            if token:
                data = request.body.read()
                if self.debug:
                    print token
                    print data
                return self.sendScanner(data, token)

        @route('/get/status/', method='GET')
        def getStatus():
            token = request.query.token
            return self.getStatus(token)

        # @route('/generate',method='GET')
        # def generate():
        # 	self.generateReport('HTML')

        self._callbacks.issueAlert('listen to %s'%str(self.auto))
        run(server='paste', host='127.0.0.1', port=self.auto, debug=True)  # paste+bottle 实现非阻塞式web服务器

    # ------------------------- burpsuite 扫描以及扫描结果监控-----------------------------
    def sendScanner(self, base_request, token=None):
        httpService, base_request = self.parseReq(base_request)
        if self.debug:
            print 'base_request:', self.b2s(base_request)
            self._callbacks.issueAlert(logger.debug(self.b2s(base_request).replace('\n', '\\n').replace('\r', '\\r')))

        # 输出扫描信息
        print 'send to scan:', httpService['method'], httpService['host'] + ':' + str(httpService['port']) + \
                                                      httpService['path']
        self._callbacks.issueAlert(logger.info(
            'send to scan: ' + httpService['method'] + ' ' + httpService['host'] + ':' + str(httpService['port']) +
            httpService['path']))
        httpService['scanTime'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        httpService['time'] = int(time.time())
        if (self.scheme == 'HTTPS'):
            self.queueItems.append([token, httpService,
                                    self._callbacks.doActiveScan(httpService['host'], httpService['port'], 1,
                                                                 base_request)])
        else:  # 默认是http 处理
            self.queueItems.append([token, httpService,
                                    self._callbacks.doActiveScan(httpService['host'], httpService['port'], 0,
                                                                 base_request)])
        return 'send success'

    def monitorQueue(self):
        self._callbacks.issueAlert('monitor queue start:')
        print 'monitor start:'
        try:
            print self.queueItems
            startime = int(time.time())
            while len(self.queueItems) > 0:
                for queueItem in self.queueItems:
                    scanToken = queueItem[0]
                    scanItem = queueItem[2]  # [token,item]
                    nip = scanItem.getNumInsertionPoints()
                    issues = scanItem.getIssues()
                    status = scanItem.getStatus()
                    requests_num = scanItem.getNumRequests()
                    percentag = scanItem.getPercentageComplete()

                    if status == 'finished':  # 如果该任务扫描完成，就从列表里面移除。
                        self.queueItems.remove(queueItem)
                        self.scanner_results.extend(issues)

                    # 如果扫描超过15s以及发包暂停15s,则认为超时，手动取消
                    if (int(time.time()) - startime >= self.packet_timeout) and (
                            int(time.time()) - self.last_packet_seen >= self.packet_timeout):  # 如果线程停止超时，则取消掉该任务
                        print 'time out', (int(time.time()) - startime >= self.packet_timeout), (
                                    int(time.time()) - self.last_packet_seen >= self.packet_timeout)
                        scanItem.cancel()
                        self.queueItems.remove(queueItem)
                    print 'info:', {'token': scanToken, 'status': status, 'issues': issues, 'insertpoint': nip,
                                    'issues': issues, 'queueItems': self.queueItems}
                    self._callbacks.issueAlert(logger.info(status))
                time.sleep(3)

            print 'scan compelete:', {'token': scanToken, 'status': status, 'issues': issues, 'insertpoint': nip,
                                      'issues': issues, 'queueItems': self.queueItems}
            self._callbacks.issueAlert(
                logger.info('scan result issues:' + str(len(issues)) + " requests:" + str(requests_num)))

            if self.debug:
                if len(self.spider_all_results) > 0:
                    print self.spider_all_results[0]
                    self._callbacks.issueAlert(logger.debug(self.spider_all_results[0]))

        except Exception, e:
            print e

    def getStatus(self, userToken):
        # print self.queueItems
        messages = []
        print self.queueItems, len(self.queueItems)
        for queueItem in self.queueItems:
            scanToken = queueItem[0]
            httpService = queueItem[1]
            scanUrl = httpService['method']+' '+httpService['host']+':'+str(httpService['port'])+httpService['path']
            scanItem = queueItem[2]
            nip = scanItem.getNumInsertionPoints()
            issues = scanItem.getIssues()
            status = scanItem.getStatus()
            requests_num = scanItem.getNumRequests()
            percentag = scanItem.getPercentageComplete()
            if not userToken: #如果没有设置token,默认获取所有的结果。
                userToken = 'all'
            if userToken == 'all' or userToken == scanToken:  # 看该userToken是否和scanToken匹配
                if self.debug:
                    print scanToken, scanItem, issues, status, requests_num
                if 'abandoned' in status:  # 或者被废弃,就从列表里面移除,并且取消掉该扫描
                    self.queueItems.remove(queueItem)
                    continue
                # 如果扫描超时和发包超时，就认为当前burp以及卡住停止扫描了，取消掉一些扫描超时的项目。
                if (status != 'finished') and (int(time.time()) - httpService['time'] > self.scan_timeout) and (int(time.time()-self.last_packet_seen > self.packet_timeout)):
                    self.queueItems.remove(queueItem)
                    print 'time out,cannel the scan,status:'+status
                    self._callbacks.issueAlert(logger.warning('time out,cannel the scan,status:'+status))
                    scanItem.cancel()
                    continue

                issuesList = self.parseIssues(issues)
                # print 'issuesList',issuesList
                if status == 'finished': #如果扫描完成，就从queueItem中移除，并且生成报表。
                    self.queueItems.remove(queueItem)
                    try:
                        saveFile = self.generateReport('HTML', issues, scanToken)  # 扫描完成，保存该scanItem的issues为一个单独的文件。
                        messages.append(
                            {'token': scanToken, 'rid': httpService['rid'], 'status': status, 'issues_num': len(issues),
                             'issues': len(issues), 'request_num': requests_num,
                             'insert_point': nip, 'issues': issuesList, 'scanTime': httpService['scanTime'],
                             'saveFile': saveFile,'scanUrl':scanUrl})
                    except Exception, e:
                        messages.append({'token': scanToken, 'status': status, 'msg': 'save error'})

                else:
                    messages.append(
                        {'token': scanToken, 'rid': httpService['rid'], 'status': status, 'issues_num': len(issues),
                         'request_num': requests_num, 'insert_point': nip, 'scanTime': httpService['scanTime'],'scanUrl':scanUrl})

            if len(messages) > 10: #只获取前10条的数据,防止扫描程序太多阻塞结果获取。
                return json.dumps(messages)

        if messages:
            return json.dumps(messages)
        else:
            return json.dumps([])

    # -----------------------httpListener 监听(多线程，非阻塞式) ------------------------------
    def processHttpMessage(self, tool_flag, isRequest, current):
        self.last_packet_seen = int(time.time())
        print 'http listen', tool_flag
        if (tool_flag == self._callbacks.TOOL_SCANNER) and not isRequest:
            self.spider_all_results.append(self.b2s(current.getResponse()))

        if (tool_flag == self._callbacks.TOOL_PROXY) and isRequest:
            print 'proxy data:'
            httpservice = self.parse_request_service(self.b2s(current.getRequest()))
            print 'proxy:', httpservice['method'], httpservice['host'], httpservice['path']
            self._callbacks.issueAlert(
                logger.info('proxy: ' + httpservice['method'] + ' ' + httpservice['host'] + ' ' + httpservice['path']))

    # ---------------------- issue 以及 结果报表生成 --------------------------------
    def newScanIssue(self, issue):
        print 'New issue find:' + issue.getIssueName()
        if self.debug:
            print 'issue http', issue.getHttpMessages(), type(issue.getHttpMessages()[1])
            print 'issue url', issue.getUrl()
            print 'issue service', issue.getHttpService()
            print "issue req:" + self.b2s(issue.getHttpMessages()[0].getRequest())
            self._callbacks.issueAlert(logger.info('New issue find: Issue' + issue.getIssueName()))
            self._callbacks.issueAlert(logger.info("issue req:" + self.b2s(issue.getHttpMessages()[0].getRequest())))

        return

    def generateReport(self, format, issues=None, token=''):
        if format != 'XML':
            format = 'HTML'

        if issues == None:
            issues = self.scanner_results

        print 'scann result:', issues
        file_name = '../output/burp_report_' + token + '_' + time.strftime(
            "%Y%m%d%H%M%S", time.localtime(time.time())) + '.' + format.lower()
        self._callbacks.generateScanReport(format, issues, File(file_name))
        # os.system('python3 parsexml.py ' + file_name)
        time.sleep(1)
        return file_name.strip('../output/')

    # ------------------- 一些助手函数的封装 -----------------------------

    def b2s(self, request):
        return self._helpers.bytesToString(request)

    def s2b(self, request):
        return self._helpers.stringToBytes(request)

    # 获取请求包的hash
    def getRid(self, request_raw):
        content = request_raw.replace('\n', '').replace('\r', '')
        rid = hashlib.sha1(content).hexdigest()
        return rid

    # @ 返回issue 信息字典
    def parseIssues(self, issues):
        issueList = []
        for issue in issues:
            issueName = issue.getIssueName()
            issueRequest = self.b2s(issue.getHttpMessages()[0].getRequest())
            issueSeverity = issue.getSeverity()
            issueConfidence = issue.getConfidence()
            issueDetail = issue.getIssueDetail()
            issueList.append({'issueName': issueName, 'issueRequest': issueRequest, 'issueSeverity': issueSeverity,
                              'issueConfidence': issueConfidence, 'issueDetail': issueDetail})
        return issueList

    # @ 返回httpService信息(host,port,path,method) 和 处理后的base_request
    def parseReq(self, base_request):
        httpService = self.parse_request_service(base_request)
        httpService['rid'] = self.getRid(base_request)
        # 处理GET请求
        if base_request.startswith('GET'):
            if not base_request.endswith("\n\n"):
                base_request = base_request + "\n\n"
            base_request = self.s2b(base_request)

        # 处理POST请求
        elif base_request.startswith('POST'):
            print list(base_request)
            if '\r\n' in base_request:  # linux
                request = base_request.split('\r\n\r\n')
                headers = request[0].split('\r\n')
                body = self.s2b(request[1])
            else:  # window
                request = base_request.split('\n\n')
                headers = request[0].split('\n')
                body = self.s2b(request[1])
            base_request = self._helpers.buildHttpMessage(headers, body)

        # base_request = self.b2s(base_request)
        return httpService, base_request

    def get_item_info(self, line, item, delim):
        if item in line:
            item_info = line.split(delim)[1].strip()
        else:
            item_info = ''
        return item_info

    def parse_request_service(self, request_info):
        if '\r\n' in request_info:
            lines = request_info.split('\r\n')  # For Linux
        else:
            lines = request_info.split('\n')  # For Windows
        requestinfo = {}
        method = lines[0].split(' ')[0]
        path = lines[0].split(' ')[1]
        for line in lines:
            if line.startswith('Host'):
                host = line.partition(':')[-1]
                if ':' in host:
                    requestinfo['host'] = host.split(':')[0].strip()
                    requestinfo['port'] = int(host.split(':')[-1].strip())
                else:
                    requestinfo['host'] = host.strip()
                    requestinfo['port'] = 80
                if method:
                    requestinfo['method'] = method
                if path:
                    requestinfo['path'] = path
                return requestinfo
        return None

    # 命令行参数获取
    def processCLI(self):
        cli = self._callbacks.getCommandLineArguments()
        print 'cli:', cli
        if len(cli) < 0:
            print "Incomplete target information provided."
            return False
        elif not cli:
            print "please input url"
            return False
        else:
            for para in cli:
                if para.split('=')[0] == '-debug':
                    self.debug = True
                if para.split('=')[0] == '-proxy':
                    self.proxy = True
                if para.split('=')[0] == '-auto':
                    self.auto = int(para.partition('=')[-1])
                if para.split('=')[0] == '--file' or para.split('=')[0] == '-f':
                    self.file = para.partition('=')[-1]
            return True
