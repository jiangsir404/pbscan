#!/usr/bin/env python
# coding:utf-8

"""消费者脚本
负责从消息队列中获取数据，然后发送到burp的扫描结果，以及解析burp扫描的结果并且保存到数据库中

Usage:
    python consumer.py burp 8083 //表示发送到burp监听的8083端口
    TODO: python consumer.py poc 8084 //表示发送到poc监听的8084端口
"""

# 标准库
import sys
import time
import json
import requests
import gevent
from gevent import monkey
monkey.patch_all()

# 第三方库
from lib.utils.pika_mq import receive, receive2
from config import scan_rules, debug, mydb
from lib.http.parse_request import parse_request_service, getRid
from lib.http.basic import detect_url_live

reload(sys)
sys.setdefaultencoding('utf8')

scan_port = sys.argv[2];
scan_api = "http://localhost:"+scan_port+"/scan/?token=%s"
getStatus_api = "http://localhost:"+scan_port+"/get/status/?token="
print 'scan api:',scan_api


def saveRequest(token, request_raw):
    request_info = parse_request_service(request_raw)
    rid = getRid(request_raw)
    request_info['rid'] = rid
    request_info['token'] = token
    request_info['update_time'] = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time()))
    return request_info


def sendToScan(token, body):
    """
    发送到burp扫描api接口
    :param token: 用户token
    :param body: 完整数据包
    :return: save success or error
    """
    url = scan_api % token
    request_service_info = parse_request_service(body)
    if detect_url_live('http://'+request_service_info['host']+':'+str(request_service_info['port'])+request_service_info['path']):
        # 先检测数据包的存活性，然后再发送到burp扫描
        try:
            res = requests.post(url, data=body,timeout=5).text
            if res:
                request_info = saveRequest(token,body);
                request_info['scan_burp'] = 0
                if not mydb.is_duplicate('requests',getRid(body),token): #多次去重，防止因为扫描延时导致重复插入
                    mydb.insert('requests', request_info)
                return res
            else:
                pass
        except Exception,e:
            print e
    else:
        print 'url time out'


def getStatus():
    """解析api反馈的结果，并且存入数据库

        扫描结果json格式如下:
        '''
        {'token': userToken, 'status': status, 'issues': len(issues),
         'request num': requests_num,'insert point': nip,'issues':issuesList,'scanTime':httpService['scanTime']}'
        '''
    :return: None
    """
    while True:  # 不需要退出
        url = getStatus_api
        try:
            res = requests.get(url,timeout=15).text #请求一定要捕获超时异常，否则可能会导致该协程停止运行，如果数据量很多的话，很容易卡住这一块，因此需要超时更长
            if res:
                resdata = json.loads(res)
                print 'receive data:', len(resdata)
                if len(resdata) == 0:
                    print 'no task runing,sleep 10s'
                    time.sleep(10)
                if debug:
                    print resdata
                for line in resdata:
                    if line['status'] == 'finished':
                        issues = line.pop('issues')
                        try:
                            mydb.update('requests', {'scan_burp': 1}, {'token': line['token'], 'rid': line['rid']})
                            if not mydb.is_duplicate('results',line['rid'],line['token']): #如果已经保存了记录，就不重复插入results和issues表。
                                mydb.insert('results', line)
                                for issue in issues:
                                    issue['token'] = line['token']
                                    issue['rid'] = line['rid']
                                    httpService = parse_request_service(issue['issueRequest'])
                                    url = httpService['host'] + ':' + str(httpService['port']) + httpService['path']
                                    if httpService['method'].lower() == 'get':
                                        issue['issueUrl'] = httpService[
                                                                'method'] + ' <a href="http://{0}" target="_blank">{0}</a>'.format(url)
                                    if httpService['method'].lower() == 'post':
                                        issue['issueUrl'] = httpService[
                                                                'method'] + ' <a href="http://{0}" target="_blank">{0}</a>'.format(
                                            url) + '\r\nbody: ' + httpService['body']
                                    mydb.insert('issues', issue)
                                print 'save success'
                        except Exception, e:
                            print 'error1',e,'res:',res
                    else:
                        print line
                    time.sleep(3) #每3s获取一次结果
        except Exception,e:
            print 'error2',e


def handle(id, body):
    """传给receive函数的调度函数

    sendToScan和getStatus需要异步操作，否则就会阻塞，虽然可以开启多个线程，但当多个线程都被阻塞后就没法跑了。
    res2 = getStatus()
    print ' [x]',res2
    print " [x] Done"
    """
    print " [x] Consumer_%s Received,send to burp scan" % (str(id))
    body = json.loads(body)
    token = body['token']
    data = body['body']
    if debug:
        print 'token:', token
        print 'data:', data
    res1 = sendToScan(token, data)
    time.sleep(1) # 每次发送完一次
    print ' [x]', res1


def handle2(id, body):
    """TODO: POC调度函数
    """
    print " [x] Consumer_%s Received,send to poc scan" % (str(id))
    print body
    time.sleep(3)


def main(scan_type):
    task = []
    for k, v in scan_rules.items():
        if k == 'burp' and k in scan_type:  # k='burp',v=开启线程数量，每个线程对应burpsuite 的扫描程序。
            # 用协程
            task.append(gevent.spawn(receive, 0, handle)) #scan只需要用一个协程就够了，太多了容易阻塞。
            task.append(gevent.spawn(getStatus))

        # receive('0',handle)
        # getStatus()
        elif k == 'poc' and k in scan_type:
            for poc_name, num in v.items():
                task.extend([gevent.spawn(receive2, i, handle2) for i in range(num)])

    gevent.joinall(task)


scan_type = sys.argv[1].split(',')
main(scan_type)
