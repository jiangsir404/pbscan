# -*- coding: utf-8 -*-

""" SQLMap API Operations

This module is used to call sqlmapapi to check sql injection.

"""

import json
import requests
import time
from lib.utils import highlight
from threading import Thread


TIME_OUT = 30
class HackSqlmapApi(Thread):
    def __init__(self, server, request_info):
        Thread.__init__(self)
        self.server = server
        if self.server[-1] != '/':
            self.server = self.server + '/'
        self.request_info = request_info
        self.target = "{}://{}{}".format(self.request_info['protocol'], self.request_info['host'], self.request_info['path'])
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.start_time = time.time()

    def task_new(self):
        url = "{}task/new".format(self.server)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            self.taskid = res['taskid']
            print highlight('[*] created new task: {}'.format(self.taskid), 'green')
            print '\t[-]target: {}'.format(self.target)
            return True
        else:
            return False

    def task_delete(self):
        url = "{}task/{}/delete".format(self.server, self.taskid)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            print highlight('[*] deleted task: {}'.format(self.taskid), 'green')
            return True
        else:
            print highlight('[!] invalid task: {}'.format(self.taskid), 'yellow')
            return False

    def scan_start(self):
        url = "{}scan/{}/start".format(self.server, self.taskid)
        headers = {'Content-Type': 'application/json'}
        payload = {'url': self.target,
                  'data': self.request_info['post_data'],
                  'cookie': self.request_info['cookie'],
                  'referer': self.request_info['referer'],
                  'user-agent': self.request_info['user_agent']}
        print '\t[-]payload: {}'.format(payload)
        res = json.loads(requests.post(url, data = json.dumps(payload), headers = headers, timeout = TIME_OUT).text)
        if res['success']:
            self.engineid = res['engineid']
            return True
        return False

    def scan_status(self):
        url = "{}scan/{}/status".format(self.server, self.taskid)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            self.status = res['status']
            if self.status == 'running':
                return 'running'
            elif self.status == 'terminated':
                return 'terminated'
            else:
                return 'error'
        else:
            return 'error'

    def scan_data(self):
        url = "{}scan/{}/data".format(self.server, self.taskid)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            self.data = res['data']
            if len(self.data) == 0:
                print highlight('[*] not injection!!!', 'red')
            else:
                print highlight('[*] injection found:', 'blue')
                print '\t[-]result: {}'.format(self.data)
        else:
            print highlight('[!] invalid scan!!!', 'yellow')

    def option_set(self):
        url = "{}option/{}/set".format(self.server, self.taskid)
        headers = {'Content-Type': 'application/json'}
        option = {"options": {
                    "smart": True,
                    }
                 }
        res = json.loads(requests.post(url, data = json.dumps(option), headers = headers, timeout = TIME_OUT).text)

    def scan_stop(self):
        url = "{}scan/{}/stop".format(self.server, self.taskid)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            return True
        return False

    def scan_kill(self):
        url = "{}scan/{}/kill".format(self.server, self.taskid)
        res = json.loads(requests.get(url, timeout = TIME_OUT).text)
        if res['success']:
            return True
        return False

    def run(self):
        if not self.task_new():
            return False
        self.option_set()
        if not self.scan_start():
            return False
        while True:
            if self.scan_status() == 'running':
                time.sleep(10)
            elif self.scan_status() == 'terminated':
                break
            else:
                break
            print '\t[-] scan time: {}'.format(time.time() - self.start_time)
            if time.time() - self.start_time > 3000:
                error = True
                self.scan_stop()
                self.scan_kill()
                break
        self.scan_data()
        self.task_delete()
        print highlight('[*] total scan time: {}'.format(time.time() - self.start_time), 'green')
