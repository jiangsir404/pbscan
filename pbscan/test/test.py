#!/usr/bin/env python		
#coding:utf-8

import requests
import sys

a = '[{"request num": 162, "scanTime": "20190105-155322", "issues": 5, "token": "111", "insert point": 3, "status": "75% complete"}, {"request num": 147, "scanTime": "20190105-155323", "issues": 4, "token": "111", "insert point": 3, "status": "75% complete"}]'


import json
print json.loads(a)