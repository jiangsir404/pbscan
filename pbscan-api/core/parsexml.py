#!/usr/bin/env python		
#coding:utf-8
import sys
import xml.etree.ElementTree as ET

#!/usr/bin/env python		
#coding:utf-8

import pymongo
import copy
import traceback
dsn = "mongodb://localhost:27017/"
dbname = 'burp'
collection = 'scan_result'

class Mongo:
    def __init__(self,dsn):
        myclient = pymongo.MongoClient(dsn)
        self.mydb = myclient[dbname] #数据库
        self.mycol = self.mydb[collection] #sites collections

    def insert_one(self,data):
        try:
            x = self.mycol.insert_one(data) #插入文档(记录)
            print('insert success:'+x.inserted_id)
        except Exception as e:
            #print traceback.print_exc()f
            print(e)

    def insert_many(self,datalist):
        for data in datalist:
            self.insert_one(data)
        #print(x.inserted_ids)

    def find(self,condition,limit=100):
        return self.mycol.find(condition).limit(limit)


def xml_parser(xmlfile):
    data = {}
    data_list = []
    tree = ET.parse(xmlfile)
    root = tree.getroot()# 获取根元素
    for info in root.findall('issue'): #查找所有info元素
    	#print info
        tmp = {}
        for child in info: #对每个info元素遍历属性和子节
            if child.tag == 'serialNumber':
                data['_id'] = child.text
            data[child.tag] = child.text
 
        tmp = copy.deepcopy(data) #dict sd
        data_list.append(tmp)
 
 
    #print data_list
    return data_list

datalist = xml_parser(sys.argv[-1])


mongo = Mongo(dsn)
mongo.insert_many(datalist)

