# -*- coding: utf-8 -*-

""" Database Operations

This module is used to parse Burp Requests and insert into MySQL DB.

"""

import MySQLdb
import time

def highlight(content, color, ENVIRONMENT='Linux'):
    if ENVIRONMENT=='Linux':
        if color == "red":
            content = "\033[1;31;40m{}\033[0m".format(content)
        if color == "green":
            content = "\033[1;32;40m{}\033[0m".format(content)
        if color == "yellow":
            content = "\033[1;33;40m{}\033[0m".format(content)
        if color == "blue":
            content = "\033[1;34;40m{}\033[0m".format(content)
    return content

def escape_content(content):
    content = MySQLdb.escape_string(content)
    return content


class Mysql():
    def __init__(self,user,pwd,dbname,host='localhost',charset="utf8"):
        self.user = user
        self.pwd = pwd
        self.hostname = host 
        self.dbname = dbname
        self.charset = charset

    def db_conn(self):
        try:
            dbconn = MySQLdb.connect(user=self.user,passwd=self.pwd,host=self.hostname,db=self.dbname,charset=self.charset)
            return dbconn
        except Exception, e:
            print highlight('[!] error: {}'.format(str(e)), 'yellow')
            pass

    def insert(self,table, args):
        """ Insert data into table

            Args:
                table: The name of table
                args: type :dict  e.g. {'exclusion':'google','update_time':'2017-03-10: 14:19'}

        """

        cols = []
        for key in args.keys():
            cols.append(key)
        sql = 'INSERT INTO `%s` (%s) VALUES (%s)' % (table, ','.join(['`%s`' % col for col in cols]), ','.join(['?' for i in range(len(cols))]))
        sql = sql.replace('?', '%s')
        try:
            db = self.db_conn()
            cursor = db.cursor()
            cursor.execute(sql, args.values())
            db.commit()
            db.close()
            return True
        except Exception, e:
            print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
            return False

    def update(self,table, args, cons):
        """ Update data in specific table with specific conditions

            Args:
                table: The name of table
                args: The update content, it is a dict, e.g. {'exclusion':'google','update_time':'2017-03-10: 14:19'}
                cons: The conditions, it is a dict, e.g. {'id':'111'}

        """

        cols = []
        cols_cons = []
        values = []
        for k,v in args.items():
            cols.append(k)
            values.append(v)
        for k,v in cons.items():
            cols_cons.append(k)
            values.append(v)
        sql = 'UPDATE `%s` SET %s WHERE %s' % (table, ','.join(['`%s`=?' % col for col in cols]), ' and '.join(['`%s`=?' % col for col in cols_cons]))
        sql = sql.replace('?', '%s')
        try:
            db = self.db_conn()
            cursor = db.cursor()
            cursor.execute(sql, values)
            db.commit()
            db.close()
            return True
        except Exception, e:
            print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
            return False

    def query(self,sql):
        try:
            db = self.db_conn()
            cursor = db.cursor()
            cursor.execute(sql)
            db.commit()
            db.close()
            query_result = cursor.fetchall()
            return query_result
        except Exception, e:
            print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
            return ''

    def is_duplicate(self, table, rid, token=None):
        """对table表的rid字段或者rid和token字段去重
        """
        try:
            if token and rid:
                sql = "SELECT COUNT(*) FROM {0} where rid ='{1}' and token='{2}'".format(table, rid.strip(), token)
            else:
                sql = "SELECT COUNT(*) FROM {} where rid ='{}'".format(table, rid.strip())
            query_result = self.query(sql)
            count = [row[0] for row in query_result]
            if count[0] >= 1:
                return True
            else:
                return False
        except Exception, e:
            print highlight('[!] {}'.format(str(e)), 'red')
            return False

if __name__ == '__main__':
    mydb = Mysql('root','root','ctf')
    print mydb.query('select * from user')
    #mydb.insert('user',{'username':'xxx','password':'xxxx'})
    #mydb.update('user',{'username':'xxx','password':'ttt'},{'username':'xxx'})