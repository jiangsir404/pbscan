# -*- coding: utf-8 -*-

""" Database Operations

This module is used to parse Burp Requests and insert into MySQL DB.

"""

import MySQLdb
import time
from utils import highlight

def escape_content(content):
    content = MySQLdb.escape_string(content)
    return content

def db_conn():
    try:
        user = "root"
        pwd = "root"
        hostname = "127.0.0.1"

        dbname = "pbscan"
        charset = "utf8"
        dbconn = MySQLdb.connect(user=user,passwd=pwd,host=hostname,db=dbname,charset=charset)
        return dbconn
    except Exception, e:
        print highlight('[!] error: {}'.format(str(e)), 'yellow')
        pass

def db_insert(table, args):
    """ Insert data into table

        Args:
            table: The name of table
            args: The input content, it is a dict, e.g. {'exclusion':'google','update_time':'2017-03-10: 14:19'}

    """

    cols = []
    for key in args.keys():
        cols.append(key)
    sql = 'INSERT INTO `%s` (%s) VALUES (%s)' % (table, ','.join(['`%s`' % col for col in cols]), ','.join(['?' for i in range(len(cols))]))
    sql = sql.replace('?', '%s')
    try:
        db = db_conn()
        cursor = db.cursor()
        cursor.execute(sql, args.values())
        db.commit()
        db.close()
        return True
    except Exception, e:
        print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
        return False

def db_update(table, args, cons):
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
    sql = 'UPDATE `%s` SET %s WHERE %s' % (table, ','.join(['`%s`=?' % col for col in cols]), ','.join(['`%s`=?' % col for col in cols_cons]))
    sql = sql.replace('?', '%s')
    try:
        db = db_conn()
        cursor = db.cursor()
        cursor.execute(sql, values)
        db.commit()
        db.close()
        return True
    except Exception, e:
        print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
        return False

def db_query(sql):
    try:
        db = db_conn()
        cursor = db.cursor()
        cursor.execute(sql)
        db.commit()
        db.close()
        query_result = cursor.fetchall()
        return query_result
    except Exception, e:
        print highlight('[!] sql: {}, error: {}'.format(sql, str(e)), 'red')
        return ''

def fetch_sqlmap():
    """Fetch SQLMAP servers from database

    """

    sql = "SELECT ip, port FROM sqlmap WHERE status = 1"
    sqlmaps = db_query(sql)
    return sqlmaps

def fetch_exclusion_scan(scan_type):
    """Fetch Scan Exclusions from database

    Args:
        scan_type: Int, the scan type, e.g. 0: xss; 1: sqli; 2: fi

    """

    sql = "SELECT ip, port, protocol, host, method, user_agent, accept, accept_language, accept_encoding, cookie, referer, content_type, post_data, path FROM exclusions_scan WHERE type = {}".format(scan_type)
    exclusions = db_query(sql)
    return exclusions

def fetch_exclusion_parse():
    """Fetch Parse Exclusions from database

    """

    sql = "SELECT exclusion FROM exclusions_parse"
    exclusions = db_query(sql)
    return exclusions

def fetch_exclusion_cookie():
    """Fetch Cookie Exclusions from database

    """

    sql = "SELECT exclusion FROM exclusions_cookie"
    exclusions = db_query(sql)
    return exclusions

def fetch_request(exclude, scan_type, limit_num):
    """Fetch request from database

    Args:
        exclude: Exclusions of requests, it is a dict
        scan_type: The scan type, e.g. scan_xss, scan_sqli
        limit_num: The number of limit of requests

    """

    if exclude:
        conditions = []
        for key, value in exclude.items():
            vals = value.split('|')
            if len(vals) > 1:
                for val in vals:
                    conditions.append("lower({}) not like '%{}%'".format(key, val))
            else:
                conditions.append("lower({}) not like '%{}%'".format(key, vals[0]))
        conditions_str = " and ".join(conditions)
        sql = "SELECT rid, protocol, host, method, user_agent, accept, accept_language, accept_encoding, cookie, referer, post_data, path, scan_xss, scan_sqli, content_type FROM requests WHERE {} = 0 and {} order by id desc limit {}".format(scan_type, conditions_str, limit_num)
    else:
        sql = "SELECT rid, protocol, host, method, user_agent, accept, accept_language, accept_encoding, cookie, referer, post_data, path, scan_xss, scan_sqli, content_type FROM requests WHERE {} = 0 order by id desc limit {}".format(scan_type, limit_num)
    requests = db_query(sql)
    return requests

def fetch_raw(exclude,scan_type,limit_num):
    sql = "SELECT rid,method,host,path,raw FROM requests WHERE {} = 0 order by id desc limit {}".format(scan_type, limit_num)
    raws = db_query(sql)
    return raws

def get_parse_exclusion_info(exclusion):
    """Convert raw parse exclusion to dict

    Args:
        exclusion: raw parse exclusion from database

    Returns:
        exclude: list

    """

    exclude = []
    if exclusion[0]:
        exclusions = exclusion[0].split('|');
        for excl in exclusions:
            if excl:
                exclude.append(excl)
    return exclude

def get_cookie_exclusion_info(exclusion):
    """Convert raw cookie exclusion to dict

    Args:
        exclusion: raw cookie exclusion from database

    Returns:
        exclude: list

    """

    exclude = []
    if exclusion[0]:
        exclusions = exclusion[0].split('|');
        for excl in exclusions:
            if excl:
                exclude.append(excl)
    return exclude

def get_scan_exclusion_info(exclusion):
    """Convert raw scan exclusion to dict

    Args:
        exclusion: raw scan exclusion from database

    Returns:
        exclude: dict

    """

    exclude = {}
    if exclusion[0]:
        exclude['ip'] = exclusion[0]
    if exclusion[1]:
        exclude['port'] = exclusion[1]
    if exclusion[2]:
        exclude['protocol'] = exclusion[2]
    if exclusion[3]:
        exclude['host'] = exclusion[3]
    if exclusion[4]:
        exclude['method'] = exclusion[4]
    if exclusion[5]:
        exclude['user_agent'] = exclusion[5]
    if exclusion[6]:
        exclude['accept'] = exclusion[6]
    if exclusion[7]:
        exclude['accept_language'] = exclusion[7]
    if exclusion[8]:
        exclude['accept_encoding'] = exclusion[8]
    if exclusion[9]:
        exclude['cookie'] = exclusion[9]
    if exclusion[10]:
        exclude['referer'] = exclusion[10]
    if exclusion[11]:
        exclude['content_type'] = exclusion[11]
    if exclusion[12]:
        exclude['post_data'] = exclusion[12]
    if exclusion[13]:
        exclude['path'] = exclusion[13]

    return exclude

def get_request_info(request):
    """Convert raw request to dict

    Args:
        request: raw request from database

    Returns:
        request_info: dict

    """

    request_info = {}
    request_info['rid'] = request[0]
    request_info['protocol'] = request[1]
    request_info['host'] = request[2]
    request_info['method'] = request[3]
    request_info['user_agent'] = request[4]
    request_info['accept'] = request[5]
    request_info['accept_language'] = request[6]
    request_info['accept_encoding'] = request[7]
    request_info['cookie'] = request[8]
    request_info['referer'] = request[9]
    request_info['post_data'] = request[10]
    request_info['path'] = request[11]
    request_info['scan_xss'] = request[12]
    request_info['scan_sqli'] = request[13]
    request_info['content_type'] = request[14]

    return request_info

def get_sqlmap_info(sqlmap):
    """Convert raw sqlmap server info to dict

    Args:
        sqlmap: raw sqlmap server info from database

    Returns:
        sqlmap_info: dict

    """

    sqlmap_info = {}
    sqlmap_info['ip'] = sqlmap[0]
    sqlmap_info['port'] = sqlmap[1]

    return sqlmap_info

def is_checked(rid, scan_type):
    """Check if the specific request has been checked before.

    Args:
        rid: The rid of the request
        scan_type: The scan type, e.g. scan_xss, scan_sqli

    Returns:
        True for checked, False otherwise.

    """

    try:
        sql = "SELECT COUNT(*) FROM requests where rid ='{}' and {} = 1".format(rid.strip(), scan_type)
        query_result = db_query(sql)
        count = [row[0] for row in query_result]
        if count[0] >= 1:
            return True
        else:
            return False
    except Exception, e:
        print highlight('[!] {}'.format(str(e)), 'red')
        return False

def is_checked_vulnerable(rid, scan_result_type):
    """Check if the specific request has been detected as vulnerable before.

    Args:
        rid: The rid of the request
        scan_result_type: The scan result type for the request, e.g. result_xss, result_sqli

    Returns:
        True for existed vulnerable, False otherwise.

    """

    try:
        sql = "SELECT COUNT(*) FROM requests where rid ='{}' and {} = 'vulnerable'".format(rid.strip(), scan_result_type)
        query_result = db_query(sql)
        count = [row[0] for row in query_result]
        if count[0] >= 1:
            return True
        else:
            return False
    except Exception, e:
        print highlight('[!] {}'.format(str(e)), 'red')
        return False

def update_scan_result(rid, scan_type, scan_result_type, scan_result, poc_type, poc_result, response_type, response):
    """Update scanning result into database

    Args:
        rid: The rid of the request
        scan_type: The scan type, e.g. scan_xss, scan_sqli
        scan_result_type: The scan result type for the request, e.g. result_xss, result_sqli
        scan_result: The scanning result, e.g. vulnerable, not vulnerable
        poc_type: The poc type, e.g. poc_xss, poc_sqli
        poc_result: The payload of poc
        response_type: The response type, e.g. response_xss, response_fi, response_sqli
        response: The source page of response

    """
    if not is_checked_vulnerable(rid, scan_result_type):
        if scan_result == "vulnerable":
            now = str(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
            table_request = 'requests'
            args_request = {}
            args_request[scan_type] = 1
            args_request[scan_result_type] = scan_result
            args_request[poc_type] = poc_result
            args_request['update_time'] = now
            cons_request = {}
            cons_request['rid'] = rid

            table_response = 'responses'
            args_response = {}
            args_response['update_time'] = now
            args_response[response_type] = response
            cons_response = {}
            cons_response['rid'] = rid
        else:
            now = str(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
            table_request = 'requests'
            args_request = {}
            args_request[scan_type] = 1
            args_request[scan_result_type] = scan_result
            args_request['update_time'] = now
            cons_request = {}
            cons_request['rid'] = rid

            table_response = 'responses'
            args_response = {}
            args_response['update_time'] = now
            cons_response = {}
            cons_response['rid'] = rid
        db_update(table_request, args_request, cons_request)
        db_update(table_response, args_response, cons_response)


def update_scan_auto(rid, **kwargs):
    """Update scanning result into database

    Args:
        rid: The rid of the request
        scan_type: The scan type, e.g. scan_xss, scan_sqli
        scan_result_type: The scan result type for the request, e.g. result_xss, result_sqli
        scan_result: The scanning result, e.g. vulnerable, not vulnerable
        poc_type: The poc type, e.g. poc_xss, poc_sqli
        poc_result: The payload of poc
        response_type: The response type, e.g. response_xss, response_fi, response_sqli
        response: The source page of response

    """
    now = str(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    table_request = 'requests'
    args_request = {}
    for k in kwargs:
        args_request[k] = kwargs[k]
        args_request['update_time'] = now
    cons_request = {}
    cons_request['rid'] = rid

    # table_response = 'responses'
    # args_response = {}
    # args_response['update_time'] = now
    # args_response[response_type] = response
    # cons_response = {}
    # cons_response['rid'] = rid
    print args_request,cons_request
    db_update(table_request, args_request, cons_request)
    # db_update(table_response, args_response, cons_response)