#!/usr/bin/env python		
#coding:utf-8

import sys
sys.path.append("..")
from lib.mysql import Mysql

mydb = Mysql('root','root','nagascan')

print mydb.query('select * from requests limit 1')


data = [{"scanTime": "2019-01-06 18:52:54", "request_num": 307, "rid": "99319594d67674abf6947481d165685adc34800d", "issues": [{"issueName": "Cross-site scripting (reflected)", "issueConfidence": "Certain", "issueRequest": "GET /myctf/xss/xss.php?x=1h97zb%3cscript%3ealert(1)%3c%2fscript%3epd27f&d=1 HTTP/1.1\r\nHost: localhost\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,de-DE;q=0.8,de;q=0.7\r\nCookie: XDEBUG_SESSION=XDEBUG_ECLIPSE; csrftoken=KpM8eEEXlrYoJPzHkdqUVikmD5BNKkLi; NAGASCAN-ID=0010018336417540987fff4508f43fbaed718e263442526000-1546413234-4b5071c702dfb4c4dfbd3e93c36b1b9c\r\nConnection: close\r\n\r\n\r\ndata =xxx&aa=11\n\n", "issueSeverity": "High", "issueDetail": "The value of the <b>x</b> request parameter is copied into the HTML document as plain text between tags. The payload <b>h97zb&lt;script&gt;alert(1)&lt;/script&gt;pd27f</b> was submitted in the x parameter. This input was echoed unmodified in the application's response.<br><br>This proof-of-concept attack demonstrates that it is possible to inject arbitrary JavaScript into the application's response."}, {"issueName": "Input returned in response (reflected)", "issueConfidence": "Certain", "issueRequest": "GET /myctf/xss/xss.php?x=14oezd9b5un&d=1 HTTP/1.1\r\nHost: localhost\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,de-DE;q=0.8,de;q=0.7\r\nCookie: XDEBUG_SESSION=XDEBUG_ECLIPSE; csrftoken=KpM8eEEXlrYoJPzHkdqUVikmD5BNKkLi; NAGASCAN-ID=0010018336417540987fff4508f43fbaed718e263442526000-1546413234-4b5071c702dfb4c4dfbd3e93c36b1b9c\r\nConnection: close\r\n\r\n\r\ndata =xxx&aa=11\n\n", "issueSeverity": "Information", "issueDetail": "The value of the <b>x</b> request parameter is copied into the application's response."}, {"issueName": "Input returned in response (reflected)", "issueConfidence": "Certain", "issueRequest": "GET /myctf/xss/xss.php?x=1&d=1xfweutgrcs HTTP/1.1\r\nHost: localhost\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,de-DE;q=0.8,de;q=0.7\r\nCookie: XDEBUG_SESSION=XDEBUG_ECLIPSE; csrftoken=KpM8eEEXlrYoJPzHkdqUVikmD5BNKkLi; NAGASCAN-ID=0010018336417540987fff4508f43fbaed718e263442526000-1546413234-4b5071c702dfb4c4dfbd3e93c36b1b9c\r\nConnection: close\r\n\r\n\r\ndata =xxx&aa=11\n\n", "issueSeverity": "Information", "issueDetail": "The value of the <b>d</b> request parameter is copied into the application's response."}], "token": "parse_burp_log", "insert_point": 5, "issues_num": 3, "status": "finished"}]


for line in data:
    if line['status'] == 'finished':
        issues = line.pop('issues')
        try:
            print line
            mydb.insert('results',line)
            for issue in issues:
                issue['token'] = 'parse_burp_log'
                issue['rid'] = line['rid']
                mydb.insert('issues',issue)
            print 'save success'
        except Exception,e:
            print e
    else:
        print line