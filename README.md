# pbscan
基于burpsuite headless 的代理式被动扫描系统


## 现有burp批量扫描工具
### headless burpsuite
无头burpsuite, 即没有图形界面的burpsuite,可以再服务器上面运行.

已有工具: 
	headless-burp-scanner: https://github.com/NetsOSS/headless-burp
	carbonator: https://github.com/integrissecurity/carbonator

carbonator 提供参数
```
optional arguments:
  -h, --help     show this help message and exit
  -host HOST     Enter an IP address or Domain name
  -saveState     Save Burpsuite State
  -enableBing    Enable Bing Reverse IP
  -enableGoogle  Enable Google Search
  -file FILE     File containing Domain names or IP addresses
  -headless      Run Burp headless
```
扫描方式: 发送url->spider->scanner 去扫描。

### burpsuite2.0 restful api

	curl -vgw "\n" -X POST 'http://localhost:1337/v0.1/scan' -d '{"scan_callback":{"url":"http://123.206.65.167:2000"},"scan_configurations":[{"name":"myburp","type":"NamedConfiguration"}],"scope":{"include":[{"rule":"http://localhost:82/*","type":"SimpleScopeDef"}]},"urls":["http://localhost:82/myctf/xss/xss.php?d=1&x=1"]}'

![](./1.png)

扫描方式: 输入url->spider(模拟表单登陆)->scanner 扫描。


缺点: 可以看到上面两种支持burpsuite 批量扫描模式都是输入url->爬虫->scanner扫描， 无法满足带cookie 的一些站点扫描，而且加上spider爬虫爬取后的链接数量不易控制。


## pbscan功能

![](./doc/0.png)

- [x] 再carbonator的基础上进行开发，通过内置bottle服务器实现burpsuite 1.7的扫描api接口
- [x] 扫描接口可以实现发送数据包直接到scanner去扫描，无需经过spider, 自带cookie扫描。
- [x] 自定义burpsuite扫描插入点(目前只扫描get和post参数), 自定义burpsuite扫描漏洞(去掉一些不重要的漏洞比如明文传送，HTML未设置字符集等)
- [x] 通过接口可以实时获取扫描结果。
- [x] 使用rabbitmq+pika 实现消息队列，每个数据包都有一个token和rid标识，支持多人共同扫描。
- [x] 可以支持同时开多个headless burpsuite 来扫描以加快扫描速率。
- [x] 支持burpsuite 报表结果显示，用thinkphp写的展示平台来进行结果展示。
- [x] 利用burp插件或chrome插件来进行代理获取数据包，可以实现代理式被动扫描。

## 安装使用
1. 依赖安装
```
wget http://www.rabbitmq.com/rabbitmq-signing-key-public.asc
sudo apt-key add rabbitmq-signing-key-public.asc  
sudo apt-get update
sudo apt-get install rabbitmq-server
pip install pika
pip install gevent
pip install MySQL-python
```
2. 导入数据库sql.sql, 修改pbscan-server/config.py 中的配置信息

3. 部署运行, 有两种方式可以集中部署，一个是通过supervisor的方式来部署，另一个是直接用nohup后台进程运行。

**supervisor部署**
```
#先安装supervisor软件:
apt-get install supervisor
pip install supervisor

# 修改pbscan_supervisor.conf的路径， 启动supervisor
cp pbscan_supervisor.conf /etc/supervisor/conf.d
supervisord
supervisorctl update
supervisorctl status
```

**使用nohup后台部署**
```
bash start.sh
```

如果只想要api的接口，也可以单独运行pbscan-api。

## api扫描接口
![](./doc/1.jpg)
获取结果显示:
```
[
	{
	  	u'insert_point': 3,
		u'issues_num': 0,
		u'request_num': 122,
		u'rid': u'4b397ed50505b5e7c406ef9776b00b766203159e',
		u'scanTime': u'2019-01-15 17:36:24',
		u'scanUrl': u'GET xx.cn:80/profile/managetag?page=1&qid=2619946579',
		u'status': u'50% complete',
		u'token': u'6465fkfljalfj5456'
  	},
	{
		u'insert_point': 3,
		u'issues_num': 0,
		u'request_num': 99,
		u'rid': u'4b397ed50505b5e7c406ef9776b00b766203159e',
		u'scanTime': u'2019-01-15 17:36:26',
		u'scanUrl': u'GET xx.cn:80/profile/managetag?page=1&qid=2619946579',
		u'status': u'50% complete',
		u'token': u'6465fkfljalfj5456'
	}
 ]
```