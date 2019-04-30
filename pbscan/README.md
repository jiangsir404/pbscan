# pbscan

passive scan by headless burpsuite

基于headless burpsuite 的被动扫描工具

## 环境
如果自己有burpsuite 环境，则直接安装carbonator.py 这个插件即可，如果没有burpsuite插件环境，可以将UserConfigPro.json 加入到`C:\Users\xx\AppData\Roaming\BurpSuite` 目录下

rabbitmq+pika
```
wget http://www.rabbitmq.com/rabbitmq-signing-key-public.asc
sudo apt-key add rabbitmq-signing-key-public.asc  
sudo apt-get update
sudo apt-get install rabbitmq-server
pip install pika
pip install gevent
pip install MySQL-python
```
## usage
### pbscan 启动
```
usage: pbscan.py [-h] [-f F] [-headless] [-debug] [-proxy] [-auto AUTO]

Burp automator

optional arguments:
  -h, --help  show this help message and exit
  -f F        File containing Domain names or IP addresses
  -headless   Run Burp headless
  -debug      debug
  -proxy      open proxy
  -auto AUTO  auto
```

直接读取data.txt 里面的数据包来发送到burpsuite去扫描。

    python pbscan.py -f data.txt [-headless] 

在服务端运行pbscan.py , 使用-headless无头模式运行burpsuite, 监听8083端口, 接收传过来的数据包。
    
    python pbscan.py -auto=8083 -headless 

在服务端运行生产者脚本，开启扫描api, 负责监听7001端口(自己修改), 

    python producer.py -auto 

在服务端运行消费者脚本，burp=8083表示选择开放8083端口的burpsuite进行消费扫描。

    python consumer.py burp=8083 
    
只介绍这三个常见命令，其他命令自己看下脚本就明白怎么用了。


客户端安需要一个流量转发插件，可以用chrome插件，burp插件.

### cli command
切换到core目录，执行以下命令

headless mode:

	java -jar  -Xbootclasspath/p:burp-loader-keygen.jar -Djava.awt.headless=true burpsuite_pro_v1.7.32.jar --config-file=burp.json --user-config-file=UserConfigPro.json -f=../data.txt


normal mode:

	java -jar  -Xbootclasspath/p:burp-loader-keygen.jar burpsuite_pro_v1.7.32.jar --config-file=burp.json --user-config-file=UserConfigPro.json -f=../data.txt

参数解析:
```
-Xbootclasspath/p:burp-loader-keygen.jar: 从burp-loader-keygen.jar启动burpsuite
-Djava.awt.headless=true: 使用headless mode
--config-file=burp.json: 加载burpsuite的扫描配置文件
--config-file=UserConfigPro.json: 加载burpsuite 的插件配置文件
```

## 功能
- [x] 读取数据包发送到scanner扫描(normal/headless mode)
- [x] 代理监听数据包并且保存到日志
- [x] 数据包以及结果存入数据库

