# pbscan burpsuite api

## Usage
burp会监听8083端口，并且开放两个api

1. 发送扫描结果api

	http://localhost:8083/scan/<token>
- get参数: 用户token
- post参数: 数据包(不需要参数)
- return: 

2. 获取扫描结果api

	http://localhost:8083/get/status/<token>

- get参数: 用户token
- return: 进度或者扫描结果

测试api的脚本
    
    cd test
	python testburpapi.py scan 
	python testburpapi.py get

默认读取data.txt中的数据包发送进行扫描。

### pbscan命令
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

    python pbscan.py -f data.txt [-headless] -debug

在服务端运行pbscan.py , 使用-headless无头模式运行burpsuite, 监听8083端口, 接收传过来的数据包。
    
    python pbscan.py -auto=8083 -headless 



### headless cli command
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


## Thinks

服务端数据库设计和入库部分参考了 安全小飞侠的NagaScan的设计

burpsuite扫描插件二次开发于carbonator插件