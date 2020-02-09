#!/usr/bin/env python
#coding:utf-8
import sys
import time
import pika

'''
建立一个命名好的的exchange和queue并绑定,进行任务调度分发
'''

def send(message):
	# ********* open_channel ************
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) ##连接到localhost的rabbitmq服务
	channel = connection.channel() #创建一个通道
	channel.exchange_declare(exchange='burp_exchange', exchange_type='fanout') #定义一个fanout类型的交换机
	channel.queue_declare(queue='burp_queue', durable=True) #重复声明队列，确认队列是否存在，持久化队列
	channel.queue_bind(exchange='burp_exchange',
	                   queue='burp_queue') # 将自定义的交换机和队列进行绑定

	channel.basic_publish(exchange='burp_exchange',
	  routing_key="burp_queue",
	  body=message,
	  properties=pika.BasicProperties(
	     delivery_mode = 2, # make message persistent
	  ))
	print " [x] Sent %r" % (message,)

	# ********* close channel ********
	if channel and channel.is_open:  # 检测信道是否还存活
		channel.close()  # 关闭信道
	if connection and connection.is_open:  # 检测连接是否还存活
		connection.close()  # 断开连接


def receive():
	# ********* open_channel ************
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) ##连接到localhost的rabbitmq服务
	channel = connection.channel() #创建一个通道
	channel.exchange_declare(exchange='burp_exchange', exchange_type='fanout') #定义一个fanout类型的交换机
	channel.queue_declare(queue='burp_queue', durable=True) #重复声明队列，确认队列是否存在，持久化队列
	channel.queue_bind(exchange='burp_exchange',
	                   queue='burp_queue') # 将自定义的交换机和队列进行绑定

	def callback(ch, method, properties, body):
	    print " [x] Received %r" % (body,)
	    time.sleep(3)
	    print " [x] Done"
	    ch.basic_ack(delivery_tag = method.delivery_tag) #消息确认

	channel.basic_qos(prefetch_count=1) #公平调度
	channel.basic_consume(callback,
	                      queue='burp_queue')

	print(' [*] Waiting for messages. To exit press CTRL+C')
	channel.start_consuming() #开始消费

	# ********* close channel ********
	if channel and channel.is_open:  # 检测信道是否还存活
		channel.close()  # 关闭信道
	if connection and connection.is_open:  # 检测连接是否还存活
		connection.close()  # 断开连接

'''
使用消息发布模式，建立一个扇形exchanges, 发布者不声明queue, 消费者使用临时queue，即每个消费者都是一个queue,这样扇形交换机就会发布任务到每一个消费者了。
'''

def send2(message):
	# ********* open_channel ************
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) ##连接到localhost的rabbitmq服务
	channel = connection.channel() #创建一个通道
	channel.exchange_declare(exchange='poc_exchange', exchange_type='fanout') #定义一个fanout类型的交换机

	channel.basic_publish(exchange='poc_exchange',
	  routing_key="",
	  body=message,
	  properties=pika.BasicProperties(
	     delivery_mode = 2, # make message persistent
	  ))
	print " [x] Sent %r to poc_exchange" % (message,)

	# ********* close channel ********
	if channel and channel.is_open:  # 检测信道是否还存活
		channel.close()  # 关闭信道
	if connection and connection.is_open:  # 检测连接是否还存活
		connection.close()  # 断开连接


def receive2():
	# ********* open_channel ************
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) ##连接到localhost的rabbitmq服务
	channel = connection.channel() #创建一个通道
	channel.exchange_declare(exchange='poc_exchange', exchange_type='fanout') #定义一个fanout类型的交换机
	result = channel.queue_declare(exclusive=True) #不传入queu name,建立临时度列,exclusive=True表示当与消费者断开连接的时候，这个队列应当被立即删除
	queue_name = result.method.queue #获取随即队列的名称(随机字符串)
	channel.queue_bind(exchange='poc_exchange',
	                   queue=queue_name) # 将自定义的交换机和临时队列进行绑定,fanout将会发布到

	def callback(ch, method, properties, body):
	    print " [x] Received %r" % (body,)
	    time.sleep(3)
	    print " [x] Done"
	    ch.basic_ack(delivery_tag = method.delivery_tag) #消息确认

	channel.basic_qos(prefetch_count=1) #公平调度
	channel.basic_consume(callback,
	                      queue=queue_name)

	print(' [*] Waiting for messages. To exit press CTRL+C')
	channel.start_consuming() #开始消费

	# ********* close channel ********
	if channel and channel.is_open:  # 检测信道是否还存活
		channel.close()  # 关闭信道
	if connection and connection.is_open:  # 检测连接是否还存活
		connection.close()  # 断开连接

def main():
	option = sys.argv[-1]
	if option == 'c':
		receive()
	if option == 'p':
		send('hello,world')
	if option == 'c2':
		receive2()
	if option == 'p2':
		send2('hello,world')

if __name__ == '__main__':
	main()