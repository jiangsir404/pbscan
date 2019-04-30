#!/usr/bin/env python
#coding:utf-8

import sys
sys.path.append('./pika/')
sys.path.append('./logging-0.4.9.6.tar/logging/')
print sys.path

import time
import pika
import logging



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

def main():
	option = sys.argv[-1]
	if option == 'c':
		receive()
	if option == 'p':
		send('hello,world')

if __name__ == '__main__':
	main()