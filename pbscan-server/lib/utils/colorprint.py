#!/usr/bin/env python
# coding:utf-8

import random
import time


class ColorPrint:

    def black(self, content):  # 200
        message = "\033[0;30m%s\033[0m" % (content)
        print message

    def red(self, content):  # 200
        message = "\033[1;31m%s\033[0m" % (content)
        print message

    def green(self, content):  # 200
        message = "\033[1;32m%s\033[0m" % (content)
        print message

    def yellow(self, content):  # 40x
        message = "\033[1;33m%s\033[0;m" % (content)
        print message

    def blue(self, content):  # 40x
        message = "\033[1;34m%s\033[0;m" % (content)
        print message

    def magenta(self, content):  # 30x
        message = "\033[1;35m%s\033[0;m" % (content)
        print message

    def cyan(self, content):  # 30x
        message = "\033[1;36m%s\033[0;m" % (content)
        print message

    def white(self, content):  # 30x
        message = "\033[1;37m%s\033[0;m" % (content)
        print message

    def reset(self, content):  # 30x
        message = "\033[1;38m%s\033[0;m" % (content)
        print message


    def random(self,content):
        colors = {31: 'red', 32: 'green', 33: 'yellow', 34: 'blue', 35: 'magenta', 36: 'cyan', 37: 'white'}  # 抛弃了黑色
        color = colors[random.randint(31, 37)]
        # print color
        getattr(self, '%s' % color)(content)


log_colors = {
    'DEBUG': 'cyan',
    'SUCCESS': 'green',
    'INFO': 'blue',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'white'
}


def log(F):
    output = ColorPrint()
    def wrapper(*args, **kwargs):
        content = F(*args, **kwargs)
        FORMAT = "{time} [{level}] ".format(time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())),
                                            level=F.__name__.upper())
        content = FORMAT + content
        if F.__name__ == 'info':
            return getattr(output, '%s' % log_colors['INFO'])(content)
        elif F.__name__ == 'debug':
            return getattr(output, '%s' % log_colors['DEBUG'])(content)
        elif F.__name__ == 'warning':
            return getattr(output, '%s' % log_colors['WARNING'])(content)
        elif F.__name__ == 'error':
            return getattr(output, '%s' % log_colors['ERROR'])(content)
        elif F.__name__ == 'critical':
            return getattr(output, '%s' % log_colors['CRITICAL'])(content)
        elif F.__name__ == 'success':
            return getattr(output, '%s' % log_colors['SUCCESS'])(content)

    return wrapper


class Logger:
    @log
    def info(self, content):
        return content

    @log
    def debug(self, content):
        return content

    @log
    def error(self, content):
        return content

    @log
    def warning(self, content):
        return content

    @log
    def critical(self, content):
        return content

    @log
    def success(self,content):
        return content


if __name__ == '__main__':
    logger = Logger()
    logger.info('test1')
    logger.error('test2')
    logger.debug('test3')
    logger.warning('test4')
    logger.critical('test5')
    logger.success('test6')



    cp = ColorPrint()
    cp.red('i am red')
    cp.random('i am change color')
    cp.random('i am change color')