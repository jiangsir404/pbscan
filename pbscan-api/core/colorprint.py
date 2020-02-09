#!/usr/bin/env python        
# coding:utf-8

import random
import time


class ColorPrinter:

    def print_black_text(self, content):  # 200
        message = "\033[0;30m%s\033[0m" % (content)
        return message

    def print_red_text(self, content):  # 200
        message = "\033[1;31m%s\033[0m" % (content)
        return message

    def print_green_text(self, content):  # 200
        message = "\033[1;32m%s\033[0m" % (content)
        return message

    def print_yellow_text(self, content):  # 40x
        message = "\033[1;33m%s\033[0;m" % (content)
        return message

    def print_blue_text(self, content):  # 40x
        message = "\033[1;34m%s\033[0;m" % (content)
        return message

    def print_magenta_text(self, content):  # 30x
        message = "\033[1;35m%s\033[0;m" % (content)
        return message

    def print_cyan_text(self, content):  # 30x
        message = "\033[1;36m%s\033[0;m" % (content)
        return message

    def print_white_text(self, content):  # 30x
        message = "\033[1;37m%s\033[0;m" % (content)
        return message

    def print_reset_text(self, content):  # 30x
        message = "\033[1;38m%s\033[0;m" % (content)
        return message


def print_random_text(content):
    output = ColorPrinter()
    colors = {31: 'red', 32: 'green', 33: 'yellow', 34: 'blue', 35: 'magenta', 36: 'cyan', 37: 'white'}  # 抛弃了黑色
    color = colors[random.randint(31, 37)]
    # print color
    getattr(output, 'print_%s_text' % color)(content)


log_colors = {
    'DEBUG': 'cyan',
    'INFO': 'green',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'white'
}


def log(F):
    output = ColorPrinter()
    def wrapper(*args, **kwargs):
        content = F(*args, **kwargs)
        FORMAT = "{time} [{level}] ".format(time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())),
                                            level=F.__name__.upper())
        content = FORMAT + content
        if F.__name__ == 'info':
            return getattr(output, 'print_%s_text' % log_colors['INFO'])(content)
        elif F.__name__ == 'debug':
            return getattr(output, 'print_%s_text' % log_colors['DEBUG'])(content)
        elif F.__name__ == 'warning':
            return getattr(output, 'print_%s_text' % log_colors['WARNING'])(content)
        elif F.__name__ == 'error':
            return getattr(output, 'print_%s_text' % log_colors['ERROR'])(content)
        elif F.__name__ == 'critical':
            return getattr(output, 'print_%s_text' % log_colors['CRITICAL'])(content)

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


if __name__ == '__main__':
    logger = Logger()
    print logger.info('xx')
