#!/usr/bin/python

import argparse
import socket

import time


def send_http_request(ip, port, http_request):
    s = socket.socket()

    s.connect((ip, port))
    s.send(http_request)

    time.sleep(2)  # give the server a chance to respond, despite the fact we'll ignore it.

    s.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send HTTP Request')
    parser.add_argument('ip', type=str, nargs=1,
                        help='server ip')
    parser.add_argument('port', metavar='Port', type=int, nargs=1,
                        help='server port')
    args = parser.parse_args()
    http_request = """GET / HTTP/1.1
Host: yuriasaservice.com
Connection: keep-alive
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Opera/12.02 (Android 4.1; Linux; Opera Mobi/ADR-1111101157; U; en-US) Presto/2.9.201 Version/12.02
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,he;q=0.6

"""
    send_http_request(args.ip[0], args.port[0], http_request)
