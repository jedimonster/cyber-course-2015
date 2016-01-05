#!/usr/bin/python
'''
THIS is an EXMAPLE code ONLY !!!!
The code is not written using the relevent standards !!!!
'''
import BaseHTTPServer
import json
import time
from scapy.tools.UTscapy import sha1

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 8080


class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""
        # we have self.path, self.client_address which is (ip, port), and self.headers
        if not self._verify_request():
            self.send_response(401)
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<html><head><title>Ex1 Web Server Template</title></head>")
        self.wfile.write("<body><p>Welcome to Q1 !!!.</p>")
        self.wfile.write("</body></html>")
        print "Connectd From: " + self.client_address[0]

    def _verify_request(self):
        ip = self.client_address[0]
        path = self.path
        try:
            secret = self._get_client_secret()
            client_hash = self.headers['secret']
        except KeyError:
            return False

        current_time = int(time.time()) << 3
        hash = sha1(str(secret) + str(current_time) + str(path))
        return hash == client_hash

    def _get_client_secret(self):
        ip = self.client_address[0]

        with open('secrets.json') as fh:
            secrets_list = json.load(fh)
            secrets = dict([(ip_secret['ip'], ip_secret['secret']) for ip_secret in secrets_list])
            return secrets[ip]


if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    print "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
