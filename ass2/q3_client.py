import random

from q1 import SpoofedTCPIPConnection

if __name__ == '__main__':
    dst_ip = '172.16.1.1'
    src_ip = '192.168.1.1'
    src_port = random.randint(1024, 65535)
    dst_port = 8080

    c = SpoofedTCPIPConnection(src_ip, src_port, dst_ip, dst_port)

    c.connect()
    c.send_data('GET /test.exe HTTP/1.0\r\n\r\n')
    c.close()
