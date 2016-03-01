import socket

if __name__ == '__main__':
    attacks = ['POST /login.php HTTP/1.0\r\n'
               '\r\n'
               'u=<script>\r\n\r\n']

    for attack in attacks:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('172.16.1.1', 80))
        s.sendall(attack)
        data = s.recv(1024)
        s.close()
        print 'Received', repr(data)
