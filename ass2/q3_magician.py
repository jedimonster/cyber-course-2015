from scapy.all import *
from scapy.tools.UTscapy import sha1

if __name__ == '__main__':
    # The tcp magician sends a magic packet to open port 22
    sport = random.randint(1024, 64 * 1024)
    current_time = int(time.time()) << 3
    secret = sha1('weeeeeee' + str(current_time))

    pkt = IP(src='192.168.1.1', dst='172.16.1.1') / TCP(sport=sport, dport=4242, flags="S") / secret

    send(pkt)
