from scapy.all import *
from scapy.tools.UTscapy import sha1

if __name__ == '__main__':
    # The tcp magician sends a magic packet to open port 22
    try:
        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
        sport = random.randint(1024, 64 * 1024)
        secret = sha1('weeeeeee')

        ip_pkt = IP(src='192.168.1.1', dst='172.16.1.1', id=random.randint(0, 50000))
        tcp_pkt = TCP(sport=sport, dport=4242, flags="S")
        pkt = ip_pkt / tcp_pkt / secret

        challenge = sr1(pkt)
        challange_number = challenge[Raw].load
        print "signing %r" % challange_number
        response = sha1('weeeeeee' + challange_number)
        ip_pkt = IP(src='192.168.1.1', dst='172.16.1.1', id=random.randint(0, 50000))
        tcp_pkt = TCP(sport=sport, dport=4243, flags="S")
        response_pkt = ip_pkt / tcp_pkt / response
        send(response_pkt)

    finally:
        os.system('iptables --flush OUTPUT')
