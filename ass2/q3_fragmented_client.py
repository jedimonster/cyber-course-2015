from scapy.all import *

if __name__ == '__main__':
    os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')
    N = 2
    dst_ip = '172.16.1.1'
    src_ip = '192.168.1.1'
    ip = IP(src=src_ip, dst=dst_ip, proto='tcp')
    payload = 'GET /a.exe HTTP/1.0\r\n' \
              'Sheker: VGaaaaaaaaS\r\n\r\n'
    src_port = random.randint(1, 65000)
    # print src_port
    dst_port = 8080
    ip_id = random.randint(1, 1000)

    # handshake
    seq_num = 1000
    syn_pckt = ip / TCP(sport=src_port, dport=dst_port, flags='S',
                        seq=seq_num)
    synack = sr1(syn_pckt)
    seq_num += 1

    if TCP in synack and synack[TCP].flags & (2 | 16):
        print "RCVED SYNACK"
        ack = synack[TCP].seq + 1
        ack_pckt = ip / TCP(sport=src_port, dport=dst_port, flags='A',
                            seq=synack.ack, ack=synack.seq + 1)
        send(ack_pckt)



    tcp_packet = ip / TCP(sport=src_port, dport=8080, seq=1001, ack=synack.seq + 1, flags="A") / payload
    tcp_raw = tcp_packet.build()

    # print 'checksum %0xd' % TCP(tcp_raw)[TCP].chksum
    fragment_size = (len(tcp_raw) - 20) / N
    ip_packets = []
    tcp_raw = tcp_raw[20:]

    for i in range(N):
        more_framents = 'MF' if i != (N - 1) else 0
        fragment_start = i * fragment_size
        fragment_end = (i + 1) * fragment_size
        print "%d - %d" % (fragment_start, fragment_end)
        payload = tcp_raw[fragment_start:fragment_end]
        # print "lengtj of payload is %s" % (len(payload),)
        print "fragment offset should be %d", (fragment_start)
        ip_packet = IP(src=src_ip, dst=dst_ip, flags=more_framents, frag=fragment_start / 8, proto='tcp',
                       id=ip_id) / payload
        # print ip_packet.show()
        ip_packets.append(ip_packet)

    for packet in ip_packets:
        send(packet)
        print packet.show()

    os.system('iptables --flush OUTPUT')
