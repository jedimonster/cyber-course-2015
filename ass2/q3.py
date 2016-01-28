import argparse
import json
import random
import re
import os
from collections import defaultdict
from netfilterqueue import NetfilterQueue
from threading import Timer
from scapy.packet import Raw
from scapy.tools.UTscapy import sha1
from scapy.sendrecv import srp, send, sr1
from scapy import route  # despite what PyCharm might claim, this is used.
from scapy.layers.inet import TCP, IP

REG_HTTP_GET = re.compile("^GET\s([A-Za-z0-9/\-\._~:\?#]+)\sHTTP/\d\.\d")
IP_PROTOCOLS_TCP = 6


class HttpInspector:
    def __init__(self, filtered_extensions, silent):
        self.silent = silent
        self.filtered_extensions = filtered_extensions

    def inspect(self, packet):
        if TCP in packet:
            layer5 = packet[TCP].payload
            results = re.search(REG_HTTP_GET, str(layer5))

            if results is not None:
                url = results.group(1)

                for extension in filter_extensions:
                    if url.find('.' + extension) != -1:
                        print "Filtered packet for uri %s" % url
                        if not self.silent:
                            self._send_error_page(packet)
                        return False

        return True

    @staticmethod
    def _send_error_page(http_pkt):
        """
        responds to the given http request with an error page
        """
        ip_packet = IP(src=http_pkt.dst, dst=http_pkt.src)
        tcp_packet = TCP(sport=http_pkt.dport, dport=http_pkt.sport, seq=http_pkt.ack, flags='A',
                         ack=http_pkt.seq + len(http_pkt[TCP].payload))
        with open('dropped.html') as fh:
            error_page = fh.read()
            error_packet = ip_packet / tcp_packet / error_page
            send(error_packet)


class IPSniffer(object):
    def __init__(self, inspector):
        self.inspector = inspector
        self._sesssion_fragments_dict = defaultdict(list)

    def process_packet(self, pkt):
        """
        handles IP fragmentation and passes packets to inspection
        :param pkt:
        :return:
        """
        scapy_packet = IP(pkt.get_payload())

        if IP in scapy_packet:
            # check MF=0 and offset = 0 (lone packet)
            if scapy_packet[IP].frag == 0 and scapy_packet[IP].flags & 1 == 0:
                if self.inspector.inspect(scapy_packet):
                    pkt.accept()
                else:
                    pkt.drop()

                return

            # otherwise the packet is fragmented. our strategy is that we allow it through
            # until the last fragment arrives, then inspect the full packet and drop or accept the last fragment.

            sess = (scapy_packet.src, scapy_packet.dst, scapy_packet[IP].id)
            session_fragments = self._sesssion_fragments_dict[sess]
            session_fragments.append(scapy_packet)

            # remove the packet from our cache in X seconds:
            def cache_cleaner():
                session_fragments.remove(scapy_packet)
                if len(session_fragments) == 0:
                    del self._sesssion_fragments_dict[sess]

            Timer(30, cache_cleaner)

            full_packet = self._reconstruct_fragments(sess)

            if full_packet is None:
                # packet is a fragment of a bigger packet, we accept it,
                # and we'll reject, if needed, when we can reconstruct the entire thing.
                pkt.accept()
            else:
                # this is either a stand alone packet, a reconstructed packet,
                # or the last fragment of a fragmented packet with offset = 0
                # in all those cases, we inspect and act accordingly.
                if self.inspector.inspect(full_packet):
                    pkt.accept()
                else:
                    pkt.drop()

        else:
            pkt.accept()

    def _reconstruct_fragments(self, sess):
        """
        attempts to reconstruct the packets in sess,
        return entire packet if successful (i.e. we have all the parts), None otherwise.
        :param sess:
        """
        pkts = sorted(self._sesssion_fragments_dict[sess],
                      key=lambda p: p[IP].frag)
        if pkts[-1][IP].flags & 1 > 0:
            return None
        if pkts[0][IP].frag > 0:
            return None

        next_offset = 0
        for pkt in pkts:

            if next_offset / 8 != pkt[IP].frag:
                # import pdb; pdb.set_trace()
                return None
            next_offset += len(pkt.payload)

        payloads = "".join([str(x.payload) for x in pkts])
        if pkts[-1][IP].proto == IP_PROTOCOLS_TCP:
            payloads = TCP(payloads)  # we don't current support UDP inspections.

        reconstructed_packet = IP(pkts[-1][IP].build()[:20]) / payloads

        return reconstructed_packet


def parse_config(file_path):
    """
    Parses config file and returns list of extensions that must be filtered
    :param file_path: string
    :return: list
    """
    with open(file_path, 'r') as f:
        return f.read().split("\n")


class SSHInspector(object):
    def __init__(self):
        self._allowed_connections = set()
        self.client_challenges = dict()

    def inspect(self, scapy_packet):
        if TCP in scapy_packet:
            client_ip = scapy_packet[IP].src
            # hashable set
            session = frozenset([client_ip, scapy_packet[IP].dst])

            # magic packet - open port?
            if scapy_packet[TCP].dport == 4242:
                self._handle_first_knock(scapy_packet)
                return False

            # second knock, should be the response of challenge-response.
            elif scapy_packet[TCP].dport == 4243:
                self._handle_second_knock(scapy_packet)
                return False

            # SSH - is he authorized?
            elif scapy_packet[TCP].dport == 22 or scapy_packet[TCP].sport == 22:
                return session in self._allowed_connections

        return True

    @staticmethod
    def _get_client_secret(ip):
        with open('secrets.json') as fh:
            secrets_list = json.load(fh)
            secrets = dict([(ip_secret['ip'], ip_secret['secret']) for ip_secret in secrets_list])
            return secrets[ip]

    def _handle_first_knock(self, scapy_packet):
        """
        sends a challenge to the client
        :param scapy_packet:
        """
        client_ip = scapy_packet[IP].src
        try:
            client_secret = self._get_client_secret(client_ip)
        except KeyError:
            print "Unknown client trying to knock."
            return False

        correct_hash = sha1(client_secret)
        if correct_hash == str(scapy_packet[TCP].payload):
            self._send_challenge(scapy_packet)
        else:
            print "Received invalid knock"

    def _send_challenge(self, scapy_packet):
        client_ip = scapy_packet[IP].src
        challenge = random.randint(0, 2 ** 32)
        self.client_challenges[client_ip] = challenge

        pkt = IP(src=scapy_packet[IP].dst, dst=client_ip) / TCP(seq=random.randint(0, 2 ** 32),
                                                                ack=scapy_packet[TCP].seq + 1,
                                                                sport=scapy_packet[TCP].dport,
                                                                dport=scapy_packet[TCP].sport) / str(challenge)
        send(pkt)

    def _handle_second_knock(self, scapy_packet):
        client_ip = scapy_packet[IP].src
        client_response = scapy_packet[Raw].load
        try:
            challenge = self.client_challenges[client_ip]
        except KeyError:  # aha! someone tried to get smart.
            return
        correct_response = sha1('weeeeeee' + str(challenge))

        if correct_response == client_response:
            session = frozenset([client_ip, scapy_packet[IP].dst])
            self._allowed_connections.add(session)
            print "Allowing connections for session %r" % session
        else:
            print "Wrong response received"


class ChainedInspector(object):
    def __init__(self, *inspectors):
        self.inspectors = inspectors

    def inspect(self, pkt):
        for inspector in self.inspectors:
            if not inspector.inspect(pkt):
                return False

        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Blocks forwarding of HTTP requests for restricted file types, '
                                                 'and blocks SSH unless TCP port knocking was used')
    parser.add_argument('--silent', dest='silent', action='store_true',
                        help='Whether to reply with an error or silently drop')

    args = parser.parse_args()
    http_silent = args.silent

    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    filter_extensions = parse_config('config')
    http_inspector = HttpInspector(filter_extensions, http_silent)
    ssh_inspector = SSHInspector()
    multi_inspector = ChainedInspector(ssh_inspector, http_inspector)
    sniffer = IPSniffer(multi_inspector)
    nfqueue = NetfilterQueue()

    try:
        nfqueue.bind(1, lambda x: sniffer.process_packet(x))
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        os.system('iptables -F')
        os.system('iptables -X')
