import argparse
import json
from scapy.all import *
from netfilterqueue import NetfilterQueue

from scapy.tools.UTscapy import sha1

REG_HTTP_GET = re.compile("^GET\s([A-Za-z0-9\/\-\._~:\?\\#]+)\sHTTP\/\d\.\d")


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

                for extension in filtered_extensions:
                    if url.find('.' + extension) != -1:
                        print "Filtered packet for uri %s" % (url)
                        if not self.silent:
                            self._send_error_page(packet)
                        return False

        return True

    def _send_error_page(self, packet):
        ip_packet = IP(src=packet.dst, dst=packet.src)
        tcp_packet = TCP(sport=packet.dport, dport=packet.sport, seq=packet.ack, flags='A',
                         ack=packet.seq + len(packet[TCP].payload))
        with open('dropped.html') as fh:
            error_page = fh.read()
            error_packet = ip_packet / tcp_packet / error_page
            send(error_packet)


class IPSniffer(object):
    def __init__(self, inspector):
        self.inspector = inspector
        self._sesssion_fragments_dict = dict()

    def process_packet(self, pkt):
        """
        handles IP fragmentation and passes packets to inspection
        :param scapy_packet:
        """
        scapy_packet = IP(pkt.get_payload())

        if IP in scapy_packet:

            # check more fragments flag
            sess = (scapy_packet.src, scapy_packet.dst, scapy_packet[IP].id)
            if scapy_packet[IP].flags & 1 > 0:  # there are more fragments
                pkt.accept()  # we'll drop the last fragment if it's malicious.
                if sess in self._sesssion_fragments_dict:
                    self._sesssion_fragments_dict[sess].append(scapy_packet)
                else:
                    self._sesssion_fragments_dict[sess] = [scapy_packet]
            else:  # no more fragments
                if sess not in self._sesssion_fragments_dict:
                    if self.inspector.inspect(scapy_packet[IP]):
                        pkt.accept()
                    else:
                        pkt.drop()
                # need to reconstruct the packet
                else:
                    self._sesssion_fragments_dict[sess].append(scapy_packet)
                    reconstructed_pkt = self._reconstruct_fragments(self._sesssion_fragments_dict[sess])
                    if self.inspector.inspect(reconstructed_pkt):
                        pkt.accept()
                    else:
                        pkt.drop()
                    self._sesssion_fragments_dict[sess] = None
        else:
            pkt.accept()

    def _reconstruct_fragments(self, scapy_packets):
        # scapy_packets = [IP(x.get_payload()) for x in pkts]
        # sort by offset

        sorted_packets = sorted(scapy_packets, key=lambda x: x[IP].frag)
        payloads = "".join([str(x.payload) for x in sorted_packets])
        reconstructed_packet = IP(sorted_packets[-1][IP].build()[:20]) / TCP(payloads)
        print reconstructed_packet.show()
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

    def inspect(self, pkt):
        scapy_packet = IP(pkt.get_payload())

        if TCP in scapy_packet:
            client_ip = scapy_packet[IP].src
            client_secret = self._get_client_secret(client_ip)

            # magic packet - open port?
            if scapy_packet[TCP].dport == 4242:

                current_time = time.time() << 3
                correct_hash = sha1(client_secret + current_time)

                if (correct_hash == scapy_packet[TCP].payload):
                    if scapy_packet[TCP].flags == "S":
                        print "Accepting SSH from %s" % (client_ip)
                        self._allowed_connections.add(client_ip)
                    elif scapy_packet[TCP].flags == "F":
                        print "Rejecting SSH from %s" % (client_ip)
                        self._allowed_connections.remove(client_ip)


            # SSH - is he authorized?
            elif scapy_packet[TCP].dport == 22:
                return client_ip in self._allowed_connections

    def _get_client_secret(self, ip):
        with open('secrets.json') as fh:
            secrets_list = json.load(fh)
            secrets = dict([(ip_secret['ip'], ip_secret['secret']) for ip_secret in secrets_list])
            return secrets[ip]


class ChainedInspector(object):
    def __init__(self, *inspectors):
        self.inspectors = inspectors

    def inspect(self, pkt):
        for inspector in self.inspectors:
            if not inspector.inspect(pkt):
                return False

        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Blocks forwarding of HTTP requests for restricted file types.')
    parser.add_argument('--silent', dest='silent', action='store_true',
                        help='Whether to reply with an error or silently drop')

    args = parser.parse_args()
    silent = args.silent

    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    filtered_extensions = parse_config('config')
    http_inspector = HttpInspector(filtered_extensions, silent)
    ssh_inspector = SSHInspector()
    multi_inspector = ChainedInspector(ssh_inspector, http_inspector)
    sniffer = IPSniffer(http_inspector)
    nfqueue = NetfilterQueue()

    try:
        nfqueue.bind(1, lambda x: sniffer.process_packet(x))
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        os.system('iptables -F')
        os.system('iptables -X')
