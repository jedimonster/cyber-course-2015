from scapy.all import *
from netfilterqueue import NetfilterQueue

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

                        return False

        return True


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
            sess = (scapy_packet.src, scapy_packet.dst)
            if scapy_packet[IP].flags & 1 > 0:  # there are more fragments
                if sess in self._sesssion_fragments_dict:
                    self._sesssion_fragments_dict[sess].append(scapy_packet)
                else:
                    self._sesssion_fragments_dict[sess] = [scapy_packet]
            else:  # no more fragments
                if scapy_packet.src not in self._sesssion_fragments_dict:
                    if self.inspector.inspect(scapy_packet[IP]):
                        pkt.accept()
                    else:
                        pkt.drop()
                # need to reconstruct the packet
                else:
                    # todo this isn't handled yet.
                    reconstructed_pkt = self._reconstruct_fragments(self._sesssion_fragments_dict[sess])
                    self._sesssion_fragments_dict[sess] = None
        else:
            pkt.accept()

    def _reconstruct_fragments(self, param):
        pass


def parse_config(file_path):
    """
    Parses config file and returns list of extensions that must be filtered
    :param file_path: string
    :return: list
    """
    with open(file_path, 'r') as f:
        return f.read().split("\n")


if __name__ == '__main__':
    silent = False
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    filtered_extensions = parse_config('config')
    inspector = HttpInspector(filtered_extensions, silent)
    sniffer = IPSniffer(inspector)
    nfqueue = NetfilterQueue()

    nfqueue.bind(1, lambda x: sniffer.process_packet(x))
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
