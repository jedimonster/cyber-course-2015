from scapy.all import *
from netfilterqueue import NetfilterQueue

REG_HTTP_GET = re.compile("^GET\s([A-Za-z0-9\-\._~:\?\\#]+)\sHTTP\/\d\.\d")


class HttpInspector:
    def inspect(self, payload):
        if TCP in payload:
            layer5 = payload.payload
            results = re.search(REG_HTTP_GET, str(layer5))
            if results is not None:
                print results.group(1)

        return True
        # import pdb; pdb.set_trace()
        pass


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
                    if self.inspector.inspect(scapy_packet[IP].payload):
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


if __name__ == '__main__':
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    inspector = HttpInspector()
    sniffer = IPSniffer(inspector)
    nfqueue = NetfilterQueue()
    print "Starting queue"

    nfqueue.bind(1, lambda x: sniffer.process_packet(x))
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
