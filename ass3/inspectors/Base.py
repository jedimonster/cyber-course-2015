class HttpInspector(object):
    def __init__(self, http_logger):
        self.http_logger = http_logger

    def inspect(self, pkt):
        """
        inspects the given packet, returns true iff it's allowed through
        :param pkt: scapy packet
        """
        raise NotImplementedError()
