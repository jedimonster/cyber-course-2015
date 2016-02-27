class HttpInspector(object):
    def __init__(self, http_logger):
        self.http_logger = http_logger

    def inspect(self, pkt):
        """
        inspects the given packet, if it's allowed, returns it (possibly modified) otherwise returns None
        :param pkt: scapy packet
        """
        raise NotImplementedError()
