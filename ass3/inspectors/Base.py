"""
Abstract class that represent inspector.
"""
class BaseHttpInspector(object):
    def __init__(self, http_logger, logger, write=True, block=True):
        self.write = write
        self.block = block
        self.logger = logger

    def inspect(self, pkt):
        """
        inspects the given packet, returns true iff it's allowed through
        :param pkt: scapy packet
        """
        raise NotImplementedError()
