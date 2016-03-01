import os
from netfilterqueue import NetfilterQueue
from scapy.layers import http
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from ass2.q3 import IPSniffer
from ass3.inspectors.CSRF import CSRF
from ass3.inspectors.PathTraversal import PathTraversal
from ass3.inspectors.SQLInjection import SQLInjection
from ass3.inspectors.ServerHeader import ServerHeaderInspector

from ass3.inspectors.XSS import XSS
from ass3.parse_settings import parse_settings
from ass3.warning_logger import StdoutLogger


class ChainedHttpInspect(object):
    def __init__(self, inspectors_str):
        self.http_logger = HttpLogger()
        self._inspectors = self._create_inspectors(inspectors_str)

    def inspect(self, pkt):
        self.http_logger.log(pkt)

        for inspector in self._inspectors:
            if not inspector.inspect(pkt):
                return False

        return True

    def _create_inspectors(self, inspectors_str):
        """

        :param inspectors_str: list of tuples from parse_settings
        :return:
        """
        # list of supported inspectors
        logger = StdoutLogger()
        res = []
        supported_inspectors = [CSRF, ServerHeaderInspector, XSS, SQLInjection, PathTraversal]
        sp_strings = [x.__name__ for x in supported_inspectors]
        for item in inspectors_str:
            if item[0] in sp_strings:
                index = sp_strings.index(item[0])
                res.append(supported_inspectors[index](self.http_logger, logger,  item[1], item[2]))
        return res
        # return inspectors


class HttpLogger(object):
    def __init__(self):
        self.requests = []
        self.responses = []
        self.MaxCacheSize = 10000

    def log(self, pkt):
        if HTTPRequest in pkt:
            self.requests += pkt

            if len(self.requests) > self.MaxCacheSize:
                self.requests.remove(0)

        elif HTTPResponse in pkt:
            self.responses += pkt

            if len(self.responses) > self.MaxCacheSize:
                self.responses.remove(0)


if __name__ == '__main__':
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
    config = parse_settings("Settings")
    http_inspector = ChainedHttpInspect(config)

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
