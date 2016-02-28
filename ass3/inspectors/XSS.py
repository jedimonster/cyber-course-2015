from scapy_http.http import HTTPRequest

from ass3.inspectors.Base import BaseHttpInspector


class XSS(BaseHttpInspector):
    def inspect(self, pkt):
        if HTTPRequest in pkt:
            pass

        return True