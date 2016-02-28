import urlparse

from scapy.layers.http import HTTPRequest

from ass3.inspectors.Base import BaseHttpInspector


class CSRF(BaseHttpInspector):

    def __init__(self, http_logger, write=True, block=True):
        super(CSRF, self).__init__(http_logger)
        self.write = write
        self.block = block

    def inspect(self, pkt):
        if HTTPRequest in pkt and pkt[HTTPRequest].fields['Method'] == 'POST':
            pkt = pkt[HTTPRequest]
            if 'Referer' in pkt.fields:
                ref = pkt.fields['Referer']
                parts = urlparse.urlparse(ref)
                if parts.hostname != pkt.fields['Host']:
                    print "Blocked: POST to HOST %s from REFER %s." % (pkt.fields['Host'], ref)
                    return False

            else:
                print "Blocked: POST to HOST %s from empty REFER." % (pkt.fields['Host'])
                return False

        return True
