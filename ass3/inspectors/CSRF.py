import urlparse

from scapy.layers.http import HTTPRequest

from ass3.inspectors.Base import HttpInspector


class CSRF(HttpInspector):
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
