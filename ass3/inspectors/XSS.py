import re
import urlparse

from scapy.layers.http import HTTPRequest

from ass3.inspectors.Base import BaseHttpInspector


class XSS(BaseHttpInspector):
    def __init__(self, http_logger, logger, write=True, block=True):
        super(XSS, self).__init__(http_logger, logger, write, block)
        self.RE_SCRIPTS = re.compile("<script.*>", flags=re.IGNORECASE)
        self.RE_FRAMES = re.compile("<i?frame.*>", flags=re.IGNORECASE)

    def inspect(self, pkt):
        if HTTPRequest in pkt:
            url = pkt[HTTPRequest].fields['Path']
            parts = urlparse.urlparse(url)
            query_params = urlparse.parse_qs(parts.query)

            matches = map(lambda s: self.is_string_suspect(s[0]), query_params.values())

            if any(matches):
                self.logger.log_if_needed("Warning: suspected XSS Attack (params: %s)" % query_params, self.write)

                # at this point we either block or ignore the rest of the suspects
                return not self.block

            if pkt[HTTPRequest].fields['Method'] == 'POST':
                query_string = str(pkt[HTTPRequest].payload)
                query_params = urlparse.parse_qs(query_string)

                matches = map(lambda s: self.is_string_suspect(s[0]), query_params.values())

                if any(matches):
                    self.logger.log_if_needed("Warning: suspected XSS Attack (params: %s)" % query_params, self.write)

                    return not self.block

        return True

    def is_string_suspect(self, str):
        return self.RE_SCRIPTS.search(str) is not None or self.RE_FRAMES.search(str) is not None
