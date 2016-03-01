import re
import urlparse

from scapy.layers.http import HTTPRequest

from ass3.inspectors.Base import BaseHttpInspector


class PathTraversal(BaseHttpInspector):
    def __init__(self, http_logger, logger, write=True, block=True):
        super(PathTraversal, self).__init__(http_logger, logger, write, block)

    def inspect(self, pkt):
        if HTTPRequest in pkt:
            url = pkt[HTTPRequest].fields['Path']

            if "../" in url:
                self.logger.log_if_needed("Warning: suspected Path Traversal Attack (path: %s)" % url, self.write)

                # at this point we either block or ignore the rest of the suspects
                return not self.block

        return True

