"""
Path traversal vulnerabilities can be found when the application allows user-controllable
data to interact with the filesystem.
This inspector will attempt to catch Path traversal attacks.
"""
import re
import urlparse
from oauthlib.common import urldecode

from scapy.layers.http import HTTPRequest
from ass3.inspectors.Base import BaseHttpInspector


class PathTraversal(BaseHttpInspector):
    def __init__(self, http_logger, logger, write=True, block=True):
        super(PathTraversal, self).__init__(http_logger, logger, write, block)

    def inspect(self, pkt):
        if HTTPRequest in pkt:
            url = pkt[HTTPRequest].fields['Path']

            if "../" in url or '../' in urldecode(url):
                self.logger.log_if_needed("Warning: suspected Path Traversal Attack (path: %s)" % url, self.write)

                return not self.block

        return True
