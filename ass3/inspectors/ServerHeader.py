import re

from scapy.layers.http import HTTPResponse

from ass3.inspectors.Base import BaseHttpInspector


class ServerHeaderInspector(BaseHttpInspector):
    def __init__(self, http_logger):
        super(ServerHeaderInspector, self).__init__(http_logger)
        self.VersionNumberRegexp = re.compile('\d+\.\d+')

    def inspect(self, packet):
        if HTTPResponse in packet:
            packet = packet[HTTPResponse]

            if 'Server' in packet.fields:
                server_version = packet.fields['Server']

                if self.VersionNumberRegexp.search(server_version) is not None:
                    print "Warning: server version is advertised (%s)." % (server_version)

        return True
