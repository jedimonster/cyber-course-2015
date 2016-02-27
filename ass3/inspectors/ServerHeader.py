from ass3.inspectors.Base import HttpInspector


class ServerHeaderInspector(HttpInspector):
    def inspect(self, packet):
        print packet
        return packet
