class ChainedHttpInspect(object):
    def __init__(self, inspectors_str):
        self.http_logger = HttpLogger()
        print inspectors_str
        self._inspectors = self._create_inspectors(inspectors_str)

    def inspect(self, pkt):
        self.http_logger.log(pkt)

        for inspector in self._inspectors:
            if not inspector.inspect(pkt):
                return False

        return True

    def _create_inspectors(self, inspectors_str):
        # todo
        pass


class HttpLogger(object):
    def log(self, pkt):
        pass


if __name__ == '__main__':
    pass
