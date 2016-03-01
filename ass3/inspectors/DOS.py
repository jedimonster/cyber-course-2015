from ass3.inspectors.Base import BaseHttpInspector


class DOS(BaseHttpInspector):
    def inspect(self, pkt):
        return True
