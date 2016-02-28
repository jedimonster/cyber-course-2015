
class Logger(object):
    """
    Responsible to write logs.
    Inner function log can be used to rite to stdout or db, depends what we want.
    """
    def log(self, data):
        raise NotImplemented("Logger is abstract class")


class StdoutLogger(Logger):
    """
    Writes warnings to stdout.
    """

    def log(self, data):
        print data

    def log_if_needed(self, data, write):
        """
        if write is true, calls to log
        data : data to log
        write - boolean true or false
        :return:
        """
        if data:
            self.log(data)