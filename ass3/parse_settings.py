"""
Settings parsing functions
"""

def parse_settings(path):
    """
    :param path: path to Settings file
    :return: list of triples with (name_of_inspector, write, block) last two are booleans
    """
    data = [x.split(" ") for x in open(path).read().split("\n") if x != ""]
    inspectors = [x[0] for x in data]
    writes = [1 if 'W' in x[1] else 0 for x in data]
    blocks = [1 if 'B' in x[1] else 0 for x in data]
    return zip(inspectors, writes, blocks)

if __name__ == "__main__":
    res = parse_settings("Settings")
    print res