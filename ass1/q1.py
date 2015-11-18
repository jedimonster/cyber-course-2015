#!/usr/bin/python

from scapy.all import *
import re
import argparse

captured = set()
USER_AGENT_PATTERN = re.compile("User-Agent: (.*)\r\n")

def analyzer_packet(analyzers, test_packet):
    """

    :param analyzers: list of methods that can anlyze single packet
    :param test_packet: packet to be tested
    :return: IP and result of analisys if analysis succesefull , otherwise None
    """
    for analyzer in analyzers:
        res = analyzer(test_packet)
        if res is not None:
            res, method = res
            if IP in test_packet:
                entry = ", ".join([method,test_packet[IP].src, res])
                if entry not in captured:
                    captured.add(entry)
                    print entry


def analyze_tcp_opts(test_packet):
    """
    analyzes tcp options
    :param test_packet:  packet to test
    :return: "Linux" if timestamp in tcp options
    """
    if TCP in test_packet and test_packet[TCP].options:
        for item in test_packet[TCP].options:
            if 'Timestamp' in item:
                return "Linux", "TCP (Options)"


def analyze_window_size(test_packet):
    """
    analyzes tcp window
    :param test_packet: packet to test
    :return: Windows if tcp.window is 8192
    """
    if TCP in test_packet and test_packet[TCP].window == 8192:
        return "Windows", "TCP (Window Size)"


def analyze_ttl(test_packet):
    """
    analyzes ttl
    :param test_packet: packet to test
    :return: "Windows" or "Linux", depending on ttl
    """
    if IP in test_packet:
        if test_packet[IP].ttl <= 64:
            return "Linux", "IP (TTL)"
        if 64 <= test_packet[IP].ttl <= 128:
            return "Windows", "IP (TTL)"


def analyze_user_agent(test_packet):
    """
    analyzes user agent
    :param test_packet: packet to test
    :return: user agent field in http protocol if exist
    """
    try:
        data = test_packet[TCP][1]
    except:
        return None
    data = str(data)
    res = re.search(USER_AGENT_PATTERN, data)
    if res is not None:
        return res.group(1), "HTTP (User-Agent)"

if __name__ == "__main__":
    ANALYZERS = [analyze_tcp_opts, analyze_window_size, analyze_ttl, analyze_user_agent]
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path to pcap file to be analized")
    parser.add_argument("-s", "--sniffer", help="run script in sniffer mode",
                        action="store_true")
    args = parser.parse_args()

    # sniffer mode
    if (not args.sniffer) and (not args.file):
        raise argparse.ArgumentTypeError('-f or -s parameters has to be used')
    if args.file:
        data = rdpcap(args.file)
        for item in data:
            analyzer_packet(ANALYZERS, item)
    else:
        print "sniffer mode"
