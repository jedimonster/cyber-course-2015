#!/usr/bin/python

from scapy.all import *
import re
import argparse
import sys

captured = set()
USER_AGENT_PATTERN = re.compile(r"User-Agent: (.*)\r\n")
BROWSER_PATTERN = re.compile("(Chrome.*?|Firefox.*?|Opera.*?|Chromium.*?)(\s|$)")
OS_PATTERN = re.compile(r"(Ubuntu|Windows)")
OS_VERSION_PATTERN = re.compile(r"(Linux x86_64|Windows.*WOW64)")


def parse_user_agent(ua):
    """
    If parsing fails(regex based), original ua returns
    :param ua: string - user agent string
    :return: parsed string or string without changes if parsing failed
    """
    browser = re.search(BROWSER_PATTERN, ua)
    operation_system = re.search(OS_PATTERN, ua)
    os_version = re.search(OS_VERSION_PATTERN, ua)
    if (browser is not None) and (operation_system is not None) and (os_version is not None):
        try:
            return operation_system.group(1) + " " + os_version.group(1).replace('WOW', "x"). \
                replace("10.0;", "10").replace(" NT ", "").replace("Windows", "") + "," + browser.group(1)
        except re.error:
            return ua
    return ua


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
                entry = ", ".join([method, test_packet[IP].src, res])
                if entry not in captured:
                    captured.add(entry)
                    return entry


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
        data_l5 = test_packet[TCP][1]
    except:
        return None
    data_l5 = str(data_l5)
    res = re.search(USER_AGENT_PATTERN, data_l5)
    if res is not None:
        return parse_user_agent(res.group(1)), "HTTP (User-Agent)"


if __name__ == "__main__":
    ANALYZERS = [analyze_tcp_opts, analyze_window_size, analyze_ttl, analyze_user_agent]
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="path to cap file to be analized")
    parser.add_argument("-s", "--sniffer", help="run script in sniffer mode",
                        action="store_true")
    args = parser.parse_args()
    if (not args.sniffer) and (not args.file):
        print('Usage: [-f FILE] [-s] ')
        sys.exit(1)
    if args.file:
        data = rdpcap(args.file)
        for item in data:
            analytic_res = analyzer_packet(ANALYZERS, item)
            if analytic_res is not None:
                print analytic_res
    else:
        sniff(prn=lambda x: analyzer_packet(ANALYZERS, x))
