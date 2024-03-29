#!/usr/bin/python

import argparse
from scapy.all import *

# all networks that aren't internet, in readable format.
# we turn it into integers to be used as masks.
RESERVED_NETWORKS = [('0.0.0.0', 8),
                     ('10.0.0.0', 8),
                     ('100.64.0.0', 10),
                     ('127.0.0.0', 8),
                     ('169.254.0.0', 16),
                     ('172.16.0.0', 12),
                     ('192.0.0.0', 24),
                     ('192.0.2.0', 24),
                     ('192.88.99.0', 24),
                     ('192.168.0.0', 16),
                     ('198.18.0.0', 15),
                     ('198.51.100.0', 24),
                     ('203.0.113.0', 24),
                     ('224.0.0.0', 4),
                     ('240.0.0.4', 8),
                     ('255.255.255.255', 32)]


def ip_to_binary(ip):
    """
    turns a string IP into a 32bit integer.
    :param ip: string ip, assumed to be correct.
    :return: 32bit unsigned integer
    """
    result = 0
    ip = ip.split(".")
    if len(ip) < 4:
        raise RuntimeError('invalid ip address')

    ip = map(int, ip)
    for i in range(4):
        result += ip[i] << (8 * (3 - i))

    return result


def ip_in_network(ip, network):
    """
    checks if the given ip belongs to the given network mask
    :param ip: integer ip
    :param network: (integer subnet mask, integer significant bits)
    :return: True iff ip is in network
    """
    return mask_ip(ip, network[1]) == network[0]


def mask_ip(ip, bits):
    """
    uses bitwise operators to mask an ip to its first bits bits.
    :param ip: integer ip
    :param bits: bits to retain
    :return: integer ip masked to bits bits
    """
    return ip & ((~0) << (32 - bits))


def filter_external_ip(packet):
    """
    checks if the given packet is destined to a reserved ip address, or the internet
    :param packet: scapy packet
    :return: True iff packet is destined to the internet
    """
    if IP in packet:
        dst_ip = ip_to_binary(packet[IP].dst)
        for network in RESERVED_MASKS:
            if ip_in_network(dst_ip, network):
                return False

        return True


def detect_gateways(packets):
    # first detect packets that are destined outside, their destination MACs are gateways
    """
    Detects default gateways by looking for packetes that are destined to the internet, but sent to a local device
    :param packets: list of scapy packets
    :return: default gateways, represented as [(mac, ip), ...]
    """
    outgoing_packets = packets.filter(filter_external_ip)
    gateways_macs = set([packet.dst for packet in outgoing_packets])

    # build mac->ip dict from ARP requests/response. we assume no-one lies.
    arp_packets = [p for p in packets if ARP in p]
    mac_ip = dict([(p.src, p[ARP].psrc) for p in arp_packets])

    # now we find a packet that is sourced or destined to these macs
    gateways_macs_ips = [(mac, mac_ip[mac]) for mac in gateways_macs]

    return gateways_macs_ips


RESERVED_MASKS = [(ip_to_binary(x[0]), x[1]) for x in RESERVED_NETWORKS]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect default gateway in PCAP file')
    parser.add_argument('file', type=str, nargs=1,
                        help='PCAP file')
    args = parser.parse_args()
    filename = args.file[0]
    packets = rdpcap(filename=filename)
    gateways = detect_gateways(packets)

    for gateway in gateways:
        print "Default gateway was found on %s (%s) " % (gateway[1], gateway[0])
