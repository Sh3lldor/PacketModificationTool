import sys
from scapy.all import *
from scapy.utils import rdpcap
import fire


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def pcapFile(pcap="", list=False, modify=False,pcapName="",send=False):
    if pcap == "":
        print("[x] No PCAP file was specified")
        sys.exit(1)

    print("[x] Using %s as PCAP file" % pcap)
    pkts=rdpcap(pcap)

    count = 0
    newPkts = []
    for pkt in pkts:
        if list:
            get_packet_layers(pkt, count)
            count += 1
        if modify: 
            if pcapName:
                newPkts.append(modify_packet_layers(pkt))
            else:
                print("[x] --pcapName flag is required")
                sys.exit(1)
                
    if modify:
        wrpcap(pcapName, newPkts)
        if list:
            for pkt in newPkts:
                get_packet_layers(pkt, count)

    if send:
        if pcapName:
            sendp(rdpcap(pcapName))
        else:
            print("[x] --pcapName flag is required")
            sys.exit(1)

    
def get_packet_layers(packet, count):
    srcIP = packet[IP].src
    dstIP = packet[IP].dst
    srcPort = packet[TCP].sport
    dstPort = packet[TCP].dport
    rawData = packet[Raw].load
    print(bcolors.OKGREEN + "[%s] Details %s -> %s | %s -> %s" % \
    (count,srcIP,dstIP,srcPort,dstPort) + bcolors.ENDC )
    print("[%s] Data: %s " % (count,rawData))


def modify_packet_layers(packet):
    print("[x] Current src IP: %s" % packet[IP].src)
    newSrcIp = input("[x] New src IP [Enter to Unchange]: ")
    print("[x] Current dst IP: %s" % packet[IP].dst)
    newDstIp = input("[x] New dst IP [Enter to Unchange]: ")
    print("[x] Current data: %s" % packet[Raw].load)
    newData = input("[x] New data [Enter to Unchange]: ")
    if newSrcIp:
        packet[IP].src = newSrcIp
    if newDstIp:
        packet[IP].dst = newDstIp
    if newData:
        packet[Raw].load = newData
    
    return packet


if __name__ == '__main__':
    fire.Fire(pcapFile)