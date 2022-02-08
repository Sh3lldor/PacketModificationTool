import sys
from scapy.all import *
from scapy.utils import rdpcap
import fire
import re

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


def showHelp():
    print("=========================== Packet Modification Tool ===========================\n \
Args:\n \
    --pcap      The name of the PCAP to parse\n \
    --list      If supplied, more details will be printed\n \
    --modify    If supplied, the PCAP file will be modified\n \
    --pcapName  The new PCAP name, Is necessary when using --modify\n \
    --send      Sending the new PCAP, --modify and --pcapName are necessary\n \
    --srcIP     The new source ip for the packets, --modify is necessary\n \
    --srcPort   The new source port for the packets, --modify is necessary\n \
    --dstIP     The new destination ip for the packets, --modify is necessary\n \
    --dstPort   The new destination port for the packets, --modify is necessary\n \
    --rawdata   The new data (Raw format), --modify is necessary\n \
    --hexdata   The new data (Hex format), --modify is necessary\n \
    --help      Show this help msg\n \
                                                                      @elad_pt")
    


def pcapFile(pcap="",list=False,modify=False,pcapName="",send=False,srcIP="",srcPort="",dstIP="", \
             dstPort="",rawdata="",hexdata="", help=False):
    if help:
        showHelp()
        sys.exit(0)

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
                newPkts.append(modify_packet_layers(pkt, srcIP, srcPort,dstIP, dstPort, rawdata, hexdata))
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
    print(bcolors.OKGREEN + "[%s] Details %s:%s -> %s:%s" % \
    (count,srcIP,srcPort,dstIP,dstPort) + bcolors.ENDC )
    print("[%s] Hex Data: %s " % (count,bytes_hex(rawData)))
    print("[%s] Raw Data: %s " % (count,rawData))


def modify_packet_layers(packet,sourceIP="",sourcePort="",destinationIP="",destinationPort="",rawData="", hexdata=""):
    flag = 1
    if sourceIP:
        packet[IP].src = sourceIP
        flag = 0
    if sourcePort:
        packet[TCP].sport = sourcePort
        flag = 0
    if destinationIP:
        packet[IP].dst = destinationIP
        flag = 0
    if destinationPort:
        packet[TCP].dport = destinationPort
        flag = 0
    if rawData or hexdata:
        if rawData:
            packet[Raw].load = rawData
        else:
            packet[Raw].load = hex_bytes(hexdata)
        flag = 0
    
    if flag:
        print("[x] Current src IP: %s" % packet[IP].src)
        newSrcIp = input("[x] New src IP [Enter to Unchange]: ")
        print("[x] Current dst IP: %s" % packet[IP].dst)
        newDstIp = input("[x] New dst IP [Enter to Unchange]: ")
        print("[x] Current data: %s" % packet[Raw].load)
        dataType = input("[x] Raw or Hex data [Type r/h]: ")
        newData = input("[x] New data [Enter to Unchange]: ")
        if newSrcIp:
            packet[IP].src = newSrcIp
        if newDstIp:
            packet[IP].dst = newDstIp
        if newData:
            if dataType == "r":
                packet[Raw].load = newData
            elif dataType == "h":
                packet[Raw].load = hex_bytes(newData)
            else:
                print("[x] No data type ! exsiting.")
                sys.exit(1)
    
    return packet

if __name__ == '__main__':
    fire.Fire(pcapFile)