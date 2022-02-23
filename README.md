# PacketModificationTool
Little script to parse PCAP files

## Installation
1) pip3 install -r requirements.txt
2) sudo apt install xxd

## Usage
1) python3 parse.py
2) ./convert.sh encode/decode <HEX data/RAW data>

## Example

1) Writing new hex data to a packet
```bash
python3 parse.py --pcap g.pcapng --list --modify --pcapName g2.pcapng 
--srcIP 1.1.1.1 --srcPort 1000 --dstIP 2.2.2.2 --dstPort 5555
--hexdata HEXDATA
```
2) List PCAP data
```bash
python3 parse.py --pcap g.pcapng --list
```
3) Manually modify packets
```bash
python3 parse.py --pcap g.pcapng --list --modify --pcapName g2.pcapng
```
