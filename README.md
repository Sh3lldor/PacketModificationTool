# PacketModificationTool
Little script to parse PCAP files


## Usage
pip3 install -r requirements.txt
python3 parse.py

## Example

1) Writing new hex data to GIOP packet
```bash
python3 parse.py --pcap g.pcapng --list --modify --pcapName g2.pcapng 
--srcIP 1.1.1.1 --srcPort 1000 --dstIP 2.2.2.2 --dstPort 5555
--hexdata 47494f5001020000000000340000a93e03000000000000000000000b47756172644f626a656374000000000e746573744578697374616e6365656c616470740a00000000000000
```
2) List PCAP data
```bash
python3 parse.py --pcap g.pcapng --list
```
3) Manually modify packets
```bash
python3 parse.py --pcap g.pcapng --list --modify --pcapName g2.pcapng
```

## Pictures
1) Change packet data with flags

![alt text](https://github.com/Sh3lldor/PacketModificationTool/blob/main/Pics/1.PNG)
2) Change packet data Manually

![alt text](https://github.com/Sh3lldor/PacketModificationTool/blob/main/Pics/2.PNG)
