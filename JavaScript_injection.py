import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            modified_load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(bytes(new_packet))
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].chksum
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Request")
            print(scapy_packet.show())
    packet.accept()




queue = netfilterqueue.NetfilterQueue()

#0 is the queue number mentionned in iptables command
queue.bind(0, process_packet)

queue.run()