#coding=utf-8
from scapy.all import *
# 数据包回调函数
from scapy.layers.inet import TCP,IP
import os


# 数据包回调函数
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        # print packet
        # print mail_packet.lower()
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] src IP: %s" % packet[IP].src)
            print("[*] dst IP: %s" % packet[IP].dst)
            print("[*] %s" % packet[TCP].payload)

def dump_file():
    #print("Testing the dump file...")
    dump_file = 'test1.pcap'
    if os.path.exists(dump_file):
        print("dump file %s found." % dump_file)
        pkts = sniff(offline=dump_file)
        print(pkts.summary())
        print(hexdump(pkts))
    else:
        print("dump file %s not found." % dump_file)


if __name__ == '__main__':
    # 开启嗅探器，过滤出tcp协议,默认端口80
    #package = sniff(filter="tcp port 80", prn=packet_callback, store=0)

 #   flowName = "test1.pcap"
  #  wrpcap(flowName, package)  # 将抓取到的包保存为test.pcap文件
    #sniff(prn=write_cap)
    dump_file()
