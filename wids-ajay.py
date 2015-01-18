#Fonte: http://www.meajay.in/project/wids
#written by Ajay
#EMail : ajay@meajay.in
#Usage: run this script with root access giving monitor mode enabled
#interface name as command line argument
#Ex: python WIDS_0.1_.py mon0


import scapy
import datetime
import sys
from scapy.all import *

FakeAPThresold = 5
global timestampDict
global timestampCount
deauthCount=0
deauthThreshold=5
START=5
global radiotapTalbe

#detects fake access points which use random timestamp field by comparing timestamp
#and maitaining count
def MonitorFakeAP(pkt):
    global FakeAPThresold
    global timestampDict
    global timestampCount
    if(pkt.type==0 and pkt.subtype==8):
        bssid=pkt.addr2
        ssid=pkt.info
        timestamp=pkt.timestamp
        if bssid not in timestampDict:
            timestampDict[bssid]=timestamp
            timestampCount[bssid]=0
        elif (timestamp <= timestampDict[bssid]):
            timestampCount[bssid]+=1
            if timestampCount[bssid] > FakeAPThresold :
                print "Detected Fake Access Point for ssid '%s'"%(ssid)
        timestampDict[bssid]=timestamp

#detecting deauth DOS attack by keeping count of deauth packets
def MonitorDeauth(pkt):
    global deauthCount
    if((pkt.type==0) and (pkt.subtype==12)):
        deauthCount+=1
        diff = datetime.datetime.now()-start
        if((diff.seconds > START) and ((deauthCount/diff.seconds) > deauthThreshold)):
            print "Detected Deauth against : "+pkt.addr1

#maintain radiotap header for each sender
def MaintainRadiotapTable(pkt):
    global radiotapTable
    if(pkt.getlayer(Dot11).type==2):
        radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
        sender=pkt.getlayer(Dot11).addr2
        if sender not in radiotapTable:
            radiotapTable[sender]=radiotap

#monitor change in radiotap header in deauth packets
def MonitorDeauth2(pkt):
    sender=pkt.getlayer(Dot11).addr2
    radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
    if sender in radiotapTable:
        radiotap2=radiotapTable[sender]
        if radiotap2!=radiotap:
            print "Detected Deauth against : %s by change in radiotap header"%(pkt.getlayer(Dot11).addr1)
            

def IDS(pkt):
    if(pkt.haslayer(Dot11)):
        if(pkt.getlayer(Dot11).type==2):
            MaintainRadiotapTable(pkt)
        if((pkt.getlayer(Dot11).type==0) and (pkt.getlayer(Dot11).subtype==12)):
            MonitorDeauth(pkt.getlayer(Dot11)) #detect for deauth attack
            MonitorDeauth2(pkt) #detect for deauth attack by monitoring change in radiotap header
        if(pkt.getlayer(Dot11).type==0 and pkt.getlayer(Dot11).subtype==8):
            MonitorFakeAP(pkt.getlayer(Dot11)) #detect fake access points




timestampDict= {}
timestampCount={}
radiotapTable={}
start=datetime.datetime.now()
sniff(iface=sys.argv[1],prn=IDS)
