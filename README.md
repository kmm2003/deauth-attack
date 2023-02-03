# deauth-attack

## requirement
- python 3.9+
- scapy

## usage
```
syntax: python deauth-attack.py <interface> <ap mac> [-s <statio mac> | -auth]
sample: python deauth-attack.py wlan0 0C:96:CD:57:A3:0B -s 3C:A0:67:63:27:A5 -auth
```

If you enter only ap mac, the AP broadcast will be sent.
If you use the "-s" option, the AP unicast is sent.

If you want to do auth attack, please add "-auth" option.
