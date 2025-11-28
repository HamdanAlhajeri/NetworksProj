# Multicast Lab Quick Notes

## Topology & IPs
- R1 Gi0/0: 172.168.1.24/30 ↔ R2 Gi0/0: 172.168.1.26/30 (transit)
- R1 Gi0/1 → switch LAN: 172.168.3.1/24
- R2 Gi0/1 → PC1: 172.168.2.34/24 (or /30 if you prefer; RP uses this IP)
- PC1: 172.168.2.1/24 (gateway 172.168.2.34)
- PC2: 172.168.3.2/24 (gateway 172.168.3.1)
- PC3: 172.168.3.3/24 (gateway 172.168.3.1)
- Multicast group: 239.1.1.1
- RP: 172.168.2.34

## Router configs (apply on both as appropriate)
```
ip multicast-routing
interface Gi0/x          ! set addresses per above
 ip pim sparse-mode
 ip igmp version 2
 no shut
ip pim rp-address 172.168.2.34
```

R1 specific:
```
interface Gi0/0
 ip address 172.168.1.24 255.255.255.252
interface Gi0/1
 ip address 172.168.3.1 255.255.255.0
```

R2 specific:
```
interface Gi0/0
 ip address 172.168.1.26 255.255.255.252
interface Gi0/1
 ip address 172.168.2.34 255.255.255.0   ! or /30 if you prefer point-to-point
```

## Switch (default VLAN 1)
```
ip igmp snooping
interface FaX   ! uplink to R1 Gi0/1
 switchport mode access
 switchport access vlan 1
 spanning-tree portfast
interface Fa0   ! PC2
 switchport mode access
 switchport access vlan 1
 spanning-tree portfast
interface Fa1   ! PC3
 switchport mode access
 switchport access vlan 1
 spanning-tree portfast
```

## PCs
- PC1 (sender): set NIC IP 172.168.2.1/24, gateway 172.168.2.34, link up.
- PC2: IP 172.168.3.2/24, gateway 172.168.3.1.
- PC3: IP 172.168.3.3/24, gateway 172.168.3.1.
- If UFW enabled on receivers: `sudo ufw allow in proto udp to any port 5004` and `sudo ufw allow in proto 2`.

## Running apps
- Sender (from `src/` on PC1):
```
python3 cli.py sender \
  --group 239.1.1.1 --port 5004 \
  --iface 172.168.2.1 \
  --file /path/to/video.ts \
  --content-type video \
  --ttl 4 --chunk-size 1316 --rate 50 --loop
```
- Receivers (from repo root on PC2/PC3):
```
./pc2_receiver.sh 172.168.3.2 239.1.1.1 5004
./pc3_receiver.sh 172.168.3.3 239.1.1.1 5004
```

## Quick verification steps
- Ping gateways: PC1→172.168.2.34, PC2/PC3→172.168.3.1.
- Routers: `show ip int brief`, `show ip pim interface`, `show ip pim rp mapping`.
- IGMP joins: start a receiver, then `show ip igmp groups` on R1; `ip maddr show dev eno1` on PCs.
- Multicast tree: `show ip mroute 239.1.1.1` while sender/receiver run.
