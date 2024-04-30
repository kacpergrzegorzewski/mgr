ip link set up ens16
ip link set ens16 arp off
sysctl -w net.ipv6.conf.ens16.disable_ipv6=1
