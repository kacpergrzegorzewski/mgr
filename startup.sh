interfaces=( ens16 )

for interface in "${interfaces[@]}"
do
	ip link set up $interface
	ip link set $interface arp off
	sysctl -w net.ipv6.conf.$interface.disable_ipv6=1
done
#ip link set up ens16
#ip link set ens16 arp off
#sysctl -w net.ipv6.conf.ens16.disable_ipv6=1

