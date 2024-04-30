from scapy.all import sniff,bytes_hex

def mod(pkt):
	print((bytes_hex(pkt)).decode("utf-8"))

def edge(pkt):
	print(pkt)
	print(pkt)

sniff(prn=edge, iface="ens16")
