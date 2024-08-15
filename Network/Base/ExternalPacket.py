from scapy.layers.l2 import Ether
from scapy.packet import raw
import scapy.layers.all

from ..Base.Env import *


class ExternalPacket:
    def __init__(self, pkt):
        if type(pkt) == bytes:
            pkt = Ether(pkt)
        self.pkt = pkt
        self.iface = pkt.sniffed_on
        self.raw_pkt = raw(pkt)
        self.layers = self.get_layers()

        if 'Ethernet' in self.layers:
            self.mac_src = self.pkt["Ether"].src
            self.mac_dst = self.pkt["Ether"].dst
        else:
            self.mac_src = ""
            self.mac_dst = ""

        if "IP" in self.layers:
            self.ip_src = self.pkt["IP"].src
            self.ip_dst = self.pkt["IP"].dst
        else:
            self.ip_src = ""
            self.ip_dst = ""

        if "TCP" in self.layers:
            self.src_port = self.pkt["TCP"].sport
            self.dst_port = self.pkt["TCP"].dport
            self.reverse_flow_required = True
        elif "UDP" in self.layers:
            self.src_port = self.pkt["UDP"].sport
            self.dst_port = self.pkt["UDP"].dport
            self.reverse_flow_required = False
        else:
            self.src_port = None
            self.dst_port = None
            self.reverse_flow_required = False

        self.to_hash = b''
        for layer_name in self.layers:
            self.to_hash += layer_name.encode()
        self.to_hash += self.mac_src.encode()
        self.to_hash += self.mac_dst.encode()
        self.to_hash += self.ip_src.encode()
        self.to_hash += self.ip_dst.encode()
        if self.dst_port is not None:
            # port number is 16 bits = 2 bytes
            self.to_hash += self.dst_port.to_bytes(length=2, byteorder=NETWORK_BYTEORDER)

        self.to_hash_reverse = b''
        for layer_name in self.layers:
            self.to_hash_reverse += layer_name.encode()
        self.to_hash_reverse += self.mac_dst.encode()
        self.to_hash_reverse += self.mac_src.encode()
        self.to_hash_reverse += self.ip_dst.encode()
        self.to_hash_reverse += self.ip_src.encode()
        if self.src_port is not None:
            # port number is 16 bits = 2 bytes
            self.to_hash += self.src_port.to_bytes(length=2, byteorder=NETWORK_BYTEORDER)


    def get_layers(self):
        counter = 0
        layers = []
        while True:
            layer = self.pkt.getlayer(counter)
            if layer is None or layer.name == "Padding":
                break
            layers.append(layer.name)
            counter += 1
        return layers
