from scapy.layers.l2 import Ether
from scapy.packet import raw
from Network.DataPlane import Hasher


class InternalPacket:
    def __init__(self, pkt: Ether):
        self.raw_pkt = raw(pkt)
        self.hash = self.raw_pkt[0:Hasher.LENGTH]
