from scapy.layers.l2 import Ether
from scapy.packet import raw
from Network.DataPlane import Hasher
from .Env import *


class InternalPacket:
    def __init__(self, pkt: Ether):
        self.iface = pkt.sniffed_on.encode()
        self.raw_pkt = raw(pkt)
        self.hash = self.raw_pkt[0:Hasher.LENGTH]
        if self.hash == BEACON_HASH:
            self.beacon = True
            self.beacon_device_hash = self.raw_pkt[Hasher.LENGTH:2 * Hasher.LENGTH]
            self.beacon_iface = self.raw_pkt[2*Hasher.LENGTH:2*Hasher.LENGTH+IFACE_NAME_LENGTH]
        else:
            self.beacon = False

