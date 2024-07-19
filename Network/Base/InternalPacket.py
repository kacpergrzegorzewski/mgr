from scapy.layers.l2 import Ether
from scapy.packet import raw
from Network.DataPlane import Hasher
from .Env import *


class InternalPacket:
    def __init__(self, pkt: Ether):
        self.iface = pkt.sniffed_on
        self.raw_pkt = raw(pkt)
        self.hash = self.raw_pkt[0:Hasher.LENGTH]
        self.data = self.raw_pkt[Hasher.LENGTH:]
        if self.hash == BEACON_HASH:
            self.beacon_device_hash = self.raw_pkt[Hasher.LENGTH:2 * Hasher.LENGTH]
            self.beacon_iface = self.raw_pkt[2*Hasher.LENGTH:2*Hasher.LENGTH+IFACE_NAME_LENGTH]
        elif self.hash == CONFIGURATOR_LINK_DISCOVERY_HASH:
            #  data schema: |#########################|##########|####################|##########|
            #                         src_hash          src_iface       dst_hash        dst_iface
            self.link_discovery_src_hash = self.data[0:Hasher.LENGTH]
            self.link_discovery_src_iface = self.data[Hasher.LENGTH:Hasher.LENGTH+IFACE_NAME_LENGTH]
            self.link_discovery_dst_hash = self.data[Hasher.LENGTH+IFACE_NAME_LENGTH:2*Hasher.LENGTH+IFACE_NAME_LENGTH]
            self.link_discovery_dst_iface = self.data[2*Hasher.LENGTH+IFACE_NAME_LENGTH:2*Hasher.LENGTH+2*IFACE_NAME_LENGTH]
        else:
            self.beacon = False

