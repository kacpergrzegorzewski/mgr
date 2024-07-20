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
            self.link_discovery_src_iface = self.data[Hasher.LENGTH:Hasher.LENGTH+IFACE_NAME_LENGTH].decode()
            self.link_discovery_dst_hash = self.data[Hasher.LENGTH+IFACE_NAME_LENGTH:2*Hasher.LENGTH+IFACE_NAME_LENGTH]
            self.link_discovery_dst_iface = self.data[2*Hasher.LENGTH+IFACE_NAME_LENGTH:2*Hasher.LENGTH+2*IFACE_NAME_LENGTH].decode()

    def extract_ldb_configuration(self):
        '''
        Function used to extract data from packets which contains ldb reconfiguration task
        :return: array contains hash of flow to add (bytes), name of outport (str)
        and time after which the flow should be removed from LDB (int)
        '''
        #  data schema: |#########################|##########|####################|
        #                        flow hash          outport          timeout
        # outport length is IFACE_NAME_LENGTH
        # timeout is in epoch format (variable length is EPOCH_TIME_LENGTH)
        pointer = 0
        flow_hash = self.data[pointer:pointer+Hasher.LENGTH]
        pointer += Hasher.LENGTH
        outport = self.data[pointer:pointer+IFACE_NAME_LENGTH].decode()
        pointer += IFACE_NAME_LENGTH
        timeout = int.from_bytes(self.data[pointer:pointer+EPOCH_TIME_LENGTH], byteorder=NETWORK_BYTEORDER)
        return [flow_hash, outport, timeout]

