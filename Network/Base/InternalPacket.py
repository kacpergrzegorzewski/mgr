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

    def extract_beacon_data(self):
        #  data schema: |#########################|###########|
        #                         src_hash          src_iface
        pointer = 0
        beacon_device_hash = self.data[0:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        beacon_iface = self.data[pointer:pointer + IFACE_NAME_LENGTH].decode()
        return [beacon_device_hash, beacon_iface]

    def extract_configurator_add_link_data(self):
        #  data schema: |#########################|###########|####################|###########|
        #                         src_hash          src_iface        dst_hash        dst_iface
        pointer = 0
        link_discovery_src_hash = self.data[pointer:pointer+Hasher.LENGTH]
        pointer += Hasher.LENGTH
        link_discovery_src_iface = self.data[pointer:pointer + IFACE_NAME_LENGTH].decode()
        pointer += IFACE_NAME_LENGTH
        link_discovery_dst_hash = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        link_discovery_dst_iface = self.data[pointer:pointer + IFACE_NAME_LENGTH].decode()
        return [link_discovery_src_hash, link_discovery_src_iface, link_discovery_dst_hash, link_discovery_dst_iface]

    def extract_ldb_add_entry_data(self):
        '''
        Function used to extract data from packets which contains ldb reconfiguration task
        :return: array contains hash of flow to add (bytes), name of outport (str)
        and time after which the flow should be removed from LDB (int)
        '''
        #  data schema: |#########################|#########|####################|
        #                      hash of flow         outport         timeout
        # outport length is IFACE_NAME_LENGTH
        # timeout is in epoch format (variable length is EPOCH_TIME_LENGTH)
        pointer = 0
        flow_hash = self.data[pointer:pointer+Hasher.LENGTH]
        pointer += Hasher.LENGTH
        outport = self.data[pointer:pointer+IFACE_NAME_LENGTH].decode()
        pointer += IFACE_NAME_LENGTH
        timeout = int.from_bytes(self.data[pointer:pointer+EPOCH_TIME_LENGTH], byteorder=NETWORK_BYTEORDER)
        return [flow_hash, outport, timeout]

    def extract_policy_engine_new_flow_data(self):
        #  data schema: |#########################|#########################|#########|#############################...
        #                      hash of flow             src device hash      src iface    copy of original packet
        pointer = 0
        hash_of_flow = self.data[pointer:pointer+Hasher.LENGTH]
        pointer += Hasher.LENGTH
        src_device = self.data[pointer:pointer+Hasher.LENGTH]
        pointer += Hasher.LENGTH
        src_iface = self.data[pointer:pointer+IFACE_NAME_LENGTH].decode()
        pointer += IFACE_NAME_LENGTH
        src_pkt = self.data[pointer:]

        return [hash_of_flow, src_device, src_iface, src_pkt]

    def extract_configurator_update_agent_data(self):
        #  data schema: |#########################|#########################|#########|
        #                        agent hash           device (edge) hash       iface
        pointer = 0
        agent_hash = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        device_hash = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        device_iface = self.data[pointer:pointer + IFACE_NAME_LENGTH].decode()

        return [agent_hash, device_hash, device_iface]

    def extract_configurator_add_flow_data(self):
        #  data schema: |#########################|#########################|#########################|####################|
        #                      hash of flow                src agent                 dst agent                timeout
        pointer = 0
        flow = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        src_device = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        dst_device = self.data[pointer:pointer + Hasher.LENGTH]
        pointer += Hasher.LENGTH
        timeout = self.data[pointer:pointer+EPOCH_TIME_LENGTH]

        return [flow, src_device, dst_device, timeout]
