import threading
import time

from scapy.sendrecv import sniff
from socket import socket, PF_PACKET, SOCK_RAW

from ..Base.InternalPacket import InternalPacket
from ..Base.Env import *
from ..Base.ExternalPacket import ExternalPacket
from ..DataPlane import Hasher


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


def count_agent_hash(*args: bytes):
    to_hash = b''
    for arg in args:
        to_hash += arg
    agent_hash = Hasher.hash(to_hash)
    return agent_hash


class PolicyEngine:
    def __init__(self, iface, allowed_flows=None, flow_timeout=10):
        print("[INFO] Initializing Policy Engine")
        self.iface = iface
        if allowed_flows is None:
            self.allowed_flows = []
        elif type(allowed_flows) == list:
            self.allowed_flows = [Hasher.hash(allowed_flow.encode()) for allowed_flow in allowed_flows]
        else:
            print("[ERROR] Allowed flows are in an invalid format!")
        self.flow_timeout = flow_timeout

        self.socket = socket(PF_PACKET, SOCK_RAW)
        self.socket.bind((iface, 0))
        self.sniff(self.recv, self.iface)

    def send(self, hash, data):
        self.socket.send(hash + data)

    @threaded
    def sniff(self, prn, iface):
        """
        Sniff for packets on interface
        :param prn:  function which will be triggered for every packet
        :param iface: name of interface
        :return: None
        """

        sniff(prn=prn, iface=iface)

    def recv(self, pkt):
        pkt = InternalPacket(pkt)
        if pkt.hash == POLICY_ENGINE_NEW_FLOW_HASH:
            flow, src_device, src_iface, src_pkt = pkt.extract_policy_engine_new_flow_data()
            src_pkt = ExternalPacket(src_pkt)


            # Count agent hash (MAC address + IP address)
            src_agent = count_agent_hash(src_pkt.mac_src.encode(), src_pkt.ip_src.encode())
            dst_agent = count_agent_hash(src_pkt.mac_dst.encode(), src_pkt.ip_dst.encode())
            print("[INFO] Received new flow (" + str(flow) + ") request. "
                  "Source agent + " + str(src_agent) +
                  " destination agent: " + str(dst_agent) +
                  " values: " + str(src_pkt.to_hash))

            # Update agent in TDB
            self.update_configurator_agent(src_agent, src_device, src_iface)

            # Allow only flows from allowed flows list
            if flow in self.allowed_flows:
                self.add_configurator_flow(flow, src_agent, dst_agent)
                print("[INFO] Allow flow " + str(flow))
            # Drop packet
            else:
                self.add_configurator_flow(flow, src_agent, src_agent)
                print("[INFO] Deny flow " + str(flow))

    @threaded
    def update_configurator_agent(self, agent_hash, edge_hash, edge_iface: str):
        _hash = CONFIGURATOR_UPDATE_AGENT_HASH
        _data = agent_hash + edge_hash + edge_iface.encode()
        self.send(_hash, _data)

    @threaded
    def add_configurator_flow(self, flow, src_agent, dst_agent):
        _hash = CONFIGURATOR_ADD_FLOW_HASH
        timeout = int(time.time() + self.flow_timeout).to_bytes(length=EPOCH_TIME_LENGTH, byteorder=NETWORK_BYTEORDER)
        _data = flow + src_agent + dst_agent + timeout
        self.send(_hash, _data)
