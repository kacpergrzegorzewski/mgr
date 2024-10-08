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
    PRINT_STATISTICS = True
    PRINT_STATISTICS_INTERVAL = 10

    def __init__(self, iface, allowed_flows=None, flow_timeout=10):
        print(time.ctime() + " [INFO] Initializing Policy Engine")
        self.iface = iface
        if allowed_flows is None:
            self.allowed_flows = []
        elif type(allowed_flows) == list:
            self.allowed_flows = [Hasher.hash(allowed_flow.encode()) for allowed_flow in allowed_flows]
        else:
            print(time.ctime() + " [ERROR] Allowed flows are in an invalid format!")
        self.flow_timeout = flow_timeout
        self.sum_of_checks_time = 0
        self.number_of_checks = 0

        self.socket = socket(PF_PACKET, SOCK_RAW)
        self.socket.bind((iface, 0))
        self.sniff(self.recv, self.iface)
        self.print_statistics()

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

    def check_flow(self, flow):
        time_before = time.time_ns()
        if flow in self.allowed_flows:
            allowed = True
        else:
            allowed = False
        time_after = time.time_ns()
        self.sum_of_checks_time += (time_after - time_before) / 1_000_000  # ms
        self.number_of_checks += 1

        return allowed

    def add_allowed_flow(self, flow):
        if flow not in self.allowed_flows:
            self.allowed_flows.append(flow)

    def recv(self, pkt):
        pkt = InternalPacket(pkt)
        if pkt.hash == POLICY_ENGINE_NEW_FLOW_HASH:
            flow, src_device, src_iface, src_pkt = pkt.extract_policy_engine_new_flow_data()
            src_pkt = ExternalPacket(src_pkt)


            # Count agent hash (MAC address + IP address)
            src_agent = count_agent_hash(src_pkt.mac_src.encode(), src_pkt.ip_src.encode())
            dst_agent = count_agent_hash(src_pkt.mac_dst.encode(), src_pkt.ip_dst.encode())
            print(time.ctime() + " [INFO] Received new flow (" + str(flow) + ") from " + str(src_device) +
                  " Source agent + " + str(src_agent) +
                  " destination agent: " + str(dst_agent) +
                  " values: " + str(src_pkt.to_hash))

            # Update agent in TDB
            self.update_configurator_agent(src_agent, src_device, src_iface)

            # Allow only flows from allowed flows list

            if self.check_flow(flow):
                self.add_configurator_flow(flow, src_agent, dst_agent)
                print(time.ctime() + " [INFO] Allow flow " + str(flow))
                if src_pkt.reverse_flow_required:
                    reverse_flow = Hasher.hash(src_pkt.to_hash_reverse)
                    self.add_configurator_flow(reverse_flow, dst_agent, src_agent)
                    print(time.ctime() + " [INFO] Allow reverse flow " + str(reverse_flow) + " Values: " + str(src_pkt.to_hash_reverse))
                    self.add_allowed_flow(reverse_flow)
            # Drop packet
            else:
                self.add_configurator_flow(flow, src_agent, src_agent)
                print(time.ctime() + " [INFO] Deny flow " + str(flow))

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

    @threaded
    def print_statistics(self):
        while self.PRINT_STATISTICS:
            print("============ statistics ============")
            print(time.ctime())
            if self.number_of_checks != 0:
                print("Number of checks: " + str(self.number_of_checks))
                print("Average check time: " + str(self.sum_of_checks_time/self.number_of_checks) + "ms")
            print("====================================")
            time.sleep(self.PRINT_STATISTICS_INTERVAL)
