import threading
import time
from socket import socket, PF_PACKET, SOCK_RAW

from scapy.sendrecv import sniff
import networkx as nx

from ..Base.Env import *
from ..Base.InternalPacket import InternalPacket
from .TDB import TDB


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Configurator:
    TDB_PRINT = True
    TDB_PRINT_INTERVAL = 10
    CREATE_INTERNAL_PATHS = True

    def __init__(self, iface, node_lifetime, link_lifetime, path_lifetime, create_paths_interval):
        print("[INFO] Initializing Configurator")
        self.iface = iface
        self.tdb = TDB()
        self.node_lifetime = int(node_lifetime)
        self.link_lifetime = int(link_lifetime)
        self.path_lifetime = int(path_lifetime)
        self.create_paths_interval = int(create_paths_interval)

        self.sniff(self.recv, self.iface)
        self.create_internal_paths()
        self.socket = socket(PF_PACKET, SOCK_RAW)
        self.socket.bind((iface, 0))

    def send(self, hash, data):
        self.socket.send(hash + data)

    def send_ldb_entry(self, device, flow, outport, timeout):
        _hash = device
        _data = flow + outport + timeout
        self.send(_hash, _data)

    @threaded
    def sniff(self, prn, iface):
        """
        Sniff for packets on interface
        :param prn:  function which will be triggered for every packet
        :param iface: name of interface
        :return: None
        """

        sniff(prn=prn, iface=iface)

    @threaded
    def recv(self, pkt):
        pkt = InternalPacket(pkt)
        if pkt.hash == CONFIGURATOR_ADD_LINK_HASH:
            src_hash, src_iface, dst_hash, dst_iface = pkt.extract_configurator_add_link_data()
            # print("[INFO] Received link discovery packet from " + str(src_hash) + " (" + str(src_iface) + ") to " +
            #      str(dst_hash) + " (" + str(dst_iface) + ")")
            self.tdb.update_node(src_hash)
            self.tdb.update_node(dst_hash)
            self.tdb.update_link(
                start=src_hash,
                end=dst_hash,
                src_iface=src_iface,
                dst_iface=dst_iface,
                link_lifetime=self.link_lifetime
            )

        elif pkt.hash == CONFIGURATOR_ADD_FLOW_HASH:
            flow, src_device, dst_device, timeout = pkt.extract_configurator_add_flow_data()
            print("[INFO] Received add flow: " + str(flow) + " src: " + str(src_device) + " dst: " + str(dst_device) + " endtime " + str(timeout))
            path = self.tdb.get_path(source=src_device, destination=dst_device)
            current_wait = MIN_TDB_WAIT
            while len(path) == 0:
                path = self.tdb.get_path(source=src_device, destination=dst_device)
                current_wait *= 2
                if current_wait > MAX_TDB_WAIT:
                    print("[WARNING] Path from " + str(src_device) + " to " + str(dst_device) + " not found.")
                    return
                time.sleep(current_wait)
            for i in range(len(path)-1):
                src_iface = self.tdb.get_link_source_iface(source=path[i], destination=path[i+1])
                # Skip if the source is an agent. The configurator cannot configure the agent, at least for now...
                if src_iface != IFACE_NAME_AGENT:
                    node = path[i]
                    outport = src_iface.encode()
                    self.send_ldb_entry(device=node, flow=flow, outport=outport, timeout=timeout.to_bytes(length=EPOCH_TIME_LENGTH, byteorder=NETWORK_BYTEORDER))
                    # increment timeout for every device
                    timeout += 1
                    print("[INFO] Sent to " + str(node) + " flow " + str(flow) + " via " + str(src_iface))

            # Add drop to every adjacent node if source and destination are the same
            if src_device == dst_device:
                for node in self.tdb.get_neighbors(src_device):
                    self.send_ldb_entry(device=node, flow=flow, outport=IFACE_NAME_DROP.encode(), timeout=timeout.to_bytes(length=EPOCH_TIME_LENGTH, byteorder=NETWORK_BYTEORDER))
                    print("[INFO] Sent drop " + str(flow) + " to node " + str(node))

        elif pkt.hash == CONFIGURATOR_UPDATE_AGENT_HASH:
            agent_hash, device_hash, device_iface = pkt.extract_configurator_update_agent_data()
            print("[INFO] Received update agent: " + str(agent_hash))
            self.tdb.update_node(agent_hash)
            self.tdb.update_node(device_hash)
            # agent -> device
            self.tdb.update_link(
                start=agent_hash,
                end=device_hash,
                src_iface=IFACE_NAME_AGENT,
                dst_iface=device_iface,
                link_lifetime=600
            )
            # device -> agent
            self.tdb.update_link(
                start=device_hash,
                end=agent_hash,
                src_iface=device_iface,
                dst_iface=IFACE_NAME_AGENT,
                link_lifetime=600
            )

    @threaded
    def create_internal_paths(self):
        while self.CREATE_INTERNAL_PATHS:
            paths = self.tdb.get_all_paths()
            for source, destinations in paths.items():
                for destination, path in destinations.items():
                    if len(path) > 1:  # not path to self
                        via = self.tdb.get_link_source_iface(path[0], path[1])
                        if via is not None:
                            if via != IFACE_NAME_AGENT:
                                endtime = ((int(time.time()) + self.path_lifetime).
                                           to_bytes(length=EPOCH_TIME_LENGTH, byteorder=NETWORK_BYTEORDER))
                                self.send_ldb_entry(device=source, flow=destination, outport=via.encode(), timeout=endtime)
                                # print("[INFO] sent to " + str(source) + " node " + str(destination) + " via " + str(via))
            time.sleep(self.create_paths_interval)
