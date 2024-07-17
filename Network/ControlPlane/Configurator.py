import threading
import time

from scapy.sendrecv import sniff
import networkx as nx

from ..Base.Env import *
from ..Base.InternalPacket import InternalPacket


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Configurator:
    TDB_PRINT = True
    TDB_PRINT_INTERVAL = 10

    def __init__(self, iface):
        print("[INFO] Initializing Configurator")
        self.iface = iface
        self.tdb = nx.DiGraph()
        self.print_current_state()
        self.sniff(self.recv, self.iface)

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
        internal_packet = InternalPacket(pkt)
        if internal_packet.hash == CONFIGURATOR_LINK_DISCOVERY_HASH:
            self.add_node(internal_packet.link_discovery_src_hash)
            self.add_node(internal_packet.link_discovery_dst_hash)
            self.add_edge(
                start=internal_packet.link_discovery_src_hash,
                end=internal_packet.link_discovery_dst_hash,
                src_iface=internal_packet.link_discovery_src_iface,
                dst_iface=internal_packet.link_discovery_dst_iface
            )

    def add_node(self, node):
        if node not in self.tdb.nodes:
            self.tdb.add_node(node)
            print("[INFO] Added node " + node + " to TDB.")
        else:
            print("[INFO] Node " + node + " exists.")

    def add_edge(self, start, end, src_iface, dst_iface):
        if start and end in self.tdb.nodes:
            self.tdb.add_edge(start, end, src_iface=src_iface, dst_iface=dst_iface)
        else:
            print("[WARNING] Node does not exist. Link " + str(start) + " -> " + str(end) + " not created in TDB.")

    @threaded
    def print_current_state(self):
        while self.TDB_PRINT:
            print("===============================================================")
            print("Current TDB state:")
            for edge in self.tdb.edges:
                print(str(edge[0]) + " -> " + str(edge[1]))
            print("===============================================================")
            time.sleep(self.TDB_PRINT_INTERVAL)

