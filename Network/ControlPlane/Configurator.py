import threading
import time

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

    def __init__(self, iface):
        print("[INFO] Initializing Configurator")
        self.iface = iface
        self.tdb = TDB()
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
            print("Received packet: " + str(internal_packet.raw_pkt))
            self.tdb.add_node(internal_packet.link_discovery_src_hash)
            self.tdb.add_node(internal_packet.link_discovery_dst_hash)
            self.tdb.add_edge(
                start=internal_packet.link_discovery_src_hash,
                end=internal_packet.link_discovery_dst_hash,
                src_iface=internal_packet.link_discovery_src_iface,
                dst_iface=internal_packet.link_discovery_dst_iface
            )


