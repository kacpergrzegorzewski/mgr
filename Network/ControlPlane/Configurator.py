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
        pkt = InternalPacket(pkt)
        if pkt.hash == CONFIGURATOR_LINK_DISCOVERY_HASH:
            src_hash, src_iface, dst_hash, dst_iface = pkt.extract_configurator_link_discovery_data()
            print("[INFO] Received link discovery packet from " + str(src_hash) + " (" + str(src_iface) + ") to " +
                  str(dst_hash) + " (" + str(dst_iface) + ")")
            self.tdb.update_node(src_hash)
            self.tdb.update_node(dst_hash)
            self.tdb.update_edge(
                start=src_hash,
                end=dst_hash,
                src_iface=src_iface,
                dst_iface=dst_iface
            )


