import threading

from scapy.sendrecv import sniff

from ..Base.InternalPacket import InternalPacket
from ..Base.Env import *



def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class PolicyEngine:
    def __init__(self, iface):
        print("[INFO] Initializing Policy Engine")
        self.iface = iface
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
        if pkt.hash == POLICY_ENGINE_NEW_FLOW_HASH:
            hash_of_flow, src_device, src_iface, src_pkt = pkt.extract_policy_engine_new_flow_data()
            print("[INFO] Received new flow request")
            # TODO
