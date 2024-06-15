import threading

from scapy.sendrecv import sniff
from scapy.packet import raw


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Configurator:
    # md5("configurator".encode()).digest()
    CONFIGURATOR_HASH = b'd\xa7\x88\xf2\xb9\xa2\x1eG\xec\xa4s\xaeye0Q'

    def __init__(self, iface):
        self.iface = iface

        print("Initializing Configurator")

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
        data = raw(pkt)
