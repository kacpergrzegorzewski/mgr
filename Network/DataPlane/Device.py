import threading
from socket import PF_PACKET, SOCK_RAW, socket, gethostname
from scapy.compat import bytes_hex
from scapy.sendrecv import sniff
from scapy.packet import raw
from time import sleep
from .Enforcement import _Enforcement as Enforcement
from . import Hasher
from ..Base.InternalPacket import InternalPacket


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Device:
    BEACON_HASH = Hasher.hasher("".encode())
    BEACON_INTERVAL = 2
    BEACON_STATUS = True

    def __init__(self, device_id, configurator_hash, ldb, ext_ifaces=None, int_ifaces=None):
        self.ext_ifaces = ext_ifaces
        self.int_ifaces = int_ifaces
        self.device_id = device_id
        # Create enforcement with LDB located in DB folder and named same as device_id but converted to int
        self.enforcement = Enforcement(ldb=ldb)

        # Dict interface_name: last_send_packet_on_interface.
        # It turned out that scapy sniff() function also receives last send packets on interface.
        # The idea is to ignore last sent packet on interface in sniff function.
        # TODO find other solution
        self.lastPacket = {}

        # dict interface_name: socket
        self.sockets = {}

        # Default value for devices without external interfaces e.g. Core
        if ext_ifaces is None:
            self.ext_ifaces = []
        # Default value for devices without internal interfaces (for testing purposes only)
        if int_ifaces is None:
            self.int_ifaces = []

        # start sniffing on all external interfaces
        for ext_iface in self.ext_ifaces:
            self.lastPacket[ext_iface] = b''
            self.sockets.update({ext_iface: socket(PF_PACKET, SOCK_RAW)})
            self.sockets[ext_iface].bind((ext_iface, 0))
            self.sniff(prn=self.ext_iface_recv, iface=ext_iface)

        # start sniffing on all internal interfaces
        for int_iface in self.int_ifaces:
            self.lastPacket[int_iface] = b''
            self.sockets.update({int_iface: socket(PF_PACKET, SOCK_RAW)})
            self.sockets[int_iface].bind((int_iface, 0))
            self.sniff(prn=self.int_iface_recv, iface=int_iface)

        # start sending beacon every BEACON_INTERVAL
        self.beacon()

    def _send(self, iface, data: bytes):
        self.lastPacket[iface] = data
        self.sockets[iface].send(data)

    @threaded
    def sniff(self, prn, iface):
        """
        Sniff for packets on interface
        :param prn:  function which will be triggered for every packet
        :param iface: name of interface
        :return: None
        """
        sniff(prn=prn, iface=iface)

    def ext_iface_recv(self, pkt):
        """
        Function triggered for every packet received on external iface
        :param pkt: received packet
        """
        data = raw(pkt)
        print("\next packet:")
        print(pkt)

    def int_iface_recv(self, pkt):
        """
        Function triggered for every packet received on internal iface
        :param pkt: received packet
        """
        data = raw(pkt)
        if data not in self.lastPacket.values():
            pkt = InternalPacket(pkt)
            if pkt.hash == self.BEACON_HASH:
                print("\nReceived Beacon on: " + pkt.iface)
            else:
                print("\nReceived internal packet with hash: " + pkt.hash)

    @threaded
    def beacon(self):
        """
        Threaded function which sends beacon on all internal interfaces every BEACON_INTERVAL
        """
        if len(self.int_ifaces) > 0:
            # int_sockets = {}
            # Create socket for each internal port
            # Add every entry to dict {<port_name>: <socket>}
            # for port in self.int_ports:
            #     int_sockets.update({port: socket(PF_PACKET, SOCK_RAW)})
            #     int_sockets[port].bind((port, 0))
            while self.BEACON_STATUS:
                # send beacon on all internal interfaces
                for iface in self.int_ifaces:
                    print("\nsending beacon on interface " + str(iface))
                    data = self.BEACON_HASH + self.device_id + iface.encode()
                    self._send(iface, data)
                # wait BEACON_INTERVAL before sending next beacon
                sleep(self.BEACON_INTERVAL)

