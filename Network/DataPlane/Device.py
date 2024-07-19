import threading
import time
from socket import PF_PACKET, SOCK_RAW, socket, gethostname
from scapy.compat import bytes_hex
from scapy.sendrecv import sniff
from scapy import packet
from time import sleep
from .Enforcement import _Enforcement as Enforcement
from . import Hasher
from ..Base.InternalPacket import InternalPacket
from ..Base.Env import *
from collections import deque


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Device:
    BEACON_STATUS = True

    def __init__(self, device_hash, ldb, ext_ifaces=None, int_ifaces=None, max_last_packet_queue_size=10):
        self.ext_ifaces = ext_ifaces
        self.int_ifaces = int_ifaces
        self.device_hash = device_hash
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
            self.lastPacket[ext_iface] = deque([], maxlen=max_last_packet_queue_size)
            self.sockets.update({ext_iface: socket(PF_PACKET, SOCK_RAW)})
            self.sockets[ext_iface].bind((ext_iface, 0))
            self.sniff(prn=self.ext_iface_recv, iface=ext_iface)

        # start sniffing on all internal interfaces
        for int_iface in self.int_ifaces:
            self.lastPacket[int_iface] = deque([], maxlen=max_last_packet_queue_size)
            self.sockets.update({int_iface: socket(PF_PACKET, SOCK_RAW)})
            self.sockets[int_iface].bind((int_iface, 0))
            self.sniff(prn=self.int_iface_recv, iface=int_iface)

        # start sending beacon every BEACON_INTERVAL
        self.beacon()

    def _send(self, iface, pkt: bytes):
        self.lastPacket[iface].append(pkt)
        self.sockets[iface].send(pkt)

    def _send_wait(self, hash, data):
        current_wait_time = MIN_PKT_WAIT
        outport = self.enforcement.enforce(hash)
        # outport not in LDB
        if outport is None:
            # find policy engine path
            policy_engine_outport = self.enforcement.enforce(POLICY_ENGINE_HASH)
            if hash == CONFIGURATOR_LINK_DISCOVERY_HASH:
                print("[ERROR] Configurator outport not found in LDB!")
            if policy_engine_outport is None:
                print("[ERROR] Policy engine outport not found in LDB!")
            else:
                # send request to policy engine
                self._send(policy_engine_outport, POLICY_ENGINE_HASH + hash + data)
                # wait for LDB reconfiguration
                while current_wait_time < MAX_PKT_WAIT:
                    outport = self.enforcement.enforce(hash)
                    if outport is not None:
                        print("Sending data to" + str(hash) + " via " + str(outport))
                        self._send(outport, hash + data)
                        break
                    time.sleep(current_wait_time)
                    current_wait_time *= 2
        # outport in LDB
        else:
            print("Sending data to " + str(hash) + " via " + str(outport))
            self._send(outport, hash + data)

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
        raw = packet.raw(pkt)
        print("\next packet:")
        print(pkt)

    def int_iface_recv(self, pkt):
        """
        Function triggered for every packet received on internal iface
        :param pkt: received packet
        """
        pkt = InternalPacket(pkt)
        if self.lastPacket[pkt.iface].count(pkt.raw_pkt) == 0:
            if pkt.hash == BEACON_HASH:
                print("\nReceived Beacon from " + str(pkt.beacon_device_hash) +
                      ". Local interface: " + str(pkt.iface) +
                      ". Remote interface: " + str(pkt.beacon_iface))
                data = self.device_hash + pkt.iface.encode() + pkt.beacon_device_hash + pkt.beacon_iface
                self._send_wait(CONFIGURATOR_LINK_DISCOVERY_HASH, data)
            else:
                print("\nReceived internal packet with hash: " + str(pkt.hash))
                self._send_wait(pkt.hash, pkt.data)

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
                    data = BEACON_HASH + self.device_hash + iface.encode()
                    self._send(iface, data)
                # wait BEACON_INTERVAL before sending next beacon
                sleep(BEACON_INTERVAL)

