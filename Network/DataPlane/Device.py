import threading
import time
from socket import PF_PACKET, SOCK_RAW, socket, gethostname

import scapy.packet
from scapy.compat import bytes_hex
from scapy.sendrecv import sniff
from scapy import packet
from scapy.layers import inet
from time import sleep
from .Enforcement import _Enforcement as Enforcement
from . import Hasher
from ..Base.InternalPacket import InternalPacket
from ..Base.ExternalPacket import ExternalPacket
from ..Base.Env import *
from collections import deque


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Device:
    BEACON_STATUS = True
    PRINT_STATISTICS = True
    PRINT_STATISTICS_INTERVAL = 10

    def __init__(self, device_hash, ldb, ext_ifaces=None, int_ifaces=None, max_last_packet_queue_size=10):
        self.ext_ifaces = ext_ifaces
        self.int_ifaces = int_ifaces
        self.device_hash = device_hash
        self.ldb = ldb

        self.number_of_pkt_wait = 0
        self.time_of_pkt_wait = 0

        # Create enforcement with LDB located in DB folder and named same as device_id but converted to int
        self.enforcement = Enforcement(ldb=self.ldb)

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

        # Start printing statistics
        self.print_statistics()

    def _send(self, iface, pkt: bytes):
        if iface != IFACE_NAME_DROP:
            self.lastPacket[iface].append(pkt)
            self.sockets[iface].send(pkt)
        # Drop packet
        else:
            return

    @threaded
    def _send_wait(self, hash, data, src_iface=""):
        current_wait_time = MIN_PKT_WAIT
        outport = self.enforcement.enforce(hash)
        # outport not in LDB
        if outport is None:
            # find policy engine path
            policy_engine_outport = self.enforcement.enforce(POLICY_ENGINE_NEW_FLOW_HASH)
            if hash == CONFIGURATOR_LINK_DISCOVERY_HASH:
                print("[ERROR] Configurator outport not found in LDB!")
                return
            if policy_engine_outport is None:
                print("[ERROR] Policy engine outport not found in LDB!")
                return
            else:
                time_before = time.time_ns()
                if src_iface in self.ext_ifaces:
                    # send request to policy engine
                    self._send(policy_engine_outport,
                               POLICY_ENGINE_NEW_FLOW_HASH + hash + self.device_hash + src_iface.encode() + data)
                # wait for LDB reconfiguration
                while current_wait_time < MAX_PKT_WAIT:
                    outport = self.enforcement.enforce(hash)
                    if outport is not None:
                        time_after = time.time_ns()
                        self.time_of_pkt_wait += (time_after-time_before) / 1_000_000  # time in ms
                        self.number_of_pkt_wait += 1
                        print("[INFO] Sending data to" + str(hash) + " via " + str(outport))
                        if outport in self.ext_ifaces:
                            self._send(outport, data)
                        else:
                            self._send(outport, hash + data)
                        return
                    time.sleep(current_wait_time)
                    current_wait_time += MIN_PKT_WAIT
                print("[WARNING] Flow " + str(hash) + " dropped due to missing entry in LDB.")
        # outport in LDB
        else:
            print("[INFO] Sending data to " + str(hash) + " via " + str(outport))
            if outport in self.ext_ifaces:
                self._send(outport, data)
            else:
                self._send(outport, hash + data)
            return

    @threaded
    def sniff(self, prn, iface):
        """
        :param prn:  function which will be triggered for every packet
        :param iface: name of interface
        :return: None
        """
        sniff(prn=prn, iface=iface, store=0)

    @threaded
    def ext_iface_recv(self, pkt):
        """
        Function triggered for every packet received on external iface
        :param pkt: received packet
        """
        pkt = ExternalPacket(pkt)
        # check if packet is not in last sent packets (sniff also captures sent packets)
        if self.lastPacket[pkt.iface].count(pkt.raw_pkt) == 0:
            print("[INFO] Received external packet with values: " + str(pkt.to_hash))
            flow_hash = Hasher.hash(pkt.to_hash)
            self._send_wait(flow_hash, pkt.raw_pkt, src_iface=pkt.iface)

    @threaded
    def int_iface_recv(self, pkt):
        """
        Function triggered for every packet received on internal iface
        :param pkt: received packet
        """
        pkt = InternalPacket(pkt)
        # check if packet is not in last sent packets (sniff also captures sent packets)
        if self.lastPacket[pkt.iface].count(pkt.raw_pkt) == 0:
            if pkt.hash == BEACON_HASH:
                beacon_hash, beacon_iface = pkt.extract_beacon_data()
                print("[INFO] Received Beacon from " + str(beacon_hash) +
                     ". Local interface: " + str(pkt.iface) +
                     ". Remote interface: " + str(beacon_iface))
                # send link discovery to configurator
                data = self.device_hash + pkt.iface.encode() + beacon_hash + beacon_iface.encode()
                self._send_wait(CONFIGURATOR_LINK_DISCOVERY_HASH, data, src_iface=pkt.iface)
            elif pkt.hash == self.device_hash:
                flow, outport, timeout = pkt.extract_ldb_add_entry_data()
                print("[INFO] Received new LDB entry. Flow " + str(flow) + " via " + str(outport))
                self.ldb.add_flow(*pkt.extract_ldb_add_entry_data())
            else:
                print("[INFO] Received internal packet with hash: " + str(pkt.hash))
                self._send_wait(pkt.hash, pkt.data, src_iface=pkt.iface)

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
                    print("[INFO] sending beacon on interface " + str(iface))
                    data = BEACON_HASH + self.device_hash + iface.encode()
                    self._send(iface, data)
                # wait BEACON_INTERVAL before sending next beacon
                sleep(BEACON_INTERVAL)

    @threaded
    def print_statistics(self):
        while self.PRINT_STATISTICS:
            print("============ statistics ============")
            if self.number_of_pkt_wait != 0:
                print("Number of packet wait: " + str(self.number_of_pkt_wait))
                print("Average packet wait: " + str(self.time_of_pkt_wait/self.number_of_pkt_wait) + "ms")
            print("====================================")
            time.sleep(self.PRINT_STATISTICS_INTERVAL)
