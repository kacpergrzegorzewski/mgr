import threading
from socket import PF_PACKET, SOCK_RAW, socket, gethostname
from scapy.compat import bytes_hex
from scapy.sendrecv import sniff
from time import sleep
from Enforcement import _Enforcement as Enforcement
import Hasher


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


def _send(s, data: bytes):
    s.send(data)


class Device:

    BEACON_HASH = Hasher.hasher("".encode())
    BEACON_INTERVAL = 15
    BEACON_STATUS = True

    def __init__(self, device_id, ext_ports=None, int_ports=None):
        self.ext_ports = ext_ports
        self.int_ports = int_ports
        self.device_id = device_id
        # Create enforcement with LDB located in DB folder and named same as device_id but converted to int
        self.enforcement = Enforcement(ldb="../../DB/" + str(int.from_bytes(self.device_id)) + ".db")

        # Default value for devices without external ports e.g. Core
        if ext_ports is None:
            self.ext_ports = []
        # Default value for devices without internal ports (for testing purposes only)
        if int_ports is None:
            self.int_ports = []

        # start sniffing on all external ports
        for ext_port in self.ext_ports:
            self.sniff(prn=self.ext_port_recv, iface=ext_port)

        # start sniffing on all internal ports
        for int_port in self.int_ports:
            self.sniff(prn=self.int_port_recv, iface=int_port)

        # start sending beacon every BEACON_INTERVAL
        self.beacon()

    @threaded
    def sniff(self, prn, iface):
        """
        Sniff for packets on interface
        :param prn:  function which will be triggered for every packet
        :param iface: name of interface
        :return: None
        """
        sniff(prn=prn, iface=iface)

    def ext_port_recv(self, pkt):
        """
        Function triggered for every packet received on external port
        :param pkt: received packet
        """
        data = bytes_hex(pkt)
        print("\next packet:")
        print(pkt)

    def int_port_recv(self, pkt):
        """
        Function triggered for every packet received on internal port
        :param pkt: received packet
        """
        data = bytes_hex(pkt)
        hash = data[0:Hasher.LENGTH]
        print("\nint packet:")
        print("hash" + str(hash))
        print(bytes_hex(pkt))

    @threaded
    def beacon(self):
        """
        Threaded function which sends beacon on all internal interfaces every BEACON_INTERVAL
        """
        if len(self.int_ports) > 0:
            int_sockets = {}
            # Create socket for each internal port
            # Add every entry to dict {<port_name>: <socket>}
            for port in self.int_ports:
                int_sockets.update({port: socket(PF_PACKET, SOCK_RAW)})
                int_sockets[port].bind((port, 0))
            while self.BEACON_STATUS:
                # send beacon on all internal sockets (created few lines above)
                for port, s in int_sockets.items():
                    print("sending beacon on port " + str(port))
                    print(type(port))
                    data = self.BEACON_HASH + self.device_id + port.encode()
                    _send(s, data)
                # wait BEACON_INTERVAL before sending next beacon
                sleep(self.BEACON_INTERVAL)


if __name__ == '__main__':
    device_id = Hasher.hasher(gethostname().encode())
    print(device_id)
    device = Device(device_id=device_id, int_ports=["ens16"])
