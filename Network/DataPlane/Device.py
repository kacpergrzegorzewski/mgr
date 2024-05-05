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


def _send(s, data):
    s.send(hex(data))


class Device:
    BEACON_HASH = hash("")
    BEACON_INTERVAL = 15
    BEACON_STATUS = True

    def __init__(self, device_id: int, ext_ports=None, int_ports=None):
        self.ext_ports = ext_ports
        self.int_ports = int_ports
        self.device_id = device_id
        self.enforcement = Enforcement(ldb="../../DB/" + str(self.device_id) + ".db")

        if ext_ports is None:
            self.ext_ports = []
        if int_ports is None:
            self.int_ports = []

        for ext_port in self.ext_ports:
            self.sniff(prn=self.ext_port_recv, iface=ext_port)
        for int_port in self.int_ports:
            self.sniff(prn=self.int_port_recv, iface=int_port)

        # start sending beacon every BEACON_INTERVAL
        self.beacon()

    @threaded
    def sniff(self, prn, iface):
        sniff(prn=prn, iface=iface)

    def ext_port_recv(self, pkt):
        data = bytes_hex(pkt)
        print("\next packet:")
        print(pkt)

    def int_port_recv(self, pkt):
        data = bytes_hex(pkt)
        hash = data[0:Hasher.LENGTH]
        print("\nint packet:")
        print("hash" + str(hash))
        print(bytes_hex(pkt))

    @threaded
    def beacon(self):
        int_sockets = {}
        # Create socket for each internal port
        # Add every entry to dict {<port_name>: <socket>}
        for port in self.int_ports:
            int_sockets = int_sockets.update({port: socket(PF_PACKET, SOCK_RAW)})
            int_sockets[port].bind((port, 0))
        while self.BEACON_STATUS:
            for port, s in int_sockets.items():
                print("sending beacon on port " + str(port))
                data = str(self.BEACON_HASH) + str(self.device_id) + str(port)
                _send(s, data)
            sleep(self.BEACON_INTERVAL)


if __name__ == '__main__':
    device_id = hash(gethostname())
    device = Device(device_id=device_id, int_ports=["ens16"])
