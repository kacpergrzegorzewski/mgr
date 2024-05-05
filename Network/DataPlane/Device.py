import threading

from scapy.compat import bytes_hex
from scapy.sendrecv import sniff

from Enforcement import _Enforcement as Enforcement
import Hasher


def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


class Device:
    def __init__(self, device_id: int, ext_ports=None, int_ports=None):
        if ext_ports is None:
            ext_ports = []
        if int_ports is None:
            int_ports = []
        self.enforcement = Enforcement(ldb="../../DB/" + str(device_id) + ".db")

        for ext_port in ext_ports:
            self.sniff(prn=self.ext_port_recv, iface=ext_port)
        for int_port in int_ports:
            self.sniff(prn=self.int_port_recv, iface=int_port)

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
        print(pkt)

    def start(self):
        print("start")


if __name__ == '__main__':
    device_id = hash("router02")
    device = Device(device_id=device_id, int_ports=["ens16"])
