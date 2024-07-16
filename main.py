from Network.DataPlane import Hasher
from socket import gethostname
from Network.DataPlane.Device import Device
from Network.DataPlane.LDB import LDBSQLite


def start_device():
    device_id = Hasher.hasher(gethostname().encode())
    configurator_hash = Hasher.hasher("configurator".encode())
    print(device_id)
    ldb = LDBSQLite("/opt/mgr/ldb/" + str(int.from_bytes(device_id, "big")) + ".db")
    device = Device(device_hash=device_id, configurator_hash=configurator_hash, ldb=ldb, int_ifaces=["ens16", "ens17", "ens27", "ens28"])

def ldb_test():
    hash = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'
    device_id = Hasher.hasher(gethostname().encode())
    ldb = LDBSQLite("/opt/mgr/ldb/" + str(int.from_bytes(device_id, "big")) + ".db")
    print(ldb.get_outport(b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'))
#    print(ldb.get_all())
    ldb.put(hash, "ens16")


if __name__ == '__main__':
    start_device()
