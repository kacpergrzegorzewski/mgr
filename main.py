from Network.DataPlane import Hasher
from socket import gethostname
from Network.DataPlane.Device import Device
from Network.DataPlane.LDB import LDBSQLite

if __name__ == '__main__':
    device_id = Hasher.hasher(gethostname().encode())
    configurator_hash = Hasher.hasher("configurator".encode())
    print(device_id)
    ldb = LDBSQLite("/opt/mgr/ldb/" + str(int.from_bytes(device_id, "big")) + ".db")
#    ldb.put(b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~', "ens16")
    device = Device(device_id=device_id, configurator_hash=configurator_hash, ldb=ldb, int_ifaces=["ens16"])
