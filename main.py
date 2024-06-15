from Network.DataPlane import Hasher
from socket import gethostname
from Network.DataPlane.Device import Device

if __name__ == '__main__':
    device_id = Hasher.hasher(gethostname().encode())
    configurator_hash = Hasher.hasher("configurator".encode())
    print(device_id)
    device = Device(device_id=device_id, configurator_hash=configurator_hash, int_ifaces=["ens16"])