from Network.DataPlane import Hasher
from socket import gethostname
from Network.DataPlane.Device import Device
from Network.DataPlane.LDB import LDBSQLite
from Network.ControlPlane.Configurator import Configurator
from Network.ControlPlane.PolicyEngine import PolicyEngine
from Network.Base.Env import *
import yaml


def start_device(device_name, ldb_path, configurator_via, policy_engine_via, int_ifaces, ext_ifaces):
    device_hash = Hasher.hash(device_name.encode())
    print("[INFO] Starting device " + str(device_hash))
    ldb = LDBSQLite(ldb_path)
    add_configurator_path(ldb, configurator_via)
    add_policy_engine_new_flow_path(ldb, policy_engine_via)
    device = Device(device_hash=device_hash, ldb=ldb, int_ifaces=int_ifaces, ext_ifaces=ext_ifaces)


def start_configurator(iface, node_lifetime, link_lifetime, path_lifetime, create_paths_interval):
    configurator = Configurator(iface=iface,
                                node_lifetime=node_lifetime,
                                link_lifetime=link_lifetime,
                                path_lifetime=path_lifetime,
                                create_paths_interval=create_paths_interval)


def start_policy_engine(iface, allowed_flows, flow_timeout):
    policy_engine = PolicyEngine(iface=iface, allowed_flows=allowed_flows, flow_timeout=flow_timeout)


def ldb_test():
    hash = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'
    device_hash = Hasher.hash(gethostname().encode())
    ldb = LDBSQLite("/opt/mgr/ldb/" + str(int.from_bytes(device_hash, "big")) + ".db")
    print(ldb.get_outport(b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'))
    #    print(ldb.get_all())
    ldb.add_flow(hash, "ens16")


def add_configurator_path(ldb, iface):
    _hash = CONFIGURATOR_LINK_DISCOVERY_HASH
    ldb.add_flow(_hash, iface)
    print("[INFO] Path to configurator add link via: " + str(ldb.get_outport(_hash)))
    _hash = CONFIGURATOR_ADD_FLOW_HASH
    ldb.add_flow(_hash, iface)
    print("[INFO] Path to configurator add flow via: " + str(ldb.get_outport(_hash)))
    _hash = CONFIGURATOR_UPDATE_AGENT_HASH
    ldb.add_flow(_hash, iface)
    print("[INFO] Path to configurator update agent via: " + str(ldb.get_outport(_hash)))


def add_policy_engine_new_flow_path(ldb, iface):
    _hash = POLICY_ENGINE_NEW_FLOW_HASH
    ldb.add_flow(_hash, iface)
    print("[INFO] Path to policy engine via: " + str(ldb.get_outport(_hash)))


if __name__ == '__main__':
    with open('config.yaml', 'r') as configfile:
        config = yaml.safe_load(configfile)
    if config["type"] == "device":
        start_device(config["spec"]["nodeName"],
                     config["spec"]["device"]["LDBPath"],
                     config["spec"]["device"]["configuratorVia"],
                     config["spec"]["device"]["policyEngineVia"],
                     config["spec"]["device"]["intIfaces"],
                     config["spec"]["device"]["extIfaces"])
    elif config["type"] == "configurator":
        start_configurator(iface=config["spec"]["configurator"]["iface"],
                           node_lifetime=config["spec"]["configurator"]["nodeLifetime"],
                           link_lifetime=config["spec"]["configurator"]["linkLifetime"],
                           path_lifetime=config["spec"]["configurator"]["pathLifetime"],
                           create_paths_interval=config["spec"]["configurator"]["createPathsInterval"])
    elif config["type"] == "policy-engine":
        iface = config["spec"]["policyEngine"]["iface"]
        flow_timeout = config["spec"]["policyEngine"]["flowTimeout"]
        allowed_flows = config["spec"]["policyEngine"]["allowedFlows"]
        start_policy_engine(iface=iface, allowed_flows=allowed_flows, flow_timeout=flow_timeout)

    # start_device()
#    add_configurator_path("ens27")
