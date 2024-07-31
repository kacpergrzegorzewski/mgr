# hash("")
BEACON_HASH = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'
# hash("policy-engine-new-flow")
POLICY_ENGINE_NEW_FLOW_HASH = b'\x1eB|\xe20\xbf\xe0\xed\xdb\xcd\xad\x07s\xc8~\r'
# hash("configurator-update-agent")
CONFIGURATOR_UPDATE_AGENT_HASH = b'\xbdA\x97xO\x1bcq!\x80_\r\x94IMn'
# hash("configurator-add-link")
CONFIGURATOR_ADD_LINK_HASH = b'v\x8d\xfb\xc3\x8bf\xea\x86\xc0\xaf\x1c!V\x0e\xd9\xe9'
# hash("configurator-add-flow")
CONFIGURATOR_ADD_FLOW_HASH = b'\x80\xcf\x1d\x04\xa7dL!\x9d\x1d\xd6\xa4N\x05\x95\xd2'


# Beacon interval in seconds
BEACON_INTERVAL = 2

# Min and Max wait time for new packet in seconds (time to add LDB entry by control plane)
# Each time the device waits twice as long as before until it reaches MAX_PKT_WAIT e.g. 0.001, 0.002, 0.004, 0.008...
MIN_PKT_WAIT = 0.001
MAX_PKT_WAIT = 2

# Min and Max wait time for new link or new node in TDB in seconds (wait for node to be created)
# Each time the TDB waits twice as long as before until it reaches MAX_LINK_WAIT e.g. 0.001, 0.002, 0.004, 0.008...
MIN_TDB_WAIT = 0.001
MAX_TDB_WAIT = 2

# Length of all interfaces names in network (e.g. "ens16" = 5)
IFACE_NAME_LENGTH = 5
# Name of outport for packet drop action
IFACE_NAME_DROP = "x"*IFACE_NAME_LENGTH
# Name of every agent interface (used to distinguish between data plane devices and agent)
IFACE_NAME_AGENT = "agent"[0:IFACE_NAME_LENGTH]

# How to send data in network? (big endian, little endian)
NETWORK_BYTEORDER = 'big'

# Length of epoch time variable in bytes (1 byte = 8 bits). Epoch time variable is used in LDB flow timeout.
EPOCH_TIME_LENGTH = 8
