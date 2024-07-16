# hash("")
BEACON_HASH = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'
# hash("policy-engine")
POLICY_ENGINE_HASH = b'\xcb\xf7\xdc-\x8b\xaf\xa0t\x85\x8a?\x80_\x03q\xee'

# Beacon interval in seconds
BEACON_INTERVAL = 2

# Min and Max wait time for new packet in seconds (time to add LDB entry by control plane)
# Each time the device waits twice as long as before until it reaches MAX_PKT_WAIT e.g. 0.001, 0.002, 0.004, 0.008...
MIN_PKT_WAIT = 0.001
MAX_PKT_WAIT = 2

# Length of all interfaces names in network (e.g. "ens16" = 5)
IFACE_NAME_LENGTH = 5

# hash("configurator")
CONFIGURATOR_HASH = b'd\xa7\x88\xf2\xb9\xa2\x1eG\xec\xa4s\xaeye0Q'
