import threading
import time
from time import sleep

from scapy.all import sniff, bytes_hex

IFACE = 'ens16'
PACKET_COUNTER = 0
PRINT_PACKET_COUNTER = True
BANDWIDTH_TEST_MESSAGE_LENGTH = 9000

def threaded(fn):
    def wrapper(*args, **kwargs):
        threading.Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper

def mod(pkt):
    print((bytes_hex(pkt)).decode("utf-8"))


def edge(pkt):
    print(pkt)
    print(pkt)

def increment_packet_counter(pkt):
    global PACKET_COUNTER
    PACKET_COUNTER += 1

@threaded
def count_packets():
    global PACKET_COUNTER
    global PRINT_PACKET_COUNTER

    while PRINT_PACKET_COUNTER:
        packet_counter_before = PACKET_COUNTER
        time_before = time.time()
        sleep(1)
        packet_counter_after = PACKET_COUNTER
        time_after = time.time()
        time_passed = time_after - time_before
        packets_passed = packet_counter_after - packet_counter_before
        mbs = packets_passed * BANDWIDTH_TEST_MESSAGE_LENGTH / time_passed / 1024
        print("Received " + str(packets_passed) + " packets in " + str(time_passed) + " (" + str(mbs) + " KB/s)")

@threaded
def sniff_threaded():
    sniff(prn=increment_packet_counter, iface=IFACE)

if __name__ == '__main__':
    sniff_threaded()
    count_packets()
