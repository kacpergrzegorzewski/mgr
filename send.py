from socket import socket, AF_PACKET, PF_PACKET, SOCK_RAW, IPPROTO_RAW
import struct
import time

BANDWIDTH_TEST_MESSAGE_LENGTH = 1500 #bytes

_socket = socket(PF_PACKET, SOCK_RAW)
_socket.bind(('ens28', 0))

def send_simple_message():
    data = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.").encode()
    print(data.hex())
    _socket.send(data)

def generate_bandwidth_test_message():
    current_message_length = 1
    even = False
    message = 1
    while current_message_length < 8 * BANDWIDTH_TEST_MESSAGE_LENGTH:
        message = message << 1
        if even:
            message += 1
        current_message_length += 1
        even = not even
    return message.to_bytes(length=BANDWIDTH_TEST_MESSAGE_LENGTH, byteorder='big')

def send_bandwidth_test(message):
    while True:
        _socket.send(message)

def send(data, iface):
    '''
    :param data: data to send
    :param iface: name of the interface
    :return: None
    '''
    _socket = socket(PF_PACKET, SOCK_RAW)
    _socket.bind((iface, 0))
    _socket.send(data)


if __name__ == '__main__':
    test_message = generate_bandwidth_test_message()
    send_bandwidth_test(test_message)