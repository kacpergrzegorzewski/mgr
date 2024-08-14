from socket import socket, AF_PACKET, PF_PACKET, SOCK_RAW, IPPROTO_RAW
import struct
import time

_socket = socket(PF_PACKET, SOCK_RAW)
_socket.bind(('ens28', 0))

data = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.").encode()
print(data.hex())
_socket.send(data)

def send(data, iface):
    '''
    :param data: data to send
    :param iface: name of the interface
    :return: None
    '''
    _socket = socket(PF_PACKET, SOCK_RAW)
    _socket.bind((iface, 0))
    _socket.send(data)

#for i in range(50):
#	data = ("to jest " + str(i) + " wiadomosc.").encode()
#	print(data)
#	socket.send(data)
#	time.sleep(0.1)
