from hashlib import md5


def hash(data):
    return md5(data).digest()


LENGTH = len(hash("".encode()))
