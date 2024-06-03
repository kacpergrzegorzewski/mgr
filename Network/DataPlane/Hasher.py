from hashlib import md5

LENGTH = hash("")

def hash_pkt(pkt):
    print("hashing")


def hasher(data):
    return md5(data).digest()
