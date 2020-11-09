import argparse
import sys
import socket
from threading import Thread
import queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def encrypt(key, plaintext):
    salt = get_random_bytes(16)
    iv = get_random_bytes(12)
    cipher = AES.new(PBKDF2(key, salt, dkLen = 32), AES.MODE_GCM, nonce = iv)
    cipher.update(salt)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt + iv + ciphertext + tag

def decrypt(key, encrypted_ciphertext):
    salt = encrypted_ciphertext[:16]
    iv = encrypted_ciphertext[16:28]
    ciphertext = encrypted_ciphertext[28:-16]
    tag = encrypted_ciphertext[-16:]
    cipher = AES.new(PBKDF2(key, salt, dkLen = 32), AES.MODE_GCM, nonce = iv)
    cipher.update(salt)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


#----- receive module -----#

def receive(connectionsocket, key):
    size_msg = connectionsocket.recv(1024)
    try:
        remain = size = int(size_msg)
    except ValueError:
        connectionsocket.send(b'BYE')
        return("data transfer error (file size)")
    if size == 44:
        connectionsocket.send(b'BYE')
        return("empty file")
    connectionsocket.send(b'READY')
    ciphertext = b''
    while remain > 0:
        ciphertext += connectionsocket.recv(1024 if remain > 1024 else remain)
        remain -= 1024
    if len(ciphertext) != size or len(ciphertext) < 44:
        connectionsocket.send(b'DTERR') # connection error
        return("data transfer error")
    try:
        plaintext = decrypt(key, ciphertext)
        sys.stdout.buffer.write(plaintext)
        connectionsocket.send(b'RCVD') # succeed
        return("successfully received")
    except ValueError:
        connectionsocket.send(b'CHKERR') # MAC check failed
        return("MAC check failed")


def server_receive_thread(connectionsocket, key):
    connectionsocket.send(b'READY')
    msg = receive(connectionsocket, key)
    return "receive thread: " + msg

def client_receive_thread(address, port, key):
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((address, port))
    clientsocket.send(b'RECEIVEMODE')
    msg = receive(clientsocket, key)
    clientsocket.close()
    return "receive thread: " + msg

#----- send module -----#

def send(clientsocket, key):
    plaintext = b''
    if not sys.stdin.isatty():
        data = sys.stdin.buffer.read(2048)
        plaintext += data
        while data:
            data = sys.stdin.buffer.read(2048)
            plaintext += data
        sys.stdin.close()
    ciphertext = encrypt(key, plaintext)
    clientsocket.send(str(len(ciphertext)).encode("utf-8"))
    connect_ack = clientsocket.recv(1024)
    if connect_ack == b'READY':
        num = 0
        while (num + 1) * 1024 < len(ciphertext):
            clientsocket.send(ciphertext[num * 1024 : (num + 1) * 1024])
            num += 1
        clientsocket.send(ciphertext[num * 1024 :])
        ack = clientsocket.recv(1024) # ack = {b'DTERR', b'CHKERR', b'RCVD'}
        if ack == b'DTERR':
            return("data transfer error")
        elif ack == b'CHKERR':
            return("MAC check failed")
        elif ack == b'RCVD':
            return("file successfully sent")
        else:
            return("failed due to unknown reason")
    elif connect_ack == b'BYE':
        return("send thread close early")
    else:
        return("connection error")


def server_send_thread(connectionsocket, key):
    msg = send(connectionsocket, key)
    return "send thread: " + msg

def client_send_thread(address, port, key):
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect((address, port))
    clientsocket.send(b'SENDMODE')
    ack = clientsocket.recv(5)
    if ack == b'READY':
        msg = send(clientsocket, key)
    else:
        msg = "destination not ready"
    clientsocket.close()
    return "send thread: " + msg


#----- main thread function -----#

def server(port, key):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('0.0.0.0', port))
    serversocket.settimeout(300) # set server socket timeout as 5 minutes
    serversocket.listen()
    connectionsocket1, address1 = serversocket.accept()
    req1 = connectionsocket1.recv(1024)
    que = queue.Queue()
    if req1 == b'SENDMODE':
        t1 = Thread(target = lambda q, arg: q.put(server_receive_thread(*arg)), args = (que, (connectionsocket1, key)))
        t1.start()
        t1.join()
        msg1 = que.get()
    elif req1 == b'RECEIVEMODE':
        t1 = Thread(target = lambda q, arg: q.put(server_send_thread(*arg)), args = (que, (connectionsocket1, key)))
        t1.start()
        t1.join()
        msg1 = que.get()
    else:
        msg1 = "first request failed due to connection error"
    connectionsocket2, address2 = serversocket.accept()
    req2 = connectionsocket2.recv(1024)
    if req2 == b'SENDMODE':
        t2 = Thread(target = lambda q, arg: q.put(server_receive_thread(*arg)), args = (que, (connectionsocket2, key)))
        t2.start()
        t2.join()
        msg2 = que.get()
    elif req2 == b'RECEIVEMODE':
        t2 = Thread(target = lambda q, arg: q.put(server_send_thread(*arg)), args = (que, (connectionsocket2, key)))
        t2.start()
        t2.join()
        msg2 = que.get()
    else:
        msg2 = "second request failed due to connection error"
    sys.stdout.close()
    sys.stderr.write(msg1 + '\n' + msg2)
    serversocket.close()
    connectionsocket1.close()
    connectionsocket2.close()

def client(address, port, key):
    que = queue.Queue()
    t1 = Thread(target = lambda q, arg: q.put(client_send_thread(*arg)), args = (que, (address, port, key)))
    t2 = Thread(target = lambda q, arg: q.put(client_receive_thread(*arg)), args = (que, (address, port, key)))
    t1.start()
    t1.join()
    msg1 = que.get()
    t2.start()
    t2.join()
    msg2 = que.get()
    sys.stdout.close()
    sys.stderr.write(msg1 + '\n' + msg2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='simple version secure netcat')
    parser.add_argument('-l', action="store_true", help='Is server mode?')
    parser.add_argument('--key', nargs=1, metavar='KEY', help='Set the key')
    parser.add_argument('address', nargs='?', metavar='ADDR', help='Set the address')
    parser.add_argument('port', type=int, nargs=1, metavar='PORT', help='Set the port')
    _args = parser.parse_args(sys.argv[1:])
    if _args.key == None:
        parser.error("the following arguments are required: KEY")
    if (_args.address is None) ^ _args.l:
        parser.error("incorrect input: ADDRESS or -l")
    try:
        if _args.l:
            server(_args.port[0], _args.key[0])
        else:
            client(_args.address, _args.port[0], _args.key[0])
    except KeyboardInterrupt:
        sys.exit()
