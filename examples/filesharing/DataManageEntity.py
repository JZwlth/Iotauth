import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime


bytes_num = 1024
DATA_UPLOAD_REQ = 0
DATA_DOWNLOAD_REQ = 1
DATA_RESP = 2
sel = selectors.DefaultSelector()

def put_data(recv_data, data_center):
    name_size = recv_data[1]
    name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
    data_center["name"].append(name)
    keyid_size = recv_data[2+name_size]
    keyid = recv_data[3+name_size:3+name_size+keyid_size]
    data_center["keyid"].append(keyid)
    hash_value_size = recv_data[3+name_size+keyid_size]
    hash_value = recv_data[4+name_size+keyid_size:4+name_size+keyid_size+hash_value_size].decode('utf-8')
    data_center["hash_value"].append(hash_value)

def accept_wrapper(sock):
    conn, addr = sock.accept()  
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

data_center = {"name":[] , "keyid" : [], "hash_value" : []}
log_center = {"name":[] , "keyid" : [], "hash_value" : []}
def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(bytes_num)  # Should be ready to read
        if recv_data:      
            total_len = len(recv_data)
            print(recv_data)
            if recv_data[0] == DATA_UPLOAD_REQ:
                put_data(recv_data, data_center)
                print(data_center)
            elif recv_data[0] == DATA_DOWNLOAD_REQ:
                name_size = recv_data[1] 
                name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
                res_keyid = data_center["keyid"][0]
                res_hashvalue = data_center["hash_value"][0]
                command = "ipfs cat $1 > enc_server.txt"
                command = command.replace("$1", res_hashvalue)
                message = bytearray(3+len(res_keyid)+len(command))
                message[0] = int(hex(DATA_RESP),16)
                message[1] = int(hex(len(res_keyid)),16)
                message[2:2+len(res_keyid)] = res_keyid
                message[2+len(res_keyid)] = int(hex(len(command)),16)
                message[3+len(res_keyid):3+len(res_keyid)+len(command)] = bytes.fromhex(str(command).encode('utf-8').hex())
                
                data.outb += message
                sent = sock.send(data.outb) 
                data.outb = data.outb[sent:]
                log_center["name"].append(name), log_center["hash_value"].append(res_hashvalue), log_center["keyid"].append(res_keyid)
                del data_center["hash_value"][0], data_center["keyid"][0], data_center["name"][0]


        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)

    
port = 22100
host, port = '127.0.0.1', port

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    lsock.close()
    sel.close()
    print("-------------LOG result-------------")
    print(log_center)
    
    print("Finished")