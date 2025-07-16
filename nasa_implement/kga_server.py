#kga_server.py
import socket
import threading
import logging
import json
import basicident

import os
import random
import sys
from copy import deepcopy
from sage.crypto.cryptosystem import PublicKeyCryptosystem
from sage.all import (EllipticCurve, Hom, Zmod, FiniteField, Integer, GF, factor)

DISCONNECT_MSG = "!DISCONNECTING"
PROTOCOL = 'utf-8'

class Drone:
    def __init__(self, identity = ""):
        self.identity = identity

def can_send(request):
    '''
    Returns true if someone is requesting a 
    public key (anyone can have anyone's public
    key) or if the person is requesting their
    own private key (identity = requester)
    '''
    if request["request_type"] == "public_key":
        return True
    elif request["request_type"] == "private_key":
        if request["requester"] == request["identity"]:
            return True
    return False
def get_encrypt_params(ibe, destination):
    pub_id = ibe.gen_P_pub()
    P = ibe.P
    Q_ID = basicident.H1(destination, ibe.order, P)
    encrypt_data = {
        "pub_id": {"x": int(pub_id[0]), "y": int(pub_id[1])},
        "order": int(ibe.order),
        "P": {"x": int(P[0]), "y": int(P[1])},
        "Q_ID": {"x": int(Q_ID[0]), "y": int(Q_ID[1])},
        "curve": {
            "q": 10177,
            "a": 0,
            "b": 1
        }
    }
    return encrypt_data

def get_decrypt_params(ibe, identity):
    d_ID = ibe.private_key(identity, ibe.order, ibe.P)
    P = ibe.P
    # P is also included to be used for for signing
    decrypt_data = {
        "order": int(ibe.order),
        "d_ID": {"x": int(d_ID[0]), "y": int(d_ID[1])},
        "P": {"x": int(P[0]), "y": int(P[1])},
        "curve": {
            "q": 10177,
            "a": 0,
            "b": 1
        }
    }
    return decrypt_data

def start(s, SERVER, ibe):
    s.listen()
    #print(f"[LISTENING] on server {SERVER}")
    logger.info(f"[LISTENING] on server {SERVER}")
    logger.info("Waiting for drone to request SAM public key")
    while True:
        conn, addr = s.accept() #Waits until Drone connects
        request_str = conn.recv(4096).decode(PROTOCOL)
        request = json.loads(request_str)
        logger.info(f"Request received\n{json.dumps(request, indent=3)}")
        if request["requester"] == "manager@SAM":
            logger.info(f"[CONNECTED] to SAM at {addr}")
        else:
            logger.info(f"[CONNECTED] to drone at {addr}")

        if can_send(request):
            if request["request_type"] == "public_key":
                encrypt_data = get_encrypt_params(ibe, request["identity"])
                #What the drone/SAM needs to encrypt a message to "identity"
                encrypt_str = json.dumps(encrypt_data)
                logger.info(f"[SENDING] encryption params to {request["requester"]}")
                conn.send(encrypt_str.encode(PROTOCOL))
                conn.close()
            elif request["request_type"] == "private_key":
                decrypt_data = get_decrypt_params(ibe, request["identity"])
                #What the drone/SAM needs to decrypt a message to "identity"              
                decrypt_str = json.dumps(decrypt_data)
                logger.info(f"[SENDING] decryption params to {request["requester"]}")
                conn.send(decrypt_str.encode(PROTOCOL))
                conn.close()


        


#def context_manager(context):

def main():
    #global drone_list
    #drone_list = [Drone(i) for i in range(10)]
    ibe = basicident.gen_global_params()

    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='kga_server.log', level = logging.INFO, encoding='utf-8', filemode='w')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER = socket.gethostbyname(socket.gethostname())
    port_kga = 5051
    s.bind((SERVER, port_kga))
    start(s, SERVER, ibe)

if __name__ == "__main__":
    main()