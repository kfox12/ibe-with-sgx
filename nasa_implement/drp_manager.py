#drp_manager.py
import json
import socket
import basicident
import logging
PROTOCOL = 'utf-8'

def conn_to_kga():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_kga = 5051 #kga's port number
    kga_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kga_socket.connect((SERVER, port_kga)) #Connects to sam_server
    logger.info("[CONNECTED] to KGA server")
    return kga_socket

def build_request(request_type):
    request = {
        "request_type": request_type,
        "requester": "manager@DRP",
        "identity": "manager@SAM",
        "auth_token": "<some form of authentication>",
    }
    return request

def conn_to_sam():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_sam = 5050 #SAM's port number
    sam_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sam_socket.connect((SERVER, port_sam)) #Connects to sam_server
    logger.info("[CONNECTED] to SAM server")
    return sam_socket

def encrypt_drp():
    with open("drp.json") as f:
        all_data = json.load(f)
    drp_str = json.dumps(all_data)

    kga_socket = conn_to_kga()
    request = build_request("public_key")
    request_str = json.dumps(request)
    logger.info("[SENDING] request to KGA for SAM public key")
    kga_socket.send(request_str.encode(PROTOCOL))
    encrypt_str = kga_socket.recv(4096).decode(PROTOCOL)
    logger.info("[RECEIVED] SAM public key")
    encrypt_data = json.loads(encrypt_str)

    ''' ------ Rebuilding the EC to rebuild the encrypt params that the 
    '''
    q = encrypt_data["curve"]["q"]
    a = encrypt_data["curve"]["a"]
    b = encrypt_data["curve"]["b"]
    E = basicident.gen_EC(q, a, b)

    pub_id = E((encrypt_data["pub_id"]["x"], encrypt_data["pub_id"]["y"]))
    P = E((encrypt_data["P"]["x"], encrypt_data["P"]["y"]))
    Q_ID = E((encrypt_data["Q_ID"]["x"], encrypt_data["Q_ID"]["y"]))
    order = encrypt_data["order"]

    C1, C2 = basicident.encrypt(drp_str, pub_id, order, P, Q_ID, text=True)
    '''Serializing the cipher to send to SAM'''
    ciphertext_msg = {
        "C1": {"x": int(C1[0]), "y": int(C1[1])},
        "C2": C2,
        "curve": {
            "q": q,
            "a": a,
            "b": b
        }
    }
    ciphertext_str = json.dumps(ciphertext_msg)
    return ciphertext_str

def main():
    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='drp_manager.log', level = logging.INFO, encoding='utf-8', filemode='w')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER = socket.gethostbyname(socket.gethostname())
    port_drp = 5052
    s.bind((SERVER, port_drp))
    s.listen()
    logger.info("[LISTENING] for SAM's connection")
    while True:    
        conn, addr = s.accept() # Accepts sam's connection
        logger.info("[CONNECTED] to SAM")
        encrypted_drp_str = encrypt_drp()
        logger.info("[SENDING] the encrypted drp file to SAM")
        conn.send(encrypted_drp_str.encode(PROTOCOL)) # Sends C1, C2 back to SAM
        conn.close()


if __name__ == "__main__":
    main()
