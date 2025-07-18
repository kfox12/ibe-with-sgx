#sam_server.py
import socket
import json
import logging
import random
import basicident
import drp_manager
PROTOCOL = 'utf-8'

def has_exp(wind_lvl, wind_exp):
    if wind_exp >= wind_lvl:
        return True
    return False

def check_wind():
    wind = random.randint(0, 2)
    logger.info(f"[CHECKING] wind level: {wind}")
    return wind

def build_request(request_type):
    request = {
        "request_type": request_type,
        "requester": "manager@SAM",
        "identity": "manager@SAM",
        "auth_token": "<some form of authentication>",
    }
    return request

def build_curve(curve_data):
    q = curve_data["curve"]["q"]
    a = curve_data["curve"]["a"]
    b = curve_data["curve"]["b"]
    E = basicident.gen_EC(q, a, b)
    return E

def rebuild_cipher(ciphertext):
    '''Makes C1, C2 back into EC points'''
    E = build_curve(ciphertext)
    #----------------
    # Rebuilding the ciphertext with the EC
    C1 = E(ciphertext["C1"]["x"], ciphertext["C1"]["y"])
    C2 = ciphertext["C2"]   
    return C1, C2

def conn_to_drp():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_drp = 5052 #drp's port number
    drp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    drp_socket.connect((SERVER, port_drp)) #Connects to sam_server
    logger.info("[CONNECTED] to DRP manager")
    return drp_socket

def conn_to_kga():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_kga = 5051 #kga's port number
    kga_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kga_socket.connect((SERVER, port_kga)) #Connects to sam_server
    logger.info("[CONNECTED] to KGA server")
    return kga_socket

def recv_decrypt_data(kga_socket):
    decrypt_str = kga_socket.recv(4096).decode(PROTOCOL)
    logger.info("[RECEIVED] private key info from KGA")
    decrypt_data = json.loads(decrypt_str)
    # Rebuilding d_ID using the EC

    E = build_curve(decrypt_data)
    global d_ID
    d_ID = E((decrypt_data["d_ID"]["x"], decrypt_data["d_ID"]["y"]))
    order = decrypt_data["order"]

    return decrypt_data, d_ID, order

def sign_feedback(feedback_str, drone_id, E, order, P):
    Q_ID = basicident.H1(drone_id, order, P)
    logger.info("[SIGNING] the feedback")
    C1, C2 = basicident.encrypt(feedback_str, d_ID, order, P, Q_ID, text=True)
    return {
        "C1": {"x": int(C1[0]), "y": int(C1[1])},
        "C2": C2
    }

def get_drp(drone_conn):
    drp_socket = conn_to_drp()
    drp_cipher_str = drp_socket.recv(4096).decode(PROTOCOL) # Encrypted DRP received
    
    logger.info("[RECEIVED] encrypted DRP file")
    drp_cipher = json.loads(drp_cipher_str)
    C1, C2 = rebuild_cipher(drp_cipher)
    logger.info(f"C1: {C1}\nC2: {C2}")
    
    ''' CONNECTING TO KGA FOR DECRYPTION'''
    kga_socket = conn_to_kga()
    request = build_request("private_key")
    request_str = json.dumps(request)
    logger.info("[SENDING] request to KGA for private key")
    kga_socket.send(request_str.encode(PROTOCOL))
    decrypt_data, d_ID, order = recv_decrypt_data(kga_socket)
    logger.info("[CLOSING] kga connection")
    kga_socket.close()
    
    cipher = (C1, C2)
    drp_str = basicident.decrypt(cipher, d_ID, order, text=True)
    drp = json.loads(drp_str)
    return drp

def get_drone_exp(drp, identity):
    for drone in drp["drones"]:
        if drone["identity"] == identity:
            logger.info(f"Drone's wind experience: {drone["wind_xp"]}")
            return drone["wind_xp"]
    raise ValueError(f"Drone with identity {identity} not found in DRP file")

def verify_sig(apar):
    if apar["signature"] == None:
        return False
    else:
        return True

def verify_airspace_req(drone_conn, apar):
    logger.info("[CHECKING] environment conditions")
    wind_lvl = check_wind()
    logger.info("[CHECKING] drone experience with DRP file")
    # NEED TO ADD ENCRYPTION AND DECRYPTION OF THE DRP FILE
    drp = get_drp(drone_conn)
    wind_exp = get_drone_exp(drp, apar["id"])
    
    # if True, Drone can enter the airspace 
    return has_exp(wind_lvl, wind_exp)

def decrypt_apar(C1, C2):
    '''Takes in the encrypted Ciphertext sent from Drone, 
    and the EC used to do so, as parameters'''
    
    logger.info(f"C1: {C1}\nC2: {C2}")
    kga_socket = conn_to_kga()
    request = build_request("private_key")
    request_str = json.dumps(request)
    logger.info("[SENDING] request to KGA for private key")
    kga_socket.send(request_str.encode(PROTOCOL))
    
    decrypt_data, d_ID, order = recv_decrypt_data(kga_socket)
    kga_socket.close()
    logger.info("[CLOSED] KGA socket")

    apar = basicident.decrypt((C1, C2), d_ID, order, text=True)
    logger.info(f"------------\nDecrypted apar file")
    logger.info(json.dumps(json.loads(apar), indent=3))
    return apar, decrypt_data

def handle_apar(conn, apar, E, decrypt_data):
    airspace_feedback = {
            "id": apar["id"],
            "mission_id": apar["mission_id"]
        }
    if verify_airspace_req(conn, apar):
        airspace_feedback["outcome"] = "approval"
    else:
        airspace_feedback["outcome"] = "denial"
    feedback_str = json.dumps(airspace_feedback)
    ''' ----- SAM signing the feedback so that the drone can confirm its legitimacy'''
    order = decrypt_data["order"]
    P = E(decrypt_data["P"]["x"], decrypt_data["P"]["y"])
    signature = sign_feedback(feedback_str, apar["id"], E, order, P)
    airspace_feedback["signature"] = signature
    feedback_str = json.dumps(airspace_feedback)
    logger.info("[SENDING] signed feedback to drone")
    conn.send(feedback_str.encode(PROTOCOL))

def accept_drone(s, SERVER):
    while True:
        conn, addr = s.accept() #Waits until Drone connects
        logger.info("==========================================================================================")
        logger.info(f"[CONNECTED] with drone {SERVER}")
        ''' data will be populated with the encrypted apar.json
        (Python dictionary) that the drone sends over upon 
        connection
        '''
        data = conn.recv(4096).decode(PROTOCOL) 
        apar_ciphertext = json.loads(data)
        # Reconstructing EC from drone data 
        C1, C2 = rebuild_cipher(apar_ciphertext)
        apar_str, decrypt_data = decrypt_apar(C1, C2)
        apar = json.loads(apar_str)
        if not verify_sig(apar):
            raise ValueError("No signature on encrypted apar file")
        E = build_curve(decrypt_data)
        handle_apar(conn, apar, E, decrypt_data)
        
def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER = socket.gethostbyname(socket.gethostname())
    port_sam = 5050
    s.bind((SERVER, port_sam))
    s.listen()
    logger.info(f"[LISTENING] on server {SERVER}")
    logger.info("Waiting for Drone to connect")
    accept_drone(s, SERVER)


def main():
    global logger 
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='sam_server.log', level = logging.INFO, encoding='utf-8', filemode='w')
    start_server()


if __name__ == "__main__":
    main()