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

def verify_airspace_req(apar):
    logger.info("[CHECKING] environment conditions")
    wind_lvl = check_wind()
    logger.info("[CHECKING] drone experience with DRP file")
    # NEED TO ADD ENCRYPTION AND DECRYPTION OF THE DRP FILE
    wind_exp = drp_manager.get_exp(apar["id"])
    return has_exp(wind_lvl, wind_exp)
    # if True, Drone can enter the airspace

def verify_sig(apar):
    if apar["signature"] == None:
        return False
    else:
        return True
    
def sign_feedback(feedback_str, drone_id, E, order, P):
    Q_ID = basicident.H1(drone_id, order, P)
    logger.info("[SIGNING] the feedback")
    C1, C2 = basicident.encrypt(feedback_str, d_ID, order, P, Q_ID, text=True)
    return {
        "C1": {"x": int(C1[0]), "y": int(C1[1])},
        "C2": C2
    }

def conn_to_kga():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_kga = 5051 #kga's port number
    kga_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kga_socket.connect((SERVER, port_kga)) #Connects to sam_server
    logger.info("[CONNECTED] to KGA server")
    return kga_socket

def decrypt_apar(C1, C2, E):
    '''Takes in the encrypted Ciphertext sent from Drone, 
    and the EC used to do so, as parameters'''
    
    logger.info(f"C1: {C1}\nC2: {C2}")
    kga_socket = conn_to_kga()
    request = {
        "request_type": "private_key",
        "requester": "manager@SAM",
        "identity": "manager@SAM",
        "auth_token": "<some form of authentication>",
    }
    request_str = json.dumps(request)
    logger.info("[SENDING] request to KGA for private key")
    kga_socket.send(request_str.encode(PROTOCOL))
    
    decrypt_str = kga_socket.recv(4096).decode(PROTOCOL)
    logger.info("[RECEIVED] private key info from KGA")
    kga_socket.close()
    logger.info("[CLOSED] KGA socket")
    decrypt_data = json.loads(decrypt_str)
    
    # Rebuilding d_ID using the EC
    global d_ID
    d_ID = E((decrypt_data["d_ID"]["x"], decrypt_data["d_ID"]["y"]))
    order = decrypt_data["order"]

    apar = basicident.decrypt((C1, C2), d_ID, order, text=True)
    logger.info(f"------------\nDecrypted apar file")
    logger.info(json.dumps(json.loads(apar), indent=3))
    return apar, decrypt_data
    
def accept_drone(s, SERVER):
    while True:
        conn, addr = s.accept() #Waits until Drone connects
        logger.info(f"[CONNECTED] with drone {SERVER}")
        ''' data will be populated with the encrypted apar.json
        (Python dictionary) that the drone sends over upon 
        connection
        '''
        data = conn.recv(4096).decode(PROTOCOL) 
        apar_ciphertext = json.loads(data)
        # Reconstructing EC from drone data 
        q = apar_ciphertext["curve"]["q"]
        a = apar_ciphertext["curve"]["a"]
        b = apar_ciphertext["curve"]["b"]
        E = basicident.gen_EC(q, a, b)
        #----------------
        # Rebuilding the ciphertext with the EC
        C1 = E(apar_ciphertext["C1"]["x"], apar_ciphertext["C1"]["y"])
        C2 = apar_ciphertext["C2"]   
        apar_str, decrypt_data = decrypt_apar(C1, C2, E)
        apar = json.loads(apar_str)
        if not verify_sig(apar):
            raise ValueError("No signature on encrypted apar file")
        handle_apar(conn, apar, E, decrypt_data)
        
def handle_apar(conn, apar, E, decrypt_data):
    airspace_feedback = {
            "id": apar["id"],
            "mission_id": apar["mission_id"]
        }
    if verify_airspace_req(apar):
        airspace_feedback["outcome"] = "approval"
    else:
        airspace_feedback["outcome"] = "denial"
    feedback_str = json.dumps(airspace_feedback)

    order = decrypt_data["order"]
    P = E(decrypt_data["P"]["x"], decrypt_data["P"]["y"])
    signature = sign_feedback(feedback_str, apar["id"], E, order, P)
    airspace_feedback["signature"] = signature
    feedback_str = json.dumps(airspace_feedback)
    logger.info("[SENDING] signed feedback to drone")
    conn.send(feedback_str.encode(PROTOCOL))

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