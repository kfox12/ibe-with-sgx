#drone_client.py
import socket
import logging
import json
import basicident
DISCONNECT_MSG = "!DISCONNECTING"
PROTOCOL =  'utf-8'
drone = "green@notredame"

def conn_to_kga():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_kga = 5051 #kga's port number
    kga_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kga_socket.connect((SERVER, port_kga)) #Connects to sam_server
    logger.info("[CONNECTED] to KGA server")

    return kga_socket

def get_sam_params():
    kga_socket = conn_to_kga()
    request = {
        "request_type": "public_key",
        "requester": drone,
        "identity": "manager@SAM",
        "auth_token": "<some form of authentication>"
    }
    request_str = json.dumps(request)
    logger.info("[SENDING] request to KGA for SAM public key")
    kga_socket.send(request_str.encode(PROTOCOL))
    response = kga_socket.recv(4096).decode(PROTOCOL)
    logger.info(f"[DEBUG] Raw response from KGA:\n{response}")
    logger.info("[CLOSING] KGA server")
    kga_socket.close()
    encrypt_data = json.loads(response)
    return encrypt_data

def sign_apar(apar):
    apar["signature"] = "HASH"

def verify_sig(airspace_feedback, sam_params):
    ''' airspace_feedback is encrypted with SAM's private key
    and needs to be decrypted with the SAM's public key'''
    q = sam_params["curve"]["q"]
    a = sam_params["curve"]["a"]
    b = sam_params["curve"]["b"]
    E = basicident.gen_EC(q, a, b)
    P = E((sam_params["P"]["x"], sam_params["P"]["y"]))
    Q_ID = E((sam_params["Q_ID"]["x"], sam_params["Q_ID"]["y"]))
    order = sam_params["order"]

    C1 = E((airspace_feedback["signature"]["C1"]["x"], airspace_feedback["signature"]["C1"]["y"]))
    C2 = airspace_feedback["signature"]["C2"]

    decrypted_str = basicident.decrypt((C1, C2), Q_ID, order, text=True)
    expected = {
        "id": airspace_feedback["id"],
        "mission_id": airspace_feedback["mission_id"],
        "outcome": airspace_feedback["outcome"]
    }
    expected_str = json.dumps(expected)
    return expected_str == decrypted_str

def send_apar(sam_socket):
    apar = {
        "mission_id": "ID_HASH",
        "id": drone
    }
    sign_apar(apar) #Trivial at the moment
    sam_params = get_sam_params() #Returns python dictionary
    #Reconstructing the encrypt params received from kga
    q = sam_params["curve"]["q"]
    a = sam_params["curve"]["a"]
    b = sam_params["curve"]["b"]
    E = basicident.gen_EC(q, a, b)
    pub_id = E((sam_params["pub_id"]["x"], sam_params["pub_id"]["y"]))
    P = E((sam_params["P"]["x"], sam_params["P"]["y"]))
    Q_ID = E((sam_params["Q_ID"]["x"], sam_params["Q_ID"]["y"]))
    order = sam_params["order"]
    #Converting apar to a valid message string
    apar_message = json.dumps(apar)
    apar_ciphertext = basicident.encrypt(apar_message, pub_id, order, P, Q_ID, text=True)
    C1, C2 = apar_ciphertext
    #Passing q, a, b so that SAM can construct EC and decrypt
    ciphertext_msg = {
        "C1": {"x": int(C1[0]), "y": int(C1[1])},
        "C2": C2,
        "curve": {
            "q": q,
            "a": a,
            "b": b
        }
    }
    #Convert dict to JSON string
    ciphertext_json = json.dumps(ciphertext_msg)
    sam_socket.send(ciphertext_json.encode(PROTOCOL))
    ''' SAM now processes the apar that was just sent,
    checks the current environment and DRP, and sends signed
    (encrypted) feedback declaring whether the drone can 
    enter the airspace '''
    handle_feedback(sam_socket, sam_params)

def handle_feedback(sam_socket, sam_params):
    feedback_str = sam_socket.recv(4096).decode(PROTOCOL)
    airspace_feedback = json.loads(feedback_str)
    if verify_sig(airspace_feedback, sam_params):
        logger.info("[SIGNATURE VERIFIED] from SAM")
        if airspace_feedback["outcome"] == "approval":
            logger.info("[PERMISSION GRANTED TO ENTER AIRSPACE]")
        else:
            logger.info("[PERMISSION DENIED TO ENTER AIRSPACE]")
    else:
        logger.info("[SIGNATURE INVALID] from SAM")

def enter_airspace():
    SERVER = socket.gethostbyname(socket.gethostname())
    port_sam = 5050 #SAM's port number
    sam_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sam_socket.connect((SERVER, port_sam)) #Connects to sam_server
    logger.info("[CONNECTED] to SAM server")
    send_apar(sam_socket)

def main():
    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='drone_client.log', level = logging.INFO, encoding='utf-8', filemode='w')
    enter_airspace()


if __name__ == "__main__":
    main()
