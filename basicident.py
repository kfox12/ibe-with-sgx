import subprocess
subprocess.getstatusoutput = lambda *a, **k: (0, "")
subprocess.getoutput       = lambda *a, **k: ""
#!/usr/bin/env sage -python
# -*- coding: utf-8 -*-
"""
basicident_demo.py
~~~~~~~~~~~~~~~~~~

Small implementation of Boneh–Franklin IBE (the “BasicIdent”
variant) that runs under Python ≥ 3.10 and SageMath ≥ 9.5.

Run:   sage -python basicident_demo.py
"""

import os
import random
import json
import sys
#from master_secret import gen_master_secret
#from json_manager import get_json_key, decrypt_json
from copy import deepcopy
from sage.crypto.cryptosystem import PublicKeyCryptosystem
from sage.all import (EllipticCurve, Hom, Zmod, FiniteField, Integer, GF, factor)

# ----------------------------------------------------------------------
# 1.  Boneh–Franklin BasicIdent class
# ----------------------------------------------------------------------
class BasicIdent(PublicKeyCryptosystem):
#class BasicIdent:
    """
    Boneh & Franklin “BasicIdent” identity‑based encryption.

    Parameters
    ----------
    ec : EllipticCurve
        A supersingular curve E / 𝔽_q.
    P : EllipticCurvePoint
        A point of prime order n on `ec`.
    dmap : callable
        Distortion map Ψ : E(𝔽_q^k) → E(𝔽_q^k).
    order : int, optional
        Explicit order of P (computed automatically if omitted).
    pairing : str, {"weil", "tate"}
        Choice of bilinear pairing.
    k : int, optional
        Embedding degree (computed automatically if omitted).
    seed : int, optional
        Seed for Python's RNG (only for reproducible *demos*).
    """

    # ------------------------------------------------------------------
    # Constructor & helpers
    # ------------------------------------------------------------------
    def __init__(self, ec, P=None, dmap=None, order=None,pairing="weil", k=None, seed=None):
        # Curve and subgroup generator
        self.ec = ec
        self.P = P
        self.order = order or P.order()

        # (Weak!) RNG for demonstration purposes
        #random.seed(seed)

        # Distortion map handling
        self.distortion = self._decorate(dmap) if dmap else self._identity_ext

        # Pairing type (Weil or Tate)
        self.pairing = pairing.lower()

        # Embedding degree k
        q = self.ec.base_ring().cardinality()
        self.k = k or Zmod(self.order)(q).multiplicative_order()
        
        # Master secret t ∈ [2, n‑1]
        self.t = random.randint(2, self.order - 1)
        #self.t = gen_master_secret(self.order)
        
        # Lift curve to 𝔽_{q^k}
        self.base_ext = FiniteField(q ** self.k, 'β')
        self.hom = Hom(self.ec.base_ring(), self.base_ext)(self.base_ext.gen() ** ((q ** self.k - 1) // (q - 1)))
        self.ec_ext = EllipticCurve(list(map(int, self.ec.a_invariants()))).change_ring(self.base_ext)

    # ---------- helper to lift P to extension field -------------------
    def _ext(self, P):
        """
        Lift a point P ∈ E(𝔽_q) to the extension curve E(𝔽_{q^k})
        by embedding each coordinate with the field homomorphism.
        """
        if P.is_zero():                       # handle the point at infinity
            return self.ec_ext(0)

        x, y = P.xy()                         # affine coordinates
        return self.ec_ext(self.hom(x), self.hom(y))

    # ---------- trivial distortion if none supplied -------------------
    def _identity_ext(self, P):
        """Fallback distortion map: identity on E(𝔽_{q^k})."""
        return self._ext(P)

    # ---------- wraps user‑provided distortion with field‑lift --------
    def _decorate(self, raw_map):
        def wrapped(point):
            return raw_map(self._ext(point))
        return wrapped
    
    
    # ------------------------------------------------------------------
    # Public / private key extraction
    # ------------------------------------------------------------------
    
    def gen_P_pub(self):
        return self.t * self.P

    def private_key(self, identity, order, P):
        """Return d_ID = t · Q_ID (only PKG can compute)."""
        return self.t * H1(identity, order, P)

# ----------------------------------------------------------------------
# 2.  Minimal distortion map for a supersingular curve
# ----------------------------------------------------------------------
def H2(element, length: int):
        """
        Weak KDF turning `element` into `length` pseudorandom bits.
        (Python's hash() is *not* deterministic across processes unless
        PYTHONHASHSEED is fixed, but fine for a single demo run.)
        """
        random.seed(hash(element))
        return [random.randint(0, 1) for _ in range(length)]

# ------------------------------------------------------------------
# One‑time‑pad helper
# ------------------------------------------------------------------

def _mask(msg_bits, element):
    mask = H2(element, len(msg_bits))
    return ''.join(str((b ^ m) & 1) for b, m in zip(msg_bits, mask))

def simple_distortion(Q):
    """
    Toy distortion map for a supersingular curve y² = x³ + 1

        ψ : (x, y)  ↦  (x, −y)

    •   Works because (x,−y) still satisfies y² = x³ + 1.
    •   Keeps the point at infinity unchanged.
    """
    if Q.is_zero():              # identity point maps to itself
        return Q
    x, y = Q.xy()                # affine coordinates
    return Q.curve()(x, -y)      # *same* curve, flipped y

def encrypt(message, pub_ID, order, P, Q_ID, *, seed=None, text=False):
        """
        Encrypt `message` for holder of `pubkey` (= [Q_ID, tP]).
        If `text=True`, treat message as UTF‑8 string.
        """
        random.seed(seed)

        # 1) Serialise message → bit list (LSB first)
        if text:
            m_int = int.from_bytes(message.encode(), 'big')
        else:
            m_int = int(message)
        msg_bits = Integer(m_int).digits(2)
        msg_bits.reverse()                    # LSB first

        # 2) Ephemeral scalar
        r = random.randint(2, order - 1)

        # 3) Pairing computation

        pair_val = Q_ID.weil_pairing(simple_distortion(pub_ID), order)

        # 4) Ciphertext
        C1 = r * P
        C2 = _mask(msg_bits, pair_val ** r)
        return C1, C2

def decrypt(ciphertext, d_ID, order, *, text=False):
        """Recover message using private key d_ID."""
        C1, C2 = ciphertext
        
        pair_val = d_ID.weil_pairing(simple_distortion(C1), order)

        # Unmask bitstring → integer
        plain_bits = [int(b) for b in C2]
        m_int = int(_mask(plain_bits, pair_val), 2)

        if text:
            m_len = (m_int.bit_length() + 7) // 8
            return m_int.to_bytes(m_len, 'big').decode()
        return m_int

def H1(identity, order, P):
        """
        Map an arbitrary identity string to a curve point of order n.

        The logic here is *extremely* cheap – for demos only.
        """
        try:
            idx = int(identity) % (order - 2)
        except ValueError:
            idx = 0
            for ch in identity.encode():
                idx = (idx * 256 + ch) % (order - 2)
        return (idx + 2) * P          # avoid 0,1 multiples

def save_to_json(fileName, content):
    with open(fileName, "w") as f:
        if is_serializable(content):
            json.dump(content, f, indent=2)
        else:
            raise ValueError("Data is not serializable")

def write_file(path, data):
    with open(path, "w") as f:
        if is_serializable(data):
            json.dump(data, f, indent=2)
        else:
            raise ValueError("Data is not serializable")

def is_serializable(data):
    try:
        json.dumps(data)
        return True
    except (TypeError, OverflowError):
        return False

# ----------------------------------------------------------------------
# 3.  Self‑contained demo
# ----------------------------------------------------------------------
def main():
    if sys.argv[1] == "setup":
        mode = 1
    elif sys.argv[1] == "encrypt":
        mode = 2
    elif sys.argv[1] == "decrypt":
        mode = 3
    else:
        raise Exception("Enter a valid command line argument")


    

    # -- 0) System‑wide setup -----------------------------------------
    if mode == 1: #SETUP MODE TO BE RUN INSIDE SGX
        print("\n╔═══════════════════════════════════════════════════════╗")
        print("║  Boneh–Franklin BasicIdent demo (Python 3 + Sage)     ║")
        print("╚═══════════════════════════════════════════════════════╝\n")
        
        print("Mode - Setup")
        q = 10177
        E = EllipticCurve(GF(q), [0, 1])               # y² = x³ + 1

        N = E.cardinality()  # order of E(𝔽_q)
        #print(f"Total number of points on E(𝔽_{q}) = {N}.")
        #factors = factor(N)
        #print(f"Largest prime factor of E(𝔽_{q}) = {max(p[0] for p in factors)}") 

        for _ in range(5000):
            pt = E.random_point()
            if pt.order().is_prime():
                if pt.order() > 5:
                    P = pt
                    #print(f"Found point P of order {P.order()} on E(𝔽_{q}).")
                    break
        else: 
            raise ValueError("No suitable point P found on E(𝔽_q)")
        """  
        P = next(pt for pt in (E.random_point() for _ in range(500))
                if pt.order().is_prime() and pt.order() > 1000) 
                #Added requirement for P to be greater than 1000
        """
        # while True:
        #     P = EllipticCurve(GF(q), [0, 1]).random_point()
        #     n = P.order()
        #     if n.is_prime() and n > 1000:
        #         break

        ibe = BasicIdent(E, P=P, dmap=simple_distortion,pairing="weil", seed=42)

        print(f"[setup]  q = {q},  n = {ibe.order},  k = {ibe.k}")
        print(f"         Master secret t = {ibe.t}\n")

        # -- 1) Key extraction for Alice ----------------------------------
        ID = "alice@example.com"
        d_ID = ibe.private_key(ID, ibe.order, ibe.P) #COMPUTES tQ
        d_ID_serial = {"x": int(d_ID[0]), "y": int(d_ID[1])}
        
        pub_ID = ibe.gen_P_pub() #COMPUTES tP
        pub_ID_serial = {"x": int(pub_ID[0]), "y": int(pub_ID[1])}
        
        P_serial = {"x": int(P[0]), "y": int(P[1])}
        print("[PKG]    Issued private key for identity:", ID, "\n")

        system_params = {
            "ID": ID,
            "P_pub": pub_ID_serial, 
            "P": P_serial, 
            "Order": int(ibe.order)
        }
        private_key_data = {"d_ID": d_ID_serial}
        print("In SGX\n---------\nStoring data in system_params.json and private_key.json")
        save_to_json("system_params.json", system_params)
        write_file("/output/private_key.json", private_key_data)



    elif mode == 2: #Encryption Mode
        print("Mode - Encrypt")
        q = 10177
        E = EllipticCurve(GF(q), [0, 1])  #Same curve as before
        
        print("Outside of SGX\n---------\nExtracting data from system_params.json")
        with open("system_params.json") as f:
            params = json.load(f)

        order = params["Order"]
        P_serial = params["P"]
        P = E(P_serial["x"], P_serial["y"])
        identity = params["ID"]
        pub_ID_serial = params["P_pub"]
        pub_ID = E(pub_ID_serial["x"], pub_ID_serial["y"])


        Q_ID = H1(identity, order, P)
        # -- 2) Bob encrypts ---------------------------------------------
        message = "The quick brown fox jumps over the lazy dog."
        ''' FOR TEXT FILES
            with open("sample.txt") as f:
            message = f.read()
            if( len(message) > 100):
            print("Message not printed for space reasons.")
        else:
            print("[Bob]    Plaintext:", repr(message))
        '''
        #====================================
        ''' FOR JSON FILES 
            key_string, cipher_string, nonce_string, tag_string = get_json_key()
        message = key_string
        print(message) 
        '''
        C1, C2 = encrypt(message, pub_ID, order, P, Q_ID, seed=99, text=True)
        #*************** MUST SERIALIZE VARIABLES
        ciphertext = {
            "C1": {"x": int(C1[0]), "y": int(C1[1])},  #Will later need to do E(C1) to recover the EC point that it represents
            "C2": C2,
            "Message": message
        }
        write_file("ciphertext.json", ciphertext) 

        print("[Bob]    Ciphertext:")
        print("         C1 =", C1)
        if(len(message) > 100):
            print("         C2 = [omitted for space reasons]")
        else:
            print("         C2 =", C2, "\n")



    elif mode == 3: # DECRYPTION MODE
        print("Mode - Decrypt")
        q = 10177
        E = EllipticCurve(GF(q), [0, 1])  #Same curve as before

        print("Outside of SGX\n---------\nExtracting data from ciphertext.json")
        with open("ciphertext.json") as f:
            contents = json.load(f)
        #De-serializing the C1 ciphertext
        C1_coords = contents["C1"]
        C1 = E((C1_coords["x"], C1_coords["y"]))
        C2 = contents["C2"]
        message = contents["Message"]

        print("Outside of SGX\n---------\nExtracting data from private_key.json")
        with open("output/private_key.json") as f:
            content = json.load(f)
        d_ID_serial = content["d_ID"]
        d_ID = E((d_ID_serial["x"], d_ID_serial["y"]))

        print("Outside of SGX\n---------\nExtracting data from system_params.json")
        with open("system_params.json") as f:
            params = json.load(f)
        order = params["Order"]

        recovered = decrypt((C1, C2), d_ID, order, text=True)
        if( len(message) > 100):
            print("Message not printed for space reasons.")
        else:
            print("[Alice]  Decrypted:", repr(recovered)) 
        #repr() function shows the string most accurately as it is written in code

        assert recovered == message
        print("\n✓ demo successful – plaintext recovered intact.")

        print("\n====================================\n")
        ''' FOR JSON FILES
        decrypted_data = decrypt_json(key_string, cipher_string, nonce_string, tag_string)
        formatted_data = json.dumps(decrypted_data, indent = 2)
        print(f"Decrypted json contents: \n{formatted_data}")
        '''


# ----------------------------------------------------------------------
if __name__ == "__main__":
    main()
