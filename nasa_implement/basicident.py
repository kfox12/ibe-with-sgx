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
import kga_server as server
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
        self.t = Integer(random.randint(2, self.order - 1))
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

def handle_context(context, ibe, E):
    personal_data = {
        "private_key": None,
        "public_key": None
    }
    if context["is_sending"]: #Needs to encrypt
        ID = context["destination"]
        P = ibe.P
        pub_ID = ibe.gen_P_pub() #COMPUTES tP
        pub_ID_serial = {"x": int(pub_ID[0]), "y": int(pub_ID[1])}
            
        P_serial = {"x": int(P[0]), "y": int(P[1])}
        #print("[PKG]    Issued private key for identity:", ID, "\n")

        '''system_params = {
            "ID": ID,
            "P_pub": pub_ID_serial, 
            "P": P_serial, 
            "Order": int(ibe.order)
        }'''
        Q_ID = H1(ID, ibe.order, ibe.P)
        C1, C2 = encrypt(context["message"], pub_ID, ibe.order, P, Q_ID, seed=99, text=True)
        '''Only if cipher is written to a file
        ciphertext = {
            "C1": {"x": int(C1[0]), "y": int(C1[1])},  #Will later need to do E(C1) to recover the EC point that it represents
            "C2": C2,
            "Message": message
        }'''
        print(f"C1: {C1} \nC2: {C2}")
    return personal_data

def gen_global_params():
    q = 10177
    E = EllipticCurve(GF(q), [0, 1])               # y² = x³ + 1

    N = E.cardinality()  # order of E(𝔽_q)
    
    for _ in range(5000):
        pt = E.random_point()
        if pt.order().is_prime():
            if pt.order() > 5:
                P = pt
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

    return BasicIdent(E, P=P, dmap=simple_distortion,pairing="weil", seed=42)
def gen_EC(q, a, b):
    return EllipticCurve(GF(q), [a, b])# ----------------------------------------------------------------------
