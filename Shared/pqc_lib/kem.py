import base64
from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as kyber_keypair,
    encrypt as kyber_encap,
    decrypt as kyber_decap,
)
from pqcrypto.kem.hqc_256 import (
    generate_keypair as hqc_keypair,
    encrypt as hqc_encap,
    decrypt as hqc_decap,
)
from . import store, kdf


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def init_handshake():
    # Generate keypairs
    kyb_pk, kyb_sk = kyber_keypair()  # pk=1184 bytes, sk=2400 bytes
    hqc_pk, hqc_sk = hqc_keypair()

    # Store raw secret keys in session
    sess = store.new_session()
    sess.kyber_sk = kyb_sk
    sess.hqc_sk = hqc_sk

    # Return public keys (base64) to client
    return {
        "session_id": sess.id,
        "kyber_pk": b64e(kyb_pk),
        "hqc_pk": b64e(hqc_pk),
        "alg": {"kyber": "kyber768", "hqc": "hqc256"},
    }


def complete_handshake(session_id: str, kyber_ct_b64: str, hqc_ct_b64: str, context: bytes):
    sess = store.get_session(session_id)
    if not sess:
        raise ValueError("Session not found or expired")

    kyb_sk = sess.kyber_sk
    hqc_sk = sess.hqc_sk

    if not isinstance(kyb_sk, bytes) or len(kyb_sk) != 2400:
        raise ValueError("'secret_key' must be of length '2400'")
    if not isinstance(hqc_sk, bytes):
        raise ValueError("Invalid HQC secret key")

    # Decode ciphertexts
    kyber_ct = b64d(kyber_ct_b64)
    hqc_ct = b64d(hqc_ct_b64)

    # Decapsulate (secret_key, ciphertext)
    s1 = kyber_decap(kyb_sk, kyber_ct)
    s2 = hqc_decap(hqc_sk, hqc_ct)

    # Derive and store final session key
    shared_key = kdf.kdf_shake256_32(s1, s2, context)
    store.set_session_key(session_id, shared_key)

    return {"ok": True}
