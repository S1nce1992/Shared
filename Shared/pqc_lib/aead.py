import base64
from typing import Optional
from nacl.utils import random as nacl_random
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as aead_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt as aead_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES as KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as NPUBBYTES,
)
from .store import get_session

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

def encrypt(session_id: str, plaintext: bytes, aad: Optional[bytes] = None) -> dict:
    sess = get_session(session_id)
    if not sess or not sess.session_key or len(sess.session_key) != KEYBYTES:
        raise ValueError("No established session key")
    nonce = nacl_random(NPUBBYTES)
    ct = aead_encrypt(plaintext, aad or b"", nonce, sess.session_key)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ct)}

def decrypt(session_id: str, nonce_b64: str, ciphertext_b64: str, aad: Optional[bytes] = None) -> dict:
    sess = get_session(session_id)
    if not sess or not sess.session_key or len(sess.session_key) != KEYBYTES:
        raise ValueError("No established session key")
    pt = aead_decrypt(b64d(ciphertext_b64), aad or b"", b64d(nonce_b64), sess.session_key)
    return {"plaintext": b64e(pt)}
