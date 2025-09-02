import base64
from functools import lru_cache
from pathlib import Path
from pqcrypto.sign.sphincs_sha2_256f_simple import (
    generate_keypair,
    sign as spx_sign,
    verify as spx_verify,
)

# SPHINCS+-SHA2-256f-simple (Level 5)
EXPECTED_PK_LEN = 64
EXPECTED_SK_LEN = 128

# Store keys next to this module to avoid CWD surprises
KEY_DIR = Path(__file__).resolve().parent / ".keys"
KEY_DIR.mkdir(exist_ok=True)
PK_PATH = KEY_DIR / "spx_pk.txt"
SK_PATH = KEY_DIR / "spx_sk.txt"

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _load_keys_from_disk():
    pk_b64 = PK_PATH.read_text().strip()
    sk_b64 = SK_PATH.read_text().strip()
    pk = b64d(pk_b64)
    sk = b64d(sk_b64)
    return pk, sk

def _save_keys_to_disk(pk: bytes, sk: bytes):
    PK_PATH.write_text(b64e(pk))
    SK_PATH.write_text(b64e(sk))

def _valid_lengths(pk: bytes, sk: bytes) -> bool:
    return len(pk) == EXPECTED_PK_LEN and len(sk) == EXPECTED_SK_LEN

@lru_cache(maxsize=1)
def get_or_create_keys():
    # Load if present and valid; otherwise generate fresh and persist.
    try:
        pk, sk = _load_keys_from_disk()
        if not _valid_lengths(pk, sk):
            raise ValueError("Invalid key lengths on disk")
    except Exception:
        pk, sk = generate_keypair()
        _save_keys_to_disk(pk, sk)
    return pk, sk

def sign(message: bytes) -> dict:
    pk, sk = get_or_create_keys()
    # Enforce clean bytes and expected lengths
    pk = bytes(pk)
    sk = bytes(sk)
    if not _valid_lengths(pk, sk):
        pk, sk = generate_keypair()
        _save_keys_to_disk(pk, sk)

    # Call with explicit keywords to avoid arg-order confusion
    signature = spx_sign(message=message, secret_key=sk)
    return {
        "alg": "SPHINCS+-SHA256-256f-simple",
        "signature": b64e(signature),
        "public_key": b64e(pk),
    }

def verify(message: bytes, signature_b64: str, public_key_b64: str) -> dict:
    try:
        spx_verify(
            message=message,
            signature=b64d(signature_b64),
            public_key=b64d(public_key_b64),
        )
        return {"valid": True}
    except Exception:
        return {"valid": False}
