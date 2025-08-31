import hashlib

def kdf_shake256_32(*parts: bytes) -> bytes:
    """Derive a 256-bit key from multiple byte inputs using SHAKE256."""
    shake = hashlib.shake_256()
    for p in parts:
        if p:
            shake.update(p)
    return shake.digest(32)
