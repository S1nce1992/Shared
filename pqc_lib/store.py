import time, secrets
from typing import Dict, Optional

class Session:
    def __init__(self, session_id: str):
        self.id = session_id
        self.created = int(time.time())
        self.expires = self.created + 3600  # 1h TTL
        self.kyber_sk: Optional[bytes] = None
        self.hqc_sk: Optional[bytes] = None
        self.session_key: Optional[bytes] = None

_sessions: Dict[str, Session] = {}

def new_session() -> Session:
    sid = secrets.token_urlsafe(16)
    s = Session(sid)
    _sessions[sid] = s
    return s

def get_session(sid: str) -> Optional[Session]:
    s = _sessions.get(sid)
    if s and s.expires > time.time():
        return s
    if s:
        _sessions.pop(sid, None)
    return None

def set_session_key(sid: str, key: bytes):
    s = get_session(sid)
    if not s:
        raise ValueError("Invalid or expired session")
    s.session_key = key
