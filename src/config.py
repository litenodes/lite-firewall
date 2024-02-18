import base64
import os
import hashlib

LS_PORT: int = int(os.environ.get('LS_PORT'))
LS_PUB_KEY_B64: str = os.environ.get('LS_PUB_KEY')
LS_PUB_KEY: bytes = base64.b64decode(LS_PUB_KEY_B64)
LITE_BACK_PORT: str = os.environ.get('LITE_BACK_PORT')
RPS_LIMIT = os.environ.get('RPS_LIMIT', 150)

SERVER_KEY_ID = hashlib.sha256(b'\xc6\xb4\x13\x48' + LS_PUB_KEY).digest()
