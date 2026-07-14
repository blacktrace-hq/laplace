"""SEG 2 -- token verification. THIS FILE SHIPS IN THE GATE. It carries only the
PUBLIC key and validates signature + expiry LOCALLY. No network call, ever --
that is what keeps the air-gap promise intact.

Gate behaviour: verify() returns the payload dict on a valid, unexpired token,
or None. A None result means the gate runs base-pack-only (free) mode; a valid
token unlocks the buyer's custom rules.
"""
import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Filled at deploy from `python3 -m license.keygen`. The private counterpart never ships.
PUBLIC_KEY_HEX = "5a62b7872fd9d517df5d28261aa6d234e39b88af8302bb2c9ed18b29ef35d9cd"


def _b64u_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify(token, public_key_hex=None, now=None):
    """Return the payload dict if the token is well-formed, correctly signed by
    the embedded public key, and unexpired. Otherwise None. Never raises on a bad
    token, never touches the network."""
    pk_hex = public_key_hex if public_key_hex is not None else PUBLIC_KEY_HEX
    if not pk_hex:
        return None
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        pub.verify(sig, body)                      # raises InvalidSignature on tamper
        payload = json.loads(body)
    except (ValueError, InvalidSignature, KeyError):
        return None
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    if (now if now is not None else time.time()) >= exp:
        return None
    return payload
