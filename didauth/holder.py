"""Holder: generates keypair, builds VPs."""

import json
from datetime import datetime, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from didauth.did import encode_did_key


class Holder:
    def __init__(self, keys_dir: Path):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._load_or_create_keys()

    def _load_or_create_keys(self):
        key_file = self.keys_dir / "holder_key.pem"
        if key_file.exists():
            with open(key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            private_key = Ed25519PrivateKey.generate()
            with open(key_file, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            key_file.chmod(0o600)
        self.private_key = private_key
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.did = encode_did_key(public_bytes)
        self.public_key_bytes = public_bytes

    def build_presentation(self, vcs: list[str], verifier_aud: str, nonce: str) -> str:
        now = datetime.now(timezone.utc)
        exp = now.timestamp() + 300

        vp = {
            "iss": self.did,
            "aud": verifier_aud,
            "nonce": nonce,
            "iat": now.timestamp(),
            "exp": exp,
            "vp": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": vcs,
            },
        }

        header = {"kid": f"{self.did}#0", "alg": "EdDSA"}
        token = jwt.encode(vp, self.private_key, algorithm="EdDSA", headers=header)
        return token
