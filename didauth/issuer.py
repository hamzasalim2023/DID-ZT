"""Issuer: signs VCs and manages revocation registry."""

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Issuer:
    def __init__(self, keys_dir: Path):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._load_or_create_keys()
        self._init_revocation_db()

    def _load_or_create_keys(self):
        key_file = self.keys_dir / "issuer_key.pem"
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
        from didauth.did import encode_did_key

        self.did = encode_did_key(public_bytes)
        self.public_key_bytes = public_bytes

    def _init_revocation_db(self):
        db_file = self.keys_dir / "revocations.db"
        self.conn = sqlite3.connect(db_file)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS revoked_jtis (jti TEXT PRIMARY KEY, revoked_at TIMESTAMP)"
        )
        self.conn.commit()

    def issue_credential(self, holder_did: str, claims: dict, lifetime_days: int = 365) -> str:
        jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        exp = now + timedelta(days=lifetime_days)

        vc = {
            "iss": self.did,
            "sub": holder_did,
            "jti": jti,
            "iat": now.timestamp(),
            "exp": exp.timestamp(),
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "EmailVerifiedCredential"],
                "credentialSubject": claims,
            },
        }

        header = {"kid": f"{self.did}#0", "alg": "EdDSA"}
        token = jwt.encode(vc, self.private_key, algorithm="EdDSA", headers=header)
        return token

    def revoke_credential(self, jti: str) -> bool:
        self.conn.execute(
            "INSERT OR REPLACE INTO revoked_jtis (jti, revoked_at) VALUES (?, ?)",
            (jti, datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()
        return True

    def is_revoked(self, jti: str) -> bool:
        cursor = self.conn.execute("SELECT 1 FROM revoked_jtis WHERE jti = ?", (jti,))
        return cursor.fetchone() is not None

    def close(self):
        if self.conn:
            self.conn.close()
