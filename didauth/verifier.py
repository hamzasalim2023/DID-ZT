"""Verifier: HTTP service for zero-trust credential verification."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from didauth.did import decode_did_key

app = FastAPI()


class ChallengeResponse(BaseModel):
    nonce: str
    aud: str


class ResourceResponse(BaseModel):
    presentation: str
    required_claims: Optional[list[str]] = None


class Verifier:
    NONCE_EXPIRY_SECONDS = 300

    def __init__(self, keys_dir: Path):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._init_nonce_db()
        self._init_audit_log()
        self._load_trust_policy()

    def _init_nonce_db(self):
        db_file = self.keys_dir / "nonces.db"
        self.nonce_conn = sqlite3.connect(db_file)
        self.nonce_conn.execute(
            "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, issued_at TIMESTAMP, used INTEGER)"
        )
        self.nonce_conn.execute(
            "CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, used_at TIMESTAMP)"
        )
        self.nonce_conn.commit()

    def _init_audit_log(self):
        self.audit_log = self.keys_dir / "audit.log"

    def _load_trust_policy(self):
        policy_file = self.keys_dir / "trust_policy.json"
        if policy_file.exists():
            with open(policy_file) as f:
                self.trust_policy = json.load(f)
        else:
            self.trust_policy = {
                "EmailVerifiedCredential": ["did:key:z0123456789abcdef"]
            }

    def issue_nonce(self) -> tuple[str, str]:
        import secrets

        nonce = secrets.token_hex(16)
        aud = "did:web:verifier.example.com"
        now = datetime.now(timezone.utc).isoformat()
        self.nonce_conn.execute(
            "INSERT INTO nonces (nonce, issued_at, used) VALUES (?, ?, 0)",
            (nonce, now),
        )
        self.nonce_conn.commit()
        return nonce, aud

    def verify_nonce(self, nonce: str) -> Optional[str]:
        cursor = self.nonce_conn.execute(
            "SELECT issued_at, used FROM nonces WHERE nonce = ?", (nonce,)
        )
        row = cursor.fetchone()
        if not row:
            return "NONCE_INVALID"
        issued_at, used = row
        if used:
            return "NONCE_INVALID"
        issued_dt = datetime.fromisoformat(issued_at)
        now = datetime.now(timezone.utc)
        if (now - issued_dt).total_seconds() > self.NONCE_EXPIRY_SECONDS:
            self.nonce_conn.execute("DELETE FROM nonces WHERE nonce = ?", (nonce,))
            self.nonce_conn.commit()
            return "NONCE_INVALID"
        self.nonce_conn.execute(
            "UPDATE nonces SET used = 1 WHERE nonce = ?", (nonce,)
        )
        self.nonce_conn.execute(
            "INSERT OR REPLACE INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            (nonce, datetime.now(timezone.utc).isoformat()),
        )
        self.nonce_conn.commit()
        return None

    def _public_key_to_pem(self, public_key_bytes: bytes) -> bytes:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def verify_presentation(self, vp_token: str) -> tuple[bool, str, Optional[dict]]:
        try:
            vp_payload = jwt.decode(
                vp_token, options={"verify_signature": False}, algorithms=["EdDSA"]
            )
        except Exception:
            self._log_audit("MALFORMED", vp_token)
            return False, "MALFORMED", None

        if not self._validate_required_vp_fields(vp_payload):
            self._log_audit("MALFORMED", vp_token)
            return False, "MALFORMED", None

        nonce = vp_payload.get("nonce")
        aud = vp_payload.get("aud")

        nonce_error = self.verify_nonce(nonce)
        if nonce_error:
            self._log_audit(nonce_error, vp_token)
            return False, nonce_error, None

        if aud != "did:web:verifier.example.com":
            self._log_audit("AUDIENCE_MISMATCH", vp_token)
            return False, "AUDIENCE_MISMATCH", None

        holder_did = vp_payload.get("iss")
        try:
            holder_key = decode_did_key(holder_did)
            holder_key_pem = self._public_key_to_pem(holder_key)
        except Exception:
            self._log_audit("BAD_PRESENTATION_SIGNATURE", vp_token)
            return False, "BAD_PRESENTATION_SIGNATURE", None

        try:
            jwt.decode(vp_token, holder_key_pem, algorithms=["EdDSA"], options={"verify_aud": False})
        except Exception:
            self._log_audit("BAD_PRESENTATION_SIGNATURE", vp_token)
            return False, "BAD_PRESENTATION_SIGNATURE", None

        vcs = vp_payload.get("vp", {}).get("verifiableCredential", [])
        if not vcs:
            self._log_audit("BAD_CREDENTIAL_SIGNATURE", vp_token)
            return False, "BAD_CREDENTIAL_SIGNATURE", None

        all_claims = {}
        for vc_token in vcs:
            vc_result = self._verify_credential(vc_token, holder_did)
            if not vc_result[0]:
                return vc_result
            vc_claims = vc_result[2]
            all_claims.update(vc_claims)

        now = datetime.now(timezone.utc)
        exp = vp_payload.get("exp", 0)
        if now.timestamp() > exp:
            self._log_audit("EXPIRED", vp_token)
            return False, "EXPIRED", None

        for vc_token in vcs:
            try:
                vc_payload = jwt.decode(vc_token, options={"verify_signature": False})
                jti = vc_payload.get("jti")
                if self._is_revoked(jti):
                    self._log_audit("REVOKED", vp_token)
                    return False, "REVOKED", None
            except Exception:
                pass

        for vc_token in vcs:
            try:
                vc_payload = jwt.decode(vc_token, options={"verify_signature": False})
                issuer_did = vc_payload.get("iss")
                claim_type = vc_payload.get("vc", {}).get("type", [])
                if not self._is_trusted_issuer(issuer_did, claim_type):
                    self._log_audit("UNTRUSTED_ISSUER", vp_token)
                    return False, "UNTRUSTED_ISSUER", None
            except Exception:
                pass

        if not self._has_required_claims(all_claims):
            self._log_audit("INSUFFICIENT_CLAIMS", vp_token)
            return False, "INSUFFICIENT_CLAIMS", None

        self._log_audit("GRANTED", vp_token)
        return True, "GRANTED", all_claims

    def _validate_required_vp_fields(self, vp: dict) -> bool:
        required = ["iss", "aud", "nonce", "iat", "exp", "vp"]
        return all(k in vp for k in required)

    def _verify_credential(self, vc_token: str, holder_did: str) -> tuple[bool, str, Optional[dict]]:
        try:
            vc_payload = jwt.decode(
                vc_token, options={"verify_signature": False}, algorithms=["EdDSA"]
            )
        except Exception:
            return False, "BAD_CREDENTIAL_SIGNATURE", None

        issuer_did = vc_payload.get("iss")
        try:
            issuer_key = decode_did_key(issuer_did)
            issuer_key_pem = self._public_key_to_pem(issuer_key)
        except Exception:
            return False, "BAD_CREDENTIAL_SIGNATURE", None

        try:
            jwt.decode(vc_token, issuer_key_pem, algorithms=["EdDSA"], options={"verify_aud": False})
        except Exception:
            return False, "BAD_CREDENTIAL_SIGNATURE", None

        if vc_payload.get("sub") != holder_did:
            return False, "HOLDER_BINDING_FAILED", None

        now = datetime.now(timezone.utc)
        exp = vc_payload.get("exp", 0)
        if now.timestamp() > exp:
            return False, "EXPIRED", None

        claims = vc_payload.get("vc", {}).get("credentialSubject", {})
        return True, "VALID", claims

    def _is_revoked(self, jti: str) -> bool:
        revoked_dir = self.keys_dir.parent / ".didauth"
        revocation_db = revoked_dir / "revocations.db"
        if not revocation_db.exists():
            return False
        try:
            conn = sqlite3.connect(revocation_db)
            cursor = conn.execute("SELECT 1 FROM revoked_jtis WHERE jti = ?", (jti,))
            result = cursor.fetchone() is not None
            conn.close()
            return result
        except Exception:
            return False

    def _is_trusted_issuer(self, issuer_did: str, claim_types: list) -> bool:
        for claim_type in claim_types:
            allowed = self.trust_policy.get(claim_type, [])
            if issuer_did in allowed:
                return True
        return False

    def _has_required_claims(self, claims: dict) -> bool:
        return bool(claims)

    def _log_audit(self, reason: str, token: str):
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(self.audit_log, "a") as f:
            f.write(f"{timestamp} {reason}\n")

    def close(self):
        if self.nonce_conn:
            self.nonce_conn.close()


verifier = None


@app.on_event("startup")
def startup_event():
    global verifier
    keys_dir = Path(".didauth")
    verifier = Verifier(keys_dir)


@app.get("/challenge", response_model=ChallengeResponse)
def get_challenge():
    nonce, aud = verifier.issue_nonce()
    return ChallengeResponse(nonce=nonce, aud=aud)


@app.post("/resource")
def verify_resource(req: ResourceResponse):
    granted, reason, claims = verifier.verify_presentation(req.presentation)
    if granted:
        return {"granted": True, "reason": reason, "claims": claims}
    raise HTTPException(status_code=403, detail={"reason": reason})
