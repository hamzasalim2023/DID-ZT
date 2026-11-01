"""Demo runner: executes all test scenarios and reports results."""

import json
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt
from didauth.holder import Holder
from didauth.issuer import Issuer
from didauth.verifier import Verifier


class ScenarioRunner:
    def __init__(self):
        self.results = []
        self.tmp_dir = None
        self.issuer = None
        self.holder = None
        self.verifier = None

    def setup(self):
        if self.tmp_dir:
            self.teardown()
        self.tmp_dir = Path(tempfile.mkdtemp())
        keys_dir = self.tmp_dir / ".didauth"
        keys_dir.mkdir()

        self.issuer = Issuer(keys_dir)
        self.holder = Holder(keys_dir)
        self.verifier = Verifier(keys_dir)

        trust_policy = {
            "EmailVerifiedCredential": [self.issuer.did]
        }
        with open(keys_dir / "trust_policy.json", "w") as f:
            json.dump(trust_policy, f)
        self.verifier._load_trust_policy()

    def teardown(self):
        if self.verifier:
            try:
                self.verifier.close()
            except Exception:
                pass
            self.verifier = None
        if self.issuer:
            try:
                self.issuer.close()
            except Exception:
                pass
            self.issuer = None
        if self.tmp_dir and self.tmp_dir.exists():
            time.sleep(0.3)
            try:
                shutil.rmtree(self.tmp_dir)
            except PermissionError:
                pass
            self.tmp_dir = None

    def run_scenario(self, name: str, expected_reason: str, test_func) -> dict:
        self.setup()
        try:
            actual_reason = test_func()
            passed = actual_reason == expected_reason
        except Exception as e:
            actual_reason = f"ERROR: {e}"
            passed = False
        finally:
            self.teardown()

        result = {
            "scenario": name,
            "expected": expected_reason,
            "actual": actual_reason,
            "passed": passed,
        }
        self.results.append(result)
        return result

    def scenario_a1_valid(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com", "verified": True},
        )
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a2_expired(self) -> str:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        now = datetime.now(timezone.utc)
        exp = now.timestamp() - 100

        vc_payload = {
            "iss": self.issuer.did,
            "sub": self.holder.did,
            "jti": "expired-jti",
            "iat": now.timestamp() - 200,
            "exp": exp,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "EmailVerifiedCredential"],
                "credentialSubject": {"email": "user@example.com"},
            },
        }
        header = {"kid": f"{self.issuer.did}#0", "alg": "EdDSA"}
        vc = jwt.encode(vc_payload, self.issuer.private_key, algorithm="EdDSA", headers=header)

        nonce, aud = self.verifier.issue_nonce()
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a3_revoked(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com", "verified": True},
        )
        vc_payload = jwt.decode(vc, options={"verify_signature": False})
        jti = vc_payload.get("jti")
        self.issuer.revoke_credential(jti)
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a4_untrusted_issuer(self) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        bad_issuer_key = Ed25519PrivateKey.generate()
        bad_issuer_public = bad_issuer_key.public_key()
        bad_issuer_public_bytes = bad_issuer_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        from didauth.did import encode_did_key

        bad_issuer_did = encode_did_key(bad_issuer_public_bytes)

        now = datetime.now(timezone.utc)
        vc_payload = {
            "iss": bad_issuer_did,
            "sub": self.holder.did,
            "jti": "untrusted-jti",
            "iat": now.timestamp(),
            "exp": now.timestamp() + 86400,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "EmailVerifiedCredential"],
                "credentialSubject": {"email": "user@example.com"},
            },
        }
        header = {"kid": f"{bad_issuer_did}#0", "alg": "EdDSA"}
        vc = jwt.encode(vc_payload, bad_issuer_key, algorithm="EdDSA", headers=header)

        nonce, aud = self.verifier.issue_nonce()
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a5_tampered(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com", "verified": True},
        )
        vc_payload = jwt.decode(vc, options={"verify_signature": False})
        vc_payload["vc"]["credentialSubject"]["email"] = "hacker@example.com"
        header = {"kid": f"{self.issuer.did}#0", "alg": "EdDSA"}
        tampered_vc = jwt.encode(vc_payload, self.issuer.private_key, algorithm="EdDSA", headers=header)

        vp = self.holder.build_presentation([tampered_vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a6_holder_mismatch(self) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        other_holder_key = Ed25519PrivateKey.generate()
        other_holder_public = other_holder_key.public_key()
        other_holder_public_bytes = other_holder_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        from didauth.did import encode_did_key

        other_holder_did = encode_did_key(other_holder_public_bytes)

        now = datetime.now(timezone.utc)
        vc_payload = {
            "iss": self.issuer.did,
            "sub": other_holder_did,
            "jti": "mismatch-jti",
            "iat": now.timestamp(),
            "exp": now.timestamp() + 86400,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "EmailVerifiedCredential"],
                "credentialSubject": {"email": "user@example.com"},
            },
        }
        header = {"kid": f"{self.issuer.did}#0", "alg": "EdDSA"}
        vc = jwt.encode(vc_payload, self.issuer.private_key, algorithm="EdDSA", headers=header)

        nonce, aud = self.verifier.issue_nonce()
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a7_replay(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com", "verified": True},
        )
        vp = self.holder.build_presentation([vc], aud, nonce)

        self.verifier.verify_presentation(vp)

        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a8_audience_mismatch(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com", "verified": True},
        )
        vp = self.holder.build_presentation([vc], "did:web:other-verifier.com", nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def scenario_a9_insufficient_claims(self) -> str:
        nonce, aud = self.verifier.issue_nonce()
        vc = self.issuer.issue_credential(
            self.holder.did,
            {"email": "user@example.com"},
        )
        vp = self.holder.build_presentation([vc], aud, nonce)
        granted, reason, _ = self.verifier.verify_presentation(vp)
        return reason

    def run_all(self):
        scenarios = [
            ("A1: Valid VC, valid VP, fresh nonce, trusted issuer", "GRANTED", self.scenario_a1_valid),
            ("A2: Expired credential", "EXPIRED", self.scenario_a2_expired),
            ("A3: Credential revoked after issuance", "REVOKED", self.scenario_a3_revoked),
            ("A4: Issuer not in trust policy", "UNTRUSTED_ISSUER", self.scenario_a4_untrusted_issuer),
            ("A5: Credential payload tampered after signing", "BAD_CREDENTIAL_SIGNATURE", self.scenario_a5_tampered),
            ("A6: Valid VC presented by different holder", "HOLDER_BINDING_FAILED", self.scenario_a6_holder_mismatch),
            ("A7: Same VP submitted twice (replay)", "NONCE_INVALID", self.scenario_a7_replay),
            ("A8: VP built for different verifier", "AUDIENCE_MISMATCH", self.scenario_a8_audience_mismatch),
            ("A9: Resource requires claim credential lacks", "INSUFFICIENT_CLAIMS", self.scenario_a9_insufficient_claims),
        ]

        print("=" * 80)
        print("DID-Based Zero-Trust Authentication - Scenario Test Results")
        print("=" * 80)
        print(f"{'Scenario':<70} {'Expected':<15} {'Actual':<20} {'Result'}")
        print("-" * 80)

        for name, expected, test_func in scenarios:
            result = self.run_scenario(name, expected, test_func)
            status = "PASS" if result["passed"] else "FAIL"
            print(f"{result['scenario']:<70} {result['expected']:<15} {result['actual']:<20} {status}")

        print("-" * 80)
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        print(f"\nTotal: {passed}/{total} scenarios passed")
        print("=" * 80)

        return passed == total


if __name__ == "__main__":
    runner = ScenarioRunner()
    success = runner.run_all()
    exit(0 if success else 1)
