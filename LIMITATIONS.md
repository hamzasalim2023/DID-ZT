# Known Limitations and Trade-offs

This document provides an honest assessment of what this implementation **cannot do**, along with architectural limitations, security considerations, and potential improvements for production use.

---

## Scope Limitations (Intentional)

These are features explicitly excluded from the MVP scope, as defined in the PRD:

### 1. No Key Rotation

**Limitation**: Once a DID is generated, the key pair cannot be changed.

**Why**: `did:key` derives the identifier directly from the public key. Changing the key means changing the DID, which breaks all existing credentials.

**Impact**:
- If a private key is compromised, all credentials issued to that DID become insecure
- No way to migrate to stronger cryptographic algorithms in the future
- Keys must be protected with same care as long-lived secrets

**Production alternatives**:
- Use `did:ion` or `did:web` which support key rotation through DID documents
- Implement key delegation (short-lived keys signed by long-term keys)
- Use hardware security modules (HSMs) for key protection

---

### 2. Revocation Requires Central Coordination

**Limitation**: Verifiers must query the issuer's revocation registry (SQLite database).

**Why**: This implementation uses a simple centralized revocation list per issuer.

**Implications**:
- Issuer's database must be accessible to all verifiers
- Verifier cannot verify credentials while offline (for revocation check)
- Single issuer assumption - doesn't scale to federated issuers
- Revocation is not provable (verifier trusts absence in list)

**What this means in practice**:
```
Issuer's revocation DB
        ↓
    ┌───────┐
    │ .db   │ ← All verifiers must access this
    └───────┘
       ↑
    Verifier
```

**Production alternatives**:
- **Accumulator-based revocation**: Cryptographic accumulators provide privacy-preserving revocation checks
- **Status List 2021** (W3C): Bit array of revocation status, published by issuer
- **Blockchain-based registries**: Publicly queryable, but adds infrastructure
- **Validity credentials**: Issue new VCs that attest to validity of other VCs

**Further reading**:
- [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)
- [Hyperledger Indy revocation](https://hyperledger-indy.readthedocs.io/en/latest/concepts/revocation.html)

---

### 3. No Selective Disclosure (P0)

**Limitation**: When presenting a credential, all claims are revealed.

**Example scenario**:
```json
// Credential contains:
{
  "name": "Alice Johnson",
  "age": 28,
  "email": "alice@example.com",
  "address": "123 Main St"
}

// Verifier only needs to know age > 21
// But all fields are revealed in the presentation
```

**Why excluded from P0**: Selective disclosure requires salted claim hashes or zero-knowledge proofs, which significantly increase complexity.

**Planned for P1**: SD-JWT (Selective Disclosure JWT) implementation

**Workaround**: Issue granular credentials (one claim per credential)
```json
// Instead of one credential with all claims:
{"name": "Alice", "age": 28, "email": "..."}

// Issue separate credentials:
VC1: {"claim": "over_21"}
VC2: {"email": "alice@example.com"}  
VC3: {"verified_address": true}
```

**Production implementation approaches**:

1. **SD-JWT** (Recommended):
   - Issuer computes hash of each claim with random salt
   - Signs credential containing claim hashes
   - Holder reveals selected claims + salts
   - Verifier recomputes hashes to verify

2. **BBS+ Signatures**:
   - Allows selective disclosure without pre-salting
   - More complex cryptography
   - Still emerging standard

3. **Zero-Knowledge Proofs**:
   - Prove properties without revealing data (e.g., "age > 21" without revealing exact age)
   - Very complex, performance overhead
   - Use specialized libraries (e.g., zk-SNARKs)

**Further reading**:
- [IETF SD-JWT Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt)
- [BBS+ Signatures](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html)

---

### 4. No Multi-Tenancy

**Limitation**: Single issuer, single verifier per instance.

**Impact**:
- Cannot run multiple issuers from same codebase instance
- Each verifier maintains separate trust policy
- No issuer federation or hierarchical trust

**Production needs**:
- Issuer registry (who is authorized to issue which credential types)
- Namespace management (prevent DID collisions)
- Trust chain verification (issuer of issuers)

---

### 5. No Blockchain Integration

**Limitation**: No anchoring of DIDs or credentials on blockchain.

**Why**: Adds infrastructure complexity and cost without clear benefit for this use case.

**When you might want blockchain**:
- Public audit trail of credential issuance
- Decentralized revocation registry
- Immutable proof of existence timestamp
- Integration with existing blockchain-based identity systems

**Trade-off**: Blockchain adds latency, cost, and complexity. Only use if specific benefits outweigh costs.

---

### 6. No DIDComm Messaging

**Limitation**: No standardized protocol for credential issuance or presentation flows.

**Current state**: Credentials are issued via direct API calls. No wallet-to-wallet communication.

**DIDComm would enable**:
- Standardized credential offer/request protocol
- Peer-to-peer credential exchange
- Encrypted, authenticated messaging between DIDs
- Interoperability with other DID systems

**Production consideration**: Implement DIDComm for interop with mobile wallets and other services.

---

## Security Limitations

### 7. Private Keys Stored in Plaintext

**Limitation**: Private keys are stored as unencrypted PEM files with file permissions as the only protection.

**Risk**: 
- Physical device theft = key compromise
- Malware with elevated privileges = key compromise
- File system backup = key exposure

**File location**: `.didauth/holder_key.pem` and `.didauth/issuer_key.pem`

**Production requirements**:

| Environment | Minimum Protection | Recommended |
|-------------|-------------------|-------------|
| **Development** | File permissions (0600) | Same as MVP |
| **Testing** | OS Keychain (macOS Keychain, Windows Credential Manager) | Encrypted keystore |
| **Production** | Hardware Security Module (HSM) | FIPS 140-2 Level 3 HSM |

**Implementation options**:

1. **OS Keychain** (Medium security):
```python
import keyring
keyring.set_password("didauth", "holder_key", private_key_pem)
private_key_pem = keyring.get_password("didauth", "holder_key")
```

2. **Encrypted Keystore** (Higher security):
```python
from cryptography.fernet import Fernet
# User provides password, derives encryption key
# Encrypt private keys before storage
```

3. **Hardware Security Module** (Highest security):
```python
# Use PKCS#11 interface to HSM
# Private key never leaves hardware
import PyKCS11
session = pkcs11.lib.open_session(slot)
private_key = session.get_key(key_id)
signature = private_key.sign(data)  # Signing happens in hardware
```

4. **TPM (Trusted Platform Module)** (Good for devices):
- Available on most modern computers
- Protects keys even if OS is compromised
- Requires platform-specific integration

**Recommendation**: For any production deployment, at minimum use OS keychain. For high-value credentials, use HSMs.

---

### 8. No Rate Limiting

**Limitation**: No protection against brute-force or DoS attacks.

**Vulnerable endpoints**:
- `GET /challenge`: Can be called unlimited times
- `POST /resource`: Can submit unlimited presentations

**Attack scenarios**:
1. **Nonce exhaustion**: Request millions of nonces to fill database
2. **Verification DoS**: Submit invalid presentations to waste CPU on signature checks
3. **Audit log flooding**: Fill disk with failed attempts

**Production mitigations**:

```python
# 1. Rate limit by IP
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.get("/challenge")
@limiter.limit("10/minute")  # Max 10 nonces per minute per IP
def get_challenge():
    ...

# 2. Rate limit by DID (after parsing VP)
@app.post("/resource")
@limiter.limit("50/hour")  # Max 50 attempts per hour per holder DID
def verify_resource():
    ...

# 3. Exponential backoff for failed attempts
# 4. CAPTCHA for suspicious patterns
# 5. Web Application Firewall (WAF) rules
```

---

### 9. No Protection Against Issuer Key Compromise

**Limitation**: If an issuer's private key is stolen, attacker can issue fake credentials until detected.

**What an attacker with issuer key can do**:
- Issue credentials for any DID
- Forge claims (e.g., false identity verification)
- Cannot revoke legitimately issued credentials (no access to revocation DB)

**Detection is slow**:
- No built-in key compromise detection
- Relies on out-of-band discovery (e.g., fraud reports)
- Credentials remain valid until revoked individually

**Mitigation strategies**:

1. **Short credential lifetimes**: Force frequent re-issuance
   ```python
   issuer.issue_credential(holder_did, claims, lifetime_days=30)  # Not 365
   ```

2. **Credential transparency logs**: Public append-only log of all issued credentials
   ```python
   # Log every issuance to immutable audit trail
   transparency_log.append({"jti": jti, "timestamp": now, "claims_hash": hash(claims)})
   ```

3. **Hardware-bound issuer keys**: Store in HSM, require multi-person auth
   
4. **Key rotation schedule**: Regular rotation even without compromise
   
5. **Anomaly detection**: Monitor for unusual issuance patterns

6. **Issuer attestations**: Issuers periodically publish signed statements confirming their active key

---

### 10. Timing Attack Vulnerability

**Limitation**: Signature verification has data-dependent timing.

**Risk**: Attackers might infer information about signatures from verification time.

**Where**: Ed25519 verification in `cryptography` library

**Mitigation**: The `cryptography` library implements constant-time Ed25519, so this is LOW risk. However, other parts of verification (database lookups, string comparisons) are not constant-time.

**Production hardening**:
```python
# Constant-time string comparison for nonces
import secrets
if not secrets.compare_digest(nonce_from_db, nonce_from_vp):
    return "NONCE_INVALID"
```

---

### 11. No Forward Secrecy

**Limitation**: Compromise of long-term keys exposes all past presentations.

**Why**: Presentations are signed with long-term DID keys, not ephemeral session keys.

**Impact**: If holder's private key is compromised, attacker can prove authenticity of all historical presentations.

**Mitigation**: Implement ephemeral key exchange
```
1. Holder and Verifier establish session key (DH key exchange)
2. Session key used for presentation signature
3. Long-term key signs session key
4. Session key destroyed after verification
```

**Trade-off**: Adds complexity, but provides forward secrecy.

---

## Scalability Limitations

### 12. SQLite Concurrency

**Limitation**: SQLite has limited write concurrency.

**Bottlenecks**:
- Nonce database: One write per `/challenge` request
- Revocation database: One write per credential revocation

**When this becomes a problem**:
- \> 1000 requests/second
- Multiple verifier instances sharing same database

**Production alternatives**:
- PostgreSQL or MySQL for multi-writer support
- Redis for nonce storage (fast, in-memory)
- Separate read replicas for verification
- Sharded databases by DID prefix

**Quick fix for moderate scale**:
```python
# Write-Ahead Logging mode improves concurrency
conn.execute("PRAGMA journal_mode=WAL")
```

---

### 13. Nonce Database Growth

**Limitation**: Nonce database grows unbounded (one row per authentication attempt).

**Growth rate**: 
- 1000 auth/day = 365,000 rows/year
- Each row ~100 bytes = 36 MB/year

**Impact**: 
- Slower queries over time
- Disk space consumption

**Missing**: Automatic cleanup of old nonces

**Production solution**:
```python
# Periodic cleanup job (run daily)
def cleanup_old_nonces():
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    conn.execute(
        "DELETE FROM nonces WHERE issued_at < ? AND used = 1",
        (cutoff.isoformat(),)
    )
```

---

### 14. Audit Log Rotation

**Limitation**: Audit log grows unbounded, never rotates.

**Production needs**:
- Log rotation (daily/weekly)
- Compression of old logs
- Archival to cold storage
- Retention policy enforcement (e.g., delete after 90 days)

**Quick implementation**:
```python
from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler(
    "audit.log",
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=10  # Keep 10 old files
)
```

---

## Feature Limitations

### 15. No Credential Schemas

**Limitation**: No validation that credentials match expected schema.

**Current state**: Verifier trusts any JSON in `credentialSubject`.

**Risk**: Issuer could include unexpected fields, missing fields, or wrong data types.

**Example**:
```json
// Expected
{"email": "user@example.com", "verified": true}

// Actually received
{"emal": "user@example.com", "verified": "yes"}  // Typos, wrong type
```

**Production solution**: Use JSON Schema validation
```python
import jsonschema

EMAIL_CREDENTIAL_SCHEMA = {
    "type": "object",
    "required": ["email", "verified"],
    "properties": {
        "email": {"type": "string", "format": "email"},
        "verified": {"type": "boolean"}
    }
}

jsonschema.validate(claims, EMAIL_CREDENTIAL_SCHEMA)
```

**Better**: Use W3C Credential Schemas
- [W3C JSON Schema Spec](https://www.w3.org/TR/vc-json-schema/)

---

### 16. No Holder Consent Flow

**Limitation**: Holder automatically presents all credentials without explicit consent UI.

**Current flow**:
```python
# Automatically builds presentation with all VCs
vp = holder.build_presentation([vc1, vc2, vc3], aud, nonce)
```

**Production requirement**: User should explicitly approve what to share.

**Proper flow**:
```
1. Verifier requests specific credentials
2. Holder's wallet shows consent screen:
   "example.com is requesting:
    ✓ Your email address
    ✓ Verified status
   
   [Share] [Deny]"
3. User approves
4. Wallet builds and sends presentation
```

---

### 17. No Credential Format Negotiation

**Limitation**: Only supports JWT-VC format.

**Other formats in the wild**:
- JSON-LD with Linked Data Signatures
- AnonCreds (Hyperledger Indy)
- CL Signatures
- Gordian Envelopes

**Production need**: Support format negotiation
```json
// Verifier advertises supported formats
{
  "supported_formats": ["jwt_vc", "ldp_vc", "anoncreds"]
}

// Holder chooses compatible format
```

---

### 18. No Presentation Definition

**Limitation**: Verifier cannot formally specify what credentials it needs.

**Current**: Verifier just accepts any VP and checks claims after parsing.

**Standard**: DIF Presentation Exchange
```json
{
  "presentation_definition": {
    "id": "age_verification",
    "input_descriptors": [{
      "id": "age_credential",
      "constraints": {
        "fields": [{
          "path": ["$.vc.credentialSubject.age"],
          "filter": {"type": "number", "minimum": 21}
        }]
      }
    }]
  }
}
```

**Benefit**: Clear contract between verifier and holder

**Further reading**: [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/)

---

### 19. No Credential Chaining

**Limitation**: Cannot verify credential hierarchies (issuer of issuer).

**Example use case**:
```
Root Authority (Government)
    ↓ issues license to
State DMV (Issuer)
    ↓ issues license to  
Alice (Holder)
```

**Current limitation**: Verifier must directly trust State DMV. Cannot verify that Government trusts DMV.

**Production solution**: Verifiable Authorization

---

### 20. No Biometric Binding

**Limitation**: No binding between credential and holder's biometrics.

**Risk**: Stolen credentials with stolen private key = complete impersonation

**Production enhancement**:
```json
{
  "credentialSubject": {
    "holder_did": "did:key:...",
    "biometric_template_hash": "sha256:...",  // Hash of fingerprint/face
    "requires_biometric": true
  }
}
```

**At verification time**: Require live biometric match before accepting presentation

---

## Operational Limitations

### 21. No Monitoring or Observability

**Missing**:
- Prometheus metrics
- Health check endpoints
- Performance tracing
- Error alerting

**Production needs**:
```python
from prometheus_client import Counter, Histogram

auth_attempts = Counter('auth_attempts_total', 'Total authentication attempts', ['result'])
verification_duration = Histogram('verification_duration_seconds', 'Time to verify')

@verification_duration.time()
def verify_presentation(vp):
    ...
    auth_attempts.labels(result='granted' if granted else reason).inc()
```

---

### 22. No Backup or Disaster Recovery

**Limitation**: No guidance on backing up critical data.

**Critical data**:
- Issuer private key (if lost, cannot issue more credentials)
- Revocation database (if lost, cannot revoke)
- Nonce database (if lost, replay attacks possible)

**Production checklist**:
- ✓ Regular encrypted backups of private keys to offline storage
- ✓ Database replication for high availability
- ✓ Documented recovery procedures
- ✓ Regular recovery drills

---

### 23. No Multi-Region Support

**Limitation**: Single-region deployment assumed.

**Production considerations**:
- Database replication lag (eventual consistency)
- Nonce synchronization across regions
- Revocation propagation delay

---

## Integration Limitations

### 24. No Mobile Wallet Integration

**Limitation**: No protocol for mobile wallet apps to interact with this system.

**Current**: CLI/programmatic use only

**Production needs**:
- Deep links for credential offers (`didauth://offer?issuer=...`)
- QR codes for presentation requests
- Push notifications
- Wallet Connect protocol support

---

### 25. No Legacy System Integration

**Limitation**: Cannot issue credentials based on legacy database identities.

**Common scenario**: 
```
Existing user database (username/password)
    ↓ How to issue DIDs and credentials?
DID-based system
```

**Bridge needed**:
```python
# 1. User logs in with legacy auth
# 2. System generates DID for user
# 3. System issues credential attesting to legacy identity
# 4. User can now use DID for future auth
```

---

## Documentation Limitations

### 26. No Deployment Guide

**Missing**: 
- Infrastructure setup (servers, load balancers)
- Production configuration examples
- Scaling guidelines
- Security hardening checklist

---

### 27. No Threat Model

**Missing**: Formal analysis of attack vectors and mitigations.

**Should document**:
- Attacker capabilities
- Assets to protect
- Attack trees
- Residual risks

---

## Comparison to Production Systems

### What's Missing for Production

| Component | MVP Status | Production Requirement |
|-----------|-----------|----------------------|
| **Key Storage** | Plaintext files | HSM or encrypted keystore |
| **Revocation** | Centralized DB | Distributed accumulator or blockchain |
| **Selective Disclosure** | None | SD-JWT or BBS+ |
| **Rate Limiting** | None | Per-IP and per-DID limits |
| **Monitoring** | Audit log only | Metrics, tracing, alerts |
| **High Availability** | Single instance | Redundant, multi-region |
| **Backup** | None | Automated encrypted backups |
| **Load Balancing** | None | Distributed verifiers |
| **Secret Management** | File system | Vault or cloud KMS |
| **Compliance** | None | SOC 2, GDPR, HIPAA as needed |

---

## Future Enhancement Ideas

### Short-term (< 1 month)
1. Nonce cleanup job
2. Rate limiting middleware
3. Prometheus metrics
4. JSON Schema validation
5. OS keychain integration

### Medium-term (1-3 months)
1. SD-JWT selective disclosure
2. PostgreSQL migration
3. Multi-issuer support
4. Presentation Exchange support
5. Docker deployment

### Long-term (3+ months)
1. HSM integration
2. Accumulator-based revocation
3. DIDComm messaging protocol
4. Mobile wallet protocol
5. BBS+ signatures
6. Zero-knowledge proofs

---

## When NOT to Use This System

This implementation is **not suitable** for:

1. **Production financial systems**: Requires HSM, formal audit, regulatory compliance
2. **Healthcare PHI**: Needs HIPAA compliance, stronger privacy guarantees
3. **Government services**: Requires certified cryptography, formal verification
4. **High-scale public services**: Needs distributed architecture, CDN, DDoS protection
5. **Real money transactions**: Requires multi-factor auth, fraud detection, formal security audit

This implementation **is suitable** for:

1. **Learning and education**: Understand DID/VC concepts hands-on
2. **Prototyping**: Quickly test DID-based auth flows
3. **Internal tools**: Low-scale corporate applications with basic security needs
4. **Research projects**: Baseline for extending with new features
5. **Proof of concept**: Demonstrate feasibility to stakeholders

---

## Getting Help

If you need production-ready decentralized identity:

- **Hyperledger Indy/Aries**: Mature framework with production implementations
- **Microsoft Entra Verified ID**: Managed service for enterprise
- **Trinsic**: Commercial platform with mobile wallets
- **Spruce ID**: Open-source tools for production DIDs
- **Mattr**: Production-grade verifiable credential platform

---

## Acknowledgment of Limitations

This is an educational MVP demonstrating core concepts. The limitations documented here are **intentional trade-offs** for clarity and simplicity. Building production-grade decentralized identity requires addressing these limitations through:

- Formal security review
- Compliance assessment
- Performance testing
- Operational procedures
- 24/7 monitoring and support

**Use responsibly.** Do not deploy this implementation in production without addressing applicable limitations.

---

**Last updated**: 2026-11-01  
**Review frequency**: Update when discovering new limitations or before any production consideration
