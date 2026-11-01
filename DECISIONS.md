# Design Decisions and Rationale

This document records every significant design decision made during implementation, including the reasoning behind each choice and alternatives that were considered.

---

## 1. DID Method Selection

**Decision**: Use `did:key` with Ed25519 (multicodec `0xed01`, multibase `z` base58btc)

**Rationale**:
- **Fully offline**: No network calls needed to resolve DIDs
- **Simplest to implement correctly**: DID is deterministically derived from public key
- **Standards-aligned**: Follows W3C DID specification and multicodec standards
- **Immediate verification**: Public key extraction is a simple decode operation

**Alternatives considered**:
- `did:web`: Requires DNS and HTTPS infrastructure, introduces network dependency
- `did:ion`: More features but requires running/querying a blockchain node
- `did:ethr`: Ethereum-based, requires blockchain infrastructure

**Trade-offs**:
- ✓ Simplicity and offline operation
- ✗ No key rotation capability (accepted for MVP)
- ✗ No service endpoints (not needed for this use case)

---

## 2. Credential Format

**Decision**: JWT-VC (JWT-based Verifiable Credentials) with EdDSA signatures

**Rationale**:
- **Standard JWT tooling**: Leverage mature `PyJWT` library
- **Compact**: Smaller than JSON-LD credentials
- **Easy to inspect**: Base64-encoded JSON is human-readable
- **Well-defined**: W3C VC specification provides clear structure

**Alternatives considered**:
- JSON-LD with linked data signatures: More flexible but complex, requires JSON-LD processor
- Raw JWS: Less structure, harder to validate schema

**Trade-offs**:
- ✓ Developer familiarity with JWT
- ✓ Easy debugging (can decode with jwt.io)
- ✗ Less semantic richness than JSON-LD (acceptable for MVP)

**JWT Structure chosen**:
```json
{
  "iss": "did:key:...",  // Issuer DID
  "sub": "did:key:...",  // Holder DID  
  "jti": "uuid",         // Unique ID for revocation
  "iat": 1730419200,     // Issued timestamp
  "exp": 1761955200,     // Expiration timestamp
  "vc": {                // W3C VC structure
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "EmailVerifiedCredential"],
    "credentialSubject": { /* claims */ }
  }
}
```

---

## 3. Presentation Format

**Decision**: JWT-VP (JWT-based Verifiable Presentations) signed by holder

**Rationale**:
- **Proves holder control**: VP signature demonstrates possession of private key
- **Replay protection**: Binds nonce and audience into the signed payload
- **Consistent format**: Same JWT tooling as VCs

**Key fields**:
```json
{
  "iss": "did:key:...",           // Holder DID
  "aud": "did:web:verifier...",   // Verifier identifier
  "nonce": "challenge",           // Single-use challenge
  "iat": 1730419200,              // Presentation timestamp
  "exp": 1730419500,              // Short expiry (5 min)
  "vp": {
    "type": ["VerifiablePresentation"],
    "verifiableCredential": ["<VC-JWT>"]
  }
}
```

**Why embed full VCs**: Allows verifier to check VC signatures without network calls

---

## 4. Replay Protection Mechanism

**Decision**: Verifier-issued single-use nonces with 5-minute expiration, bound into VP

**Rationale**:
- **Simple and effective**: Cryptographically binds VP to a specific request
- **Time-bounded**: Nonces expire after 5 minutes to limit attack window
- **Stateful nonce tracking**: SQLite database marks nonces as used

**Implementation details**:
- Nonces are 32-character hex strings (128 bits of entropy)
- Stored in SQLite with `(nonce, issued_at, used)` columns
- Mark as used immediately upon first verification
- Cleanup of expired nonces happens lazily during verification

**Alternatives considered**:
- Timestamp-only (no nonce): Vulnerable to replay within time window
- Long-lived nonces: Increases attack surface
- Distributed nonce coordination: Too complex for single-verifier MVP

**Trade-offs**:
- ✓ Strong replay protection
- ✓ Simple to implement
- ✗ Requires verifier state (acceptable for this architecture)

---

## 5. Audience Binding

**Decision**: Verifier identifier (`did:web:verifier.example.com`) bound into VP

**Rationale**:
- **Prevents credential redirection**: VP captured from one verifier can't be used on another
- **Explicit intent**: Holder explicitly targets specific verifier
- **Standard JWT field**: Uses standard `aud` claim

**Why `did:web`**: 
- Represents real-world verifier services with DNS-based identity
- Easier to understand than abstract identifiers
- Could be resolved to actual service endpoints in production

---

## 6. Revocation Strategy

**Decision**: Issuer-maintained SQLite registry keyed by credential `jti`

**Rationale**:
- **Minimal viable revocation**: Simple to implement and query
- **Immediate effect**: Revoked credentials rejected on next verification
- **No credential modification**: Credentials themselves don't change

**Implementation**:
```sql
CREATE TABLE revoked_jtis (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMP
)
```

**Verifier check process**:
1. Extract `jti` from each credential
2. Query issuer's revocation registry (SQLite file)
3. Reject if `jti` is found

**Alternatives considered**:
- **Accumulator-based revocation**: More private but complex
- **Blockchain-based registry**: Adds infrastructure dependency
- **Revocation list credentials**: Requires additional VC infrastructure
- **Status List 2021**: W3C standard but overkill for MVP

**Known limitations** (documented in LIMITATIONS.md):
- Requires verifier to access issuer's revocation database
- Single issuer assumption (would need federation for multiple issuers)
- No proof of non-revocation (verifier must trust absence in list)

---

## 7. Trust Policy Model

**Decision**: Verifier config file mapping claim type → allowed issuer DIDs

**Rationale**:
- **Explicit trust anchoring**: Verifier declares which issuers it trusts
- **Flexible per-claim-type**: Different issuers for different credential types
- **Runtime configurable**: Can update trust without code changes

**Format** (`trust_policy.json`):
```json
{
  "EmailVerifiedCredential": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "GovernmentIDCredential": [
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
  ]
}
```

**Why claim-type-specific**: 
- More granular than trusting an issuer for everything
- Reflects real-world trust relationships (you trust DMV for licenses, not emails)

**Alternatives considered**:
- Global issuer whitelist: Too coarse-grained
- Verifiable issuer registry: Adds coordination complexity
- Web of trust: Too complex for MVP

---

## 8. Verification Order

**Decision**: 10-step verification chain (see README), fail on first error

**Rationale**:
- **Security-first ordering**: Check structural validity before expensive operations
- **Clear error reporting**: Each step has specific failure code
- **Performance optimization**: Cheap checks first (parsing, nonce lookup) before crypto

**Order rationale**:
1. **Parse/structure**: Reject garbage input immediately
2. **Nonce**: Cheap database lookup, catches replays early
3. **Audience**: Simple string comparison
4. **VP signature**: Proves holder identity (before checking credentials)
5. **VC signature**: Validates credential authenticity
6. **Holder binding**: Ensures credential belongs to presenter
7. **Expiration**: Time-based check
8. **Revocation**: Database lookup
9. **Trust policy**: Business logic check
10. **Required claims**: Final authorization check

**Why this order**: 
- Fail fast on obvious attacks (malformed, replay)
- Verify cryptographic proofs before business logic
- Separate authentication (who are you?) from authorization (what can you access?)

---

## 9. Private Key Storage

**Decision**: PEM-encoded files with 0600 permissions in `.didauth/` directory

**Rationale**:
- **Standard format**: PEM is widely supported (openssl, cryptography library)
- **Secure permissions**: 0600 = read/write for owner only
- **Simple management**: One file per key, clear naming

**File structure**:
```
.didauth/
├── holder_key.pem    # User's private key
└── issuer_key.pem    # Issuer's private key
```

**Security measures**:
- `.didauth/` excluded in `.gitignore`
- Files created with restrictive permissions immediately
- No key material in logs or API responses

**Alternatives considered**:
- OS keychain integration: Platform-specific, complex
- Hardware security modules: Overkill for MVP
- Encrypted keystores: Adds password management complexity

**Known limitation**: 
- Keys stored in plaintext on disk (acceptable for demo)
- Production should use hardware keys or encrypted storage

---

## 10. Programming Language and Framework

**Decision**: Python 3.11+ with FastAPI for HTTP server

**Rationale**:
- **Python 3.11+**: 
  - Modern type hints (e.g., `tuple[bool, str, dict]`)
  - Better performance than 3.10
  - `tomllib` for future config parsing
  
- **FastAPI**:
  - Modern async framework
  - Automatic API documentation (OpenAPI)
  - Pydantic for request/response validation
  - Easy to understand for demos

**Alternatives considered**:
- Flask: More traditional but less modern
- Django: Too heavy for this use case
- aiohttp: Lower-level, more boilerplate

**Libraries chosen**:
- `cryptography`: Industry-standard crypto library, no hand-rolled crypto
- `PyJWT`: Standard JWT library with EdDSA support
- `sqlite3`: Built-in, sufficient for MVP persistence

---

## 11. Cryptographic Algorithm Selection

**Decision**: Ed25519 (EdDSA) for all signatures

**Rationale**:
- **Security**: 128-bit security level, equivalent to 3072-bit RSA
- **Performance**: Fast signing and verification
- **Compact**: 32-byte keys, 64-byte signatures
- **Deterministic**: Same message always produces same signature
- **Well-supported**: In `cryptography` library and JWT standards

**Why not RSA**:
- Larger key sizes (2048+ bits)
- Slower operations
- More complex parameter management

**Why not ECDSA (P-256)**:
- Non-deterministic (requires good RNG)
- More complex implementation
- Ed25519 is simpler and faster

---

## 12. Demo and Testing Approach

**Decision**: Runnable demo script (`python -m didauth.demo`) with 9 acceptance scenarios

**Rationale**:
- **Self-contained**: Demonstrates all features in one command
- **Clear pass/fail**: Table output shows which scenarios work
- **Test-driven**: Implements all acceptance tests from PRD
- **Educational**: Each scenario has descriptive name and expected outcome

**Why not pytest-only**:
- Demo is more accessible to non-developers
- Shows real-world flow (setup → issue → present → verify)
- Can be run in CI or manually

**Scenario coverage**:
- 1 happy path (everything works)
- 8 failure modes (each security check)

---

## 13. Audit Logging Strategy

**Decision**: Simple append-only text log with timestamp and reason code

**Format**:
```
2026-11-01T03:08:54.731Z GRANTED
2026-11-01T03:09:12.445Z NONCE_INVALID
```

**Rationale**:
- **Simple**: Easy to parse and grep
- **Tamper-evident**: Append-only, no overwrites
- **Minimal**: Just timestamp and outcome
- **Privacy-conscious**: No credential content, just verification result

**Alternatives considered**:
- Structured JSON logs: More complex to write, harder to read manually
- Syslog integration: Adds dependency
- Database logging: Overkill for MVP

**Future enhancement**:
- Add request ID for correlation
- Include DID (but not full credential)
- Rotate logs by size/date

---

## 14. Error Handling Philosophy

**Decision**: Fail closed - any error results in denial, never a grant

**Rationale**:
- **Security-first**: Unknown states should deny access
- **Clear errors**: Each failure has specific reason code
- **No silent failures**: Every path logs to audit

**Implementation**:
```python
try:
    jwt.decode(vp_token, holder_key_pem, algorithms=["EdDSA"])
except Exception:  # Catch-all for any JWT error
    self._log_audit("BAD_PRESENTATION_SIGNATURE", vp_token)
    return False, "BAD_PRESENTATION_SIGNATURE", None
```

**Why broad exception handling**:
- JWT library could raise various exceptions (expired, invalid signature, malformed)
- We don't want to leak internal errors to attackers
- All JWT failures are effectively signature failures from verifier's perspective

---

## 15. HTTP API Design

**Decision**: Two endpoints - GET `/challenge` and POST `/resource`

**Rationale**:
- **Minimal surface**: Only what's needed for the auth flow
- **RESTful**: GET for read-only, POST for mutation (using nonce)
- **Standard HTTP codes**: 200 for success, 403 for auth failure

**Why not more endpoints**:
- No credential issuance endpoint (out of scope - issuers are separate services)
- No DID resolution endpoint (did:key is self-resolving)
- No revocation endpoint (issuer-only operation)

**Response design**:
```json
// Success
{"granted": true, "reason": "GRANTED", "claims": {...}}

// Failure  
{"reason": "EXPIRED"}  // 403 status
```

**Why include reason in success**: Consistency and logging

---

## 16. Credential Lifetime

**Decision**: Default 365 days, configurable per credential

**Rationale**:
- **Balance security and UX**: Long enough to be useful, short enough to limit exposure
- **Per-credential flexibility**: Different claim types may need different lifetimes
- **Standard practice**: Similar to certificate validity periods

**Examples**:
- Email verification: 365 days (people don't change email often)
- Government ID: 1825 days (5 years, like real licenses)
- One-time proof: 1 day

---

## 17. Nonce Expiration

**Decision**: 5-minute expiration for nonces

**Rationale**:
- **Long enough**: Allows for network latency and user interaction
- **Short enough**: Limits replay attack window
- **Standard practice**: Similar to OAuth state parameter TTL

**User flow assumption**:
1. Client requests nonce (< 1 second)
2. User reviews and approves presentation (< 4 minutes)
3. Client submits presentation (< 1 second)

**Why not longer**: Increases replay risk
**Why not shorter**: May cause legitimate requests to fail

---

## 18. Presentation Expiration

**Decision**: 5 minutes from creation (matches nonce lifetime)

**Rationale**:
- **Consistent with nonce**: Both expire together
- **Prevents stockpiling**: Old presentations can't be reused
- **Clear user expectation**: Presentations are meant for immediate use

**In JWT**:
```json
{
  "iat": 1730419200,
  "exp": 1730419500  // iat + 300 seconds
}
```

---

## 19. Python Package Structure

**Decision**: Single package `didauth` with no nested packages

**Rationale**:
- **Simple imports**: `from didauth.holder import Holder`
- **Clear separation**: Each role (holder, issuer, verifier) is one module
- **No deep nesting**: All code is one level deep

**Module responsibilities**:
- `did.py`: Pure functions for DID encoding/decoding
- `issuer.py`: Issuer class with credential lifecycle
- `holder.py`: Holder class with presentation building
- `verifier.py`: Verifier class + FastAPI app
- `demo.py`: Runnable test scenarios

**Why not split further**: Increases complexity without benefit at this scale

---

## 20. Database Choice

**Decision**: SQLite for nonces and revocations

**Rationale**:
- **Embedded**: No separate database server
- **Reliable**: ACID transactions, proven technology
- **Sufficient performance**: Handles demo load easily
- **Simple schema**: Just two tables

**Schema decisions**:
```sql
-- Nonces: track issued and used challenges
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,      -- Unique challenge string
    issued_at TIMESTAMP,         -- When it was created
    used INTEGER                 -- 0=unused, 1=used
)

-- Revocations: track invalidated credentials
CREATE TABLE revoked_jtis (
    jti TEXT PRIMARY KEY,        -- Credential unique ID
    revoked_at TIMESTAMP         -- When it was revoked
)
```

**Why not use separate table for used nonces**: 
- Initially considered but simplified to single table
- `used` flag is simpler than JOIN between tables

---

## 21. Configuration Management

**Decision**: JSON files for configuration (trust policy), not environment variables

**Rationale**:
- **Structured data**: Trust policy is a map, fits JSON naturally
- **Versionable**: Can be committed to git (unlike secrets)
- **Human-readable**: Easy to edit and review

**What goes in config files**:
- Trust policy (which issuers to trust)
- Resource requirements (which claims needed)

**What doesn't**:
- Private keys (in separate PEM files)
- Nonces (in database)
- Runtime state (in database)

---

## 22. Demo Data Strategy

**Decision**: Generate fresh keys on every demo run, use temporary directories

**Rationale**:
- **Security**: No keys ever committed to git
- **Reproducibility**: Each run starts from clean state
- **Isolation**: No interference between test runs

**Implementation**:
```python
import tempfile
tmp_dir = Path(tempfile.mkdtemp())
keys_dir = tmp_dir / ".didauth"
```

**Cleanup**: Demo runner removes temp directory after all scenarios (with retries for Windows file locking)

---

## 23. Documentation Structure

**Decision**: Three separate docs - README, DECISIONS, LIMITATIONS

**Rationale**:
- **README**: User-facing documentation (how to use it)
- **DECISIONS**: Developer documentation (why it's built this way)
- **LIMITATIONS**: Honest assessment (what it can't do)

**Why separate**: 
- Different audiences and purposes
- Keeps each focused and scannable
- Easier to maintain

---

## 24. Datetime Handling

**Decision**: UTC timestamps everywhere, stored as Unix epoch (float)

**Rationale**:
- **No timezone confusion**: Everything in UTC
- **JWT standard**: JWTs use Unix epoch for `iat`, `exp`
- **Simple arithmetic**: Easy to calculate expiration

**Why not ISO 8601 strings**: 
- Less compact in JWTs
- Requires parsing for comparisons
- Unix epoch is JWT standard

**Display format**: ISO 8601 in logs for human readability
```python
datetime.now(timezone.utc).isoformat()  # "2026-11-01T03:08:54.731Z"
```

---

## 25. EdDSA Key Format for PyJWT

**Decision**: Convert raw Ed25519 public keys to PEM format for JWT verification

**Rationale**:
- **PyJWT requirement**: Library expects PEM-encoded keys, not raw bytes
- **Standards compliance**: PEM is standard X.509 SubjectPublicKeyInfo format

**Implementation**:
```python
def _public_key_to_pem(self, public_key_bytes: bytes) -> bytes:
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
```

**Why this matters**:
- `did:key` stores raw 32-byte public keys
- PyJWT EdDSA verification needs PEM wrapper
- Conversion is needed at verification time

---

## 26. Audience Verification in PyJWT

**Decision**: Disable PyJWT's automatic audience verification (`verify_aud=False`)

**Rationale**:
- **Custom check**: We verify audience manually before signature check
- **Avoid redundancy**: PyJWT's audience check is redundant
- **Clear error codes**: Our check returns `AUDIENCE_MISMATCH`, not generic JWT error

**Implementation**:
```python
jwt.decode(vp_token, holder_key_pem, algorithms=["EdDSA"], options={"verify_aud": False})
```

---

## Summary of Key Trade-offs

| Decision | Pro | Con | Accepted Because |
|----------|-----|-----|------------------|
| `did:key` | Offline, simple | No key rotation | MVP simplicity priority |
| JWT-VC | Standard tooling | Less semantic | Developer familiarity |
| SQLite revocation | Simple | Centralized per issuer | Acceptable for demo |
| 5-min nonces | Balance UX/security | Some state required | Industry standard |
| Python | Rapid development | Not systems language | Demo/education focus |
| Single package | Simple imports | Less modular | Appropriate scale |
| Plaintext keys | Simple | Less secure | Demo disclaimer |
| Trust policy config | Flexible | Manual setup | Explicit > implicit |

---

**Last updated**: 2026-11-01  
**Review cadence**: Update when making architectural changes
