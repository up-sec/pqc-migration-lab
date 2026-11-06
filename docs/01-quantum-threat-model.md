# 01 — Quantum Threat Model

## Threat actor and capability

A **CRQC** (Cryptographically Relevant Quantum Computer) is a quantum computer large
and stable enough to run cryptanalytic algorithms against real key sizes. It does not
exist today. The planning question is not *if* but *whether our data outlives the
time until it does*.

## What breaks and what survives

| Primitive | Examples | Quantum attack | Effect | Action |
|-----------|----------|----------------|--------|--------|
| Key exchange (asymmetric) | RSA key transport, ECDH, X25519 | Shor | **Broken** (polynomial time) | Replace with ML-KEM (FIPS 203), hybrid first |
| Signatures (asymmetric) | RSA, ECDSA, Ed25519 | Shor | **Broken** | Replace with ML-DSA (FIPS 204) / SLH-DSA (FIPS 205) |
| Symmetric encryption | AES-128 / AES-256 | Grover | Security roughly halved (AES-256 ≈ 128-bit) | Prefer AES-256 |
| Hash functions | SHA-256 / SHA-384 | Grover-type | Reduced margin, still usable | Prefer SHA-384+ where long-lived |

Key point: Shor makes RSA and ECC fail regardless of key size. RSA-4096 is not a
mitigation. Grover only gives a quadratic speedup, so doubling symmetric key length
restores the margin.

## Harvest Now, Decrypt Later (HNDL)

An adversary records encrypted traffic today and stores it. When a CRQC is available,
they break the recorded key exchange, recover the session keys and decrypt everything.

- HNDL threatens **confidentiality** (key exchange), not short-lived **authentication**.
- A signature only needs to resist forgery while it is valid. A 15-minute session token
  is not an HNDL target; a Root CA or a firmware-signing key valid for 20 years is a
  long-term signature risk.

## Mosca's inequality

```
X = years the data must stay confidential
Y = years needed to migrate the system
Z = years until a CRQC exists

If X + Y > Z  ->  the data is already at risk
```

Banking example: KYC records retained 10 years (X=10), core migration estimated at
5 years (Y=5). Unless a CRQC is more than 15 years away, that data is exposed today.

## Banking assets in scope (simulated institution)

| Asset | Crypto in use | Data lifetime | HNDL priority |
|-------|---------------|---------------|---------------|
| Online banking portal (TLS) | ECDHE + RSA cert | Long (statements, PII) | High |
| Internal payment API (mTLS) | ECDHE + ECDSA certs | Long (transactions) | High |
| Root / Intermediate CA | RSA-4096 signatures | 10–20 years | High (signature) |
| Firmware / code signing | RSA / ECDSA | Years | High (signature) |
| Session tokens (JWT) | ES256 | Minutes | Low |
| Data at rest | AES-256-GCM | Long | Low (key wrapping still asymmetric — review) |

## References

- CISA, NSA, NIST — *Quantum-Readiness: Migration to Post-Quantum Cryptography* (Aug 2023)
- NIST FIPS 203, 204, 205 (Aug 2024)
- NIST IR 8547 — *Transition to Post-Quantum Cryptography Standards*
