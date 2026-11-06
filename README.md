# PQC Migration Lab for Financial Infrastructure

A hands-on lab that simulates the cryptographic infrastructure of a financial institution
and documents its migration from classical public-key cryptography (RSA / ECC) to
NIST post-quantum standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA).

## Why

A cryptographically relevant quantum computer (CRQC) would break RSA, ECDH and ECDSA.
Adversaries can capture encrypted traffic today and decrypt it later
(**Harvest Now, Decrypt Later**), so data with long confidentiality requirements is
already at risk. Migration starts with knowing what cryptography you run, where, and
what it protects.

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Threat model and cryptographic inventory (TLS discovery, CBOM) | In progress |
| 1 | PKI: Root CA, Intermediate CA, issuance, revocation (CRL/OCSP) | Planned |
| 2 | TLS / mTLS between simulated banking services + troubleshooting | Planned |
| 3 | Key management: HSM simulation with SoftHSM2 and PKCS#11 | Planned |
| 4 | Risk prioritization and vendor quantum-readiness assessment | Planned |
| 5 | Hybrid key exchange (X25519MLKEM768) and PQC certificates | Planned |
| 6 | Crypto-agile architecture and migration plan with rollback | Planned |

## Structure

```
docs/        Threat model, lab guides, architecture decisions (ADR), progress log
tools/       Discovery and automation scripts
lab/         Local simulated infrastructure (TLS servers, later PKI/HSM)
inventory/   Inventory outputs (CSV / JSON, CBOM planned)
tests/       Unit tests
```

## Documentation

- [01 — Quantum threat model](docs/01-quantum-threat-model.md)
- [02 — Lab: TLS cryptographic inventory](docs/02-lab-tls-inventory.md)
- [ADR-0001 — Inventory before migration](docs/adr/0001-inventory-before-migration.md)
- [Progress log](docs/PROGRESS.md)

## Quick start

```bash
pip install cryptography --break-system-packages   # if missing
bash lab/local-tls/start_servers.sh                # local RSA + ECDSA endpoints
python3 tools/tls_inventory/tls_inventory.py tools/tls_inventory/targets.txt
python3 -m unittest discover -s tests -v
bash lab/local-tls/start_servers.sh stop
```

## Tools

### `tools/tls_inventory` (v0.1)
Scans TLS endpoints and records protocol version, cipher suite, certificate key
algorithm and size, signature algorithm, expiration and quantum risk.
Sample output: [`inventory/sample-local-lab.csv`](inventory/sample-local-lab.csv)

Known limitation: v0.1 does not capture the key exchange group, which is the
relevant field for Harvest Now, Decrypt Later. Planned for v0.2.

## References

- CISA, NSA, NIST — *Quantum-Readiness: Migration to Post-Quantum Cryptography* (2023)
- NIST FIPS 203, 204, 205 (2024)
- NIST IR 8547 — *Transition to Post-Quantum Cryptography Standards*

## Author

Uriel Prado — [GitHub](https://github.com/up-sec) · [LinkedIn](https://linkedin.com/in/urielprado)
