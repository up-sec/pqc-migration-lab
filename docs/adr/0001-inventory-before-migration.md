# ADR-0001: Build the cryptographic inventory before any migration work

- **Status:** Accepted
- **Date:** 2026-11-05

## Context

The simulated bank runs TLS, mTLS, a private PKI, code signing and third-party (COTS
and cloud) products. Nobody has a complete picture of which algorithms are used where,
or what data they protect.

## Decision

Phase 0 of the lab is discovery: build an automated, repeatable cryptographic
inventory before choosing algorithms or touching configurations. TLS endpoints first,
then certificates, code/dependencies (CI/CD) and vendor-declared embedded crypto.

## Rationale

- You cannot prioritize what you cannot see. Risk ranking (Mosca: X + Y > Z) needs
  data lifetime and exposure per asset.
- Aligns with the CISA/NSA/NIST quantum-readiness factsheet, which puts inventory at
  the center of the roadmap.
- The inventory also detects classical problems (expiring certs, weak TLS, TLS
  interception), so it pays off before PQC.

## Consequences

- Discovery tooling must be automated and versioned (this repo), not a spreadsheet.
- Tools cannot see crypto embedded in closed products; vendor questionnaires are
  required (Phase 4).
- Output format will move toward a CBOM (CycloneDX) for interoperability.
