# Progress Log

| Date | Topic | Level | Labs completed | Exam | Weaknesses | Next goal |
|------|-------|-------|----------------|------|------------|-----------|
| 2026-11-05 | Quantum threat model, HNDL, inventory | Introductory | TLS inventory v0.1 (local lab + tests) | Q1 partial, Q2 incorrect (Shor vs Grover) | Confidentiality vs authentication under HNDL; why symmetric survives | v0.2: capture key exchange group, split kex/auth risk |
| 2026-11-08 | Lab environment (WSL2), real TLS scan, verification vs inventory, HNDL, Grover | Introductory+ | Moved lab to WSL2 Ubuntu (VMware on Hyper-V unstable); first real scan of MX banks (`inventory/scan-2026-11-08-mx-banks.csv`); first push from own machine | CERT_NONE ✅ after 2nd attempt; ECDHE as HNDL target ✅; ML-KEM + AES roles ✅; Grover on AES-128 partial (said "half the effort" instead of "half the bits") | Mixed up trust (cert verification) with algorithm choice (PQC); Grover = square root of effort (2^128 → 2^64), not half | v0.2: capture key exchange group, split `kex_risk` / `auth_risk` |
