# 02 — Lab: TLS Cryptographic Inventory (v0.1)

Goal: discover which public-key cryptography protects each TLS endpoint, as the first
step of the cryptographic inventory recommended by CISA/NSA/NIST.

## 1. Local targets (no internet needed)

```bash
bash lab/local-tls/start_servers.sh
```

| Endpoint | Simulates | Certificate |
|----------|-----------|-------------|
| localhost:8443 | Legacy online banking portal | RSA-2048, self-signed |
| localhost:8444 | Payments API | ECDSA P-256, self-signed |

Private keys live in `lab/local-tls/certs/` (mode 700/600) and are excluded by
`.gitignore`. Never commit private keys, even lab ones.

## 2. Manual inspection with OpenSSL

```bash
openssl s_client -connect localhost:8443 </dev/null 2>/dev/null | grep -E "New,|Server Temp Key|Negotiated"
```

Observed:

```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

Reading it:
- `TLS_AES_256_GCM_SHA384` — symmetric bulk encryption. Survives a CRQC.
- `X25519` — the key exchange. **This is what HNDL breaks.**
- The certificate key (RSA-2048) authenticates the server. Vulnerable to Shor, but it
  is an authentication risk, not an HNDL risk.

OpenSSL 3.5+ can negotiate the hybrid group `X25519MLKEM768`; on older versions the
best you will see is a classical group.

## 3. Automated scan

```bash
python3 tools/tls_inventory/tls_inventory.py tools/tls_inventory/targets.txt
```

Sample result (local lab): [`inventory/sample-local-lab.csv`](../inventory/sample-local-lab.csv)

```
[OK]    localhost:8443  TLSv1.3  RSA-2048  VULNERABLE (Shor)
[OK]    localhost:8444  TLSv1.3  EC-secp256r1-256  VULNERABLE (Shor)
```

## 4. Tests

```bash
python3 -m unittest discover -s tests -v
```

Covers RSA-2048, RSA-4096 (proves key size does not fix Shor), ECDSA P-256, Ed25519
and unknown key types.

## 5. Troubleshooting notes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Name or service not known` | No DNS / no outbound access | Check `ping`, `resolvectl`, VM network mode |
| `Connection refused` on 8443/8444 | Local servers not running | Run `start_servers.sh` |
| `ModuleNotFoundError: cryptography` | Library missing | `pip install cryptography --break-system-packages` |
| Issuer is not the expected public CA | **TLS inspection proxy** (corporate MITM) | See finding below |

### Finding: TLS interception detected

During development, scanning `github.com` from a sandboxed environment returned a
certificate issued by the environment's egress proxy, not by GitHub's real CA. The
proxy terminates TLS and re-encrypts with its own certificate.

Why it matters for a bank: TLS inspection appliances are common in corporate networks.
An inventory run from inside the network may record the **proxy's** cryptography, not
the real server's. A correct inventory records the observation point and compares the
issuer against the expected CA.

## 6. Known limitation (v0.1) → v0.2

Python's `ssl` module does not expose the negotiated key exchange group, which is the
field that matters for HNDL. v0.2 will capture it via `openssl s_client` and separate
the risk into:

- `kex_risk` — confidentiality / HNDL (key exchange)
- `auth_risk` — authentication (certificate key and signature)
