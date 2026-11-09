#!/usr/bin/env python3
"""
tls_inventory.py  v0.2
Inventario criptografico de endpoints TLS.
Parte del PQC Migration Lab: github.com/up-sec/pqc-migration-lab

Uso:
    python3 tls_inventory.py targets.txt

Lee una lista de hosts (host o host:puerto, uno por linea, '#' = comentario),
hace un handshake TLS con cada uno y registra:
  - version de TLS y cipher suite negociados
  - grupo de intercambio de claves (X25519, ECDH P-256, X25519MLKEM768...)  [v0.2]
  - algoritmo y tamano de la llave publica del certificado
  - algoritmo de firma del certificado
  - emisor y dias para expirar

Y separa el riesgo cuantico en dos:
  - kex_risk  -> CONFIDENCIALIDAD: el intercambio de claves. Es lo que ataca
                 Harvest Now, Decrypt Later (HNDL). Urgente.
  - auth_risk -> AUTENTICACION: la llave del certificado. Un atacante necesita
                 un CRQC en el momento de la conexion; no aplica HNDL.

Salida: inventory/tls_inventory.csv y inventory/tls_inventory.json

LIMITACION: el resultado depende tambien de lo que ofrece NUESTRO cliente.
OpenSSL < 3.5 no ofrece ML-KEM, asi que un servidor con soporte hibrido
negociara X25519 con nosotros. Ver la columna 'client_offers_pqc'.
"""

import csv
import json
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

VULN = "VULNERABLE (Shor)"
KEX_HNDL = "VULNERABLE (HNDL)"
KEX_PQC = "PQC-HIBRIDO (protegido)"

# Salida siempre en <raiz_del_repo>/inventory, sin importar desde donde se ejecute
OUTPUT_DIR = Path(__file__).resolve().parents[2] / "inventory"
FIELDS = [
    "host", "port", "tls_version", "cipher", "cipher_bits",
    "kex_group", "kex_risk",
    "cert_key_algo", "cert_key_size", "cert_sig_algo", "auth_risk",
    "issuer", "not_after", "days_left", "client_offers_pqc", "error",
]


# ---------------------------------------------------------------------------
# Autenticacion: llave publica del certificado
# ---------------------------------------------------------------------------
def classify_public_key(pubkey):
    """Devuelve (algoritmo, tamano_bits, riesgo_cuantico)."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size, VULN
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return f"EC-{pubkey.curve.name}", pubkey.key_size, VULN
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, VULN
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", 448, VULN
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size, VULN
    return type(pubkey).__name__, None, "REVISAR"


# ---------------------------------------------------------------------------
# Confidencialidad: intercambio de claves  [v0.2]
# ---------------------------------------------------------------------------
def parse_kex_group(s_client_output):
    """Extrae el grupo de intercambio de claves de la salida de `openssl s_client`.

    OpenSSL 3.0-3.4 imprime:  'Server Temp Key: X25519, 253 bits'
                              'Server Temp Key: ECDH, prime256v1, 256 bits'
    OpenSSL 3.5+ puede imprimir: 'Negotiated TLS1.3 group: X25519MLKEM768'
    Devuelve un nombre normalizado ('X25519', 'ECDH-prime256v1', ...) o ''.
    """
    m = re.search(r"^Negotiated TLS1\.3 group:\s*(\S+)", s_client_output, re.M)
    if m:
        return m.group(1)
    m = re.search(r"^(?:Server|Peer) Temp Key:\s*(.+)$", s_client_output, re.M)
    if not m:
        return ""
    parts = [p.strip() for p in m.group(1).split(",")]
    if parts[0] == "ECDH" and len(parts) >= 2:
        return f"ECDH-{parts[1]}"
    if parts[0] == "DH" and len(parts) >= 2:
        return f"DH-{parts[1].replace(' bits', '')}"
    return parts[0]


def classify_kex(group, tls_version="", cipher=""):
    """Devuelve (grupo_normalizado, riesgo_confidencialidad)."""
    up = group.upper()
    if "MLKEM" in up or "KYBER" in up:
        return group, KEX_PQC
    if group:
        # X25519, X448, ECDH-*, DH-*: todos se basan en logaritmo discreto -> Shor
        return group, KEX_HNDL
    # Sin llave temporal en TLS 1.2 y sin ECDHE/DHE en el cipher:
    # intercambio RSA estatico -> sin forward secrecy y vulnerable a HNDL
    if tls_version == "TLSv1.2" and cipher and not cipher.startswith(("ECDHE", "DHE")):
        return "RSA-estatico", KEX_HNDL + " sin forward secrecy"
    return "", "DESCONOCIDO"


def openssl_offers_pqc():
    """True si el OpenSSL local puede ofrecer ML-KEM (3.5+)."""
    try:
        out = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return False
    m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 5)


def get_kex_group(host, port, timeout=8):
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return parse_kex_group(result.stdout)


# ---------------------------------------------------------------------------
# Escaneo
# ---------------------------------------------------------------------------
def scan(host, port=443, timeout=5):
    ctx = ssl.create_default_context()
    # Esto es INVENTARIO, no validacion: queremos ver todo, incluso
    # certificados expirados o autofirmados. Primero check_hostname, luego verify_mode.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            tls_version = tls.version()
            cipher_name, _, cipher_bits = tls.cipher()

    cert = x509.load_der_x509_certificate(der)

    try:
        key_algo, key_size, auth_risk = classify_public_key(cert.public_key())
    except Exception:
        # Si la libreria no reconoce la llave, puede ser un cert PQC (ML-DSA) u otro raro
        key_algo, key_size, auth_risk = "NO_RECONOCIDO", None, "REVISAR (posible PQC)"

    kex_group, kex_risk = classify_kex(get_kex_group(host, port), tls_version, cipher_name)

    sig_oid = cert.signature_algorithm_oid
    sig_algo = getattr(sig_oid, "_name", None) or sig_oid.dotted_string

    # cryptography >= 42 trae not_valid_after_utc; versiones anteriores (ej. 41 en
    # Ubuntu 24.04) solo traen not_valid_after sin zona horaria -> le ponemos UTC
    if hasattr(cert, "not_valid_after_utc"):
        not_after = cert.not_valid_after_utc
    else:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days

    return {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "cipher": cipher_name,
        "cipher_bits": cipher_bits,
        "kex_group": kex_group,
        "kex_risk": kex_risk,
        "cert_key_algo": key_algo,
        "cert_key_size": key_size,
        "cert_sig_algo": sig_algo,
        "auth_risk": auth_risk,
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "error": "",
    }


def read_targets(path):
    targets = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host, _, port = line.partition(":")
        targets.append((host, int(port) if port else 443))
    return targets


def main():
    if len(sys.argv) != 2:
        print("Uso: python3 tls_inventory.py targets.txt")
        sys.exit(1)

    pqc_client = openssl_offers_pqc()
    if not pqc_client:
        print("[AVISO] Tu OpenSSL no ofrece ML-KEM (requiere 3.5+). Un servidor con soporte\n"
              "        hibrido aparecera aqui como X25519. Ver columna client_offers_pqc.\n")

    results = []
    for host, port in read_targets(sys.argv[1]):
        try:
            row = scan(host, port)
            print(f"[OK]    {host}:{port}  {row['tls_version']}  "
                  f"KEX={row['kex_group'] or '?'} -> {row['kex_risk']}  |  "
                  f"CERT={row['cert_key_algo']}-{row['cert_key_size']} -> {row['auth_risk']}")
        except Exception as exc:
            row = {f: "" for f in FIELDS}
            row.update(host=host, port=port, error=str(exc))
            print(f"[ERROR] {host}:{port}  {exc}")
        row["client_offers_pqc"] = pqc_client
        results.append(row)

    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(OUTPUT_DIR / "tls_inventory.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(results)
    with open(OUTPUT_DIR / "tls_inventory.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{len(results)} endpoints -> {OUTPUT_DIR}/tls_inventory.csv y .json")


if __name__ == "__main__":
    main()
