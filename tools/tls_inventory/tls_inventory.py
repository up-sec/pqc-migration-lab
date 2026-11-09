#!/usr/bin/env python3
"""
tls_inventory.py  v0.1
Inventario criptografico basico de endpoints TLS.
Parte del PQC Migration Lab: github.com/up-sec/pqc-migration-lab

Uso:
    python3 tls_inventory.py targets.txt

Lee una lista de hosts (host o host:puerto, uno por linea, '#' = comentario),
hace un handshake TLS con cada uno y registra:
  - version de TLS y cipher suite negociados
  - algoritmo y tamano de la llave publica del certificado
  - algoritmo de firma del certificado
  - emisor y dias para expirar
  - si la llave publica es vulnerable a un CRQC (algoritmo de Shor)

Salida: inventory/tls_inventory.csv y inventory/tls_inventory.json

LIMITACION CONOCIDA (v0.1): el modulo ssl de Python no expone el grupo de
intercambio de claves (X25519, X25519MLKEM768, etc.). Ese dato es el que
importa para Harvest Now, Decrypt Later. Se agrega en v0.2 con openssl s_client.
"""

import csv
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

VULN = "VULNERABLE (Shor)"
# Salida siempre en <raiz_del_repo>/inventory, sin importar desde donde se ejecute
OUTPUT_DIR = Path(__file__).resolve().parents[2] / "inventory"
FIELDS = [
    "host", "port", "tls_version", "cipher", "cipher_bits",
    "cert_key_algo", "cert_key_size", "cert_sig_algo",
    "issuer", "not_after", "days_left", "quantum_risk", "error",
]


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
        key_algo, key_size, risk = classify_public_key(cert.public_key())
    except Exception:
        # Si la libreria no reconoce la llave, puede ser un cert PQC (ML-DSA) u otro raro
        key_algo, key_size, risk = "NO_RECONOCIDO", None, "REVISAR (posible PQC)"

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
        "cert_key_algo": key_algo,
        "cert_key_size": key_size,
        "cert_sig_algo": sig_algo,
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "quantum_risk": risk,
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

    results = []
    for host, port in read_targets(sys.argv[1]):
        try:
            row = scan(host, port)
            print(f"[OK]    {host}:{port}  {row['tls_version']}  "
                  f"{row['cert_key_algo']}-{row['cert_key_size']}  {row['quantum_risk']}")
        except Exception as exc:
            row = {f: "" for f in FIELDS}
            row.update(host=host, port=port, error=str(exc))
            print(f"[ERROR] {host}:{port}  {exc}")
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
