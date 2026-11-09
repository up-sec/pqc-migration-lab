"""
Pruebas del intercambio de claves (v0.2), sin red: usan salidas reales de
`openssl s_client` capturadas durante el lab (2026-11-09).
Ejecutar desde la raiz del repo:  python3 -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "tls_inventory"))

from tls_inventory import KEX_HNDL, KEX_PQC, classify_kex, parse_kex_group  # noqa: E402

BBVA = "Server Temp Key: X25519, 253 bits\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
BANORTE = ("Server Temp Key: ECDH, prime256v1, 256 bits\n"
           "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n")
HYBRID = "Negotiated TLS1.3 group: X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"


class TestParseKexGroup(unittest.TestCase):
    def test_x25519(self):
        self.assertEqual(parse_kex_group(BBVA), "X25519")

    def test_ecdh_p256(self):
        self.assertEqual(parse_kex_group(BANORTE), "ECDH-prime256v1")

    def test_hibrido_openssl35(self):
        self.assertEqual(parse_kex_group(HYBRID), "X25519MLKEM768")

    def test_sin_llave_temporal(self):
        self.assertEqual(parse_kex_group("New, TLSv1.2, Cipher is AES128-GCM-SHA256\n"), "")


class TestClassifyKex(unittest.TestCase):
    def test_x25519_vulnerable_hndl(self):
        self.assertEqual(classify_kex("X25519")[1], KEX_HNDL)

    def test_ecdh_vulnerable_hndl(self):
        self.assertEqual(classify_kex("ECDH-prime256v1")[1], KEX_HNDL)

    def test_hibrido_protegido(self):
        self.assertEqual(classify_kex("X25519MLKEM768")[1], KEX_PQC)

    def test_rsa_estatico_sin_forward_secrecy(self):
        group, risk = classify_kex("", "TLSv1.2", "AES128-GCM-SHA256")
        self.assertEqual(group, "RSA-estatico")
        self.assertIn("sin forward secrecy", risk)


if __name__ == "__main__":
    unittest.main()
