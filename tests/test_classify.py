"""
Pruebas de classify_public_key: genera llaves reales y verifica la clasificacion.
Ejecutar desde la raiz del repo:  python3 -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "tls_inventory"))

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402

from tls_inventory import VULN, classify_public_key  # noqa: E402


class TestClassifyPublicKey(unittest.TestCase):
    def test_rsa_2048(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        self.assertEqual(classify_public_key(key), ("RSA", 2048, VULN))

    def test_rsa_4096_sigue_vulnerable(self):
        # Shor no se arregla con llaves mas grandes: RSA-4096 tambien cae
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096).public_key()
        self.assertEqual(classify_public_key(key)[2], VULN)

    def test_ecdsa_p256(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.assertEqual(classify_public_key(key), ("EC-secp256r1", 256, VULN))

    def test_ed25519(self):
        key = ed25519.Ed25519PrivateKey.generate().public_key()
        self.assertEqual(classify_public_key(key), ("Ed25519", 256, VULN))

    def test_tipo_desconocido(self):
        algo, size, risk = classify_public_key(object())
        self.assertEqual(risk, "REVISAR")
        self.assertIsNone(size)


if __name__ == "__main__":
    unittest.main()
