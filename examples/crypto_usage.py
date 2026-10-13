"""Scan input illustrating migration candidates; no dependencies are needed to scan."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
exchange_algorithm = ec.ECDH()
signature_algorithm = ec.ECDSA(hashes.SHA256())
