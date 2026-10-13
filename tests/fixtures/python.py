from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as make_rsa
from Crypto.PublicKey import ECC, RSA
from Cryptodome.PublicKey import RSA as OtherRSA

# ruleid: qrypt.python.rsa-keygen
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# ruleid: qrypt.python.rsa-keygen
alias_key = make_rsa(public_exponent=65537, key_size=4096)
# ruleid: qrypt.python.rsa-keygen
legacy_key = RSA.generate(2048)
# ruleid: qrypt.python.rsa-keygen
other_key = OtherRSA.generate(2048)
# ruleid: qrypt.python.dh-parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)
# ruleid: qrypt.python.ec-keygen
curve_key = ec.generate_private_key(ec.SECP256R1())
# ruleid: qrypt.python.ec-keygen
other_curve_key = ECC.generate(curve="P-256")
# ruleid: qrypt.python.ecdh
exchange_algorithm = ec.ECDH()
# ruleid: qrypt.python.ecdsa
signature_algorithm = ec.ECDSA(hash_algorithm)

# ok: qrypt.python.rsa-keygen
text = "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
# rsa.generate_private_key(public_exponent=65537, key_size=2048)
# ok: qrypt.python.rsa-keygen
unrelated = unrelated_library.generate_private_key()
# ok: qrypt.python.ecdh
unrelated_exchange = unrelated_library.ECDH()
from cryptography.hazmat.primitives.ciphers import algorithms
# ok: qrypt.python.ec-keygen
symmetric = algorithms.AES(b"this-is-a-test-key-only-32-bytes!")

def shadowed(rsa):
    # ok: qrypt.python.rsa-keygen
    return rsa.generate_private_key()

# ruleid: qrypt.python.rsa-keygen
multiline_key = make_rsa(
    public_exponent=65537,
    key_size=2048,
)
