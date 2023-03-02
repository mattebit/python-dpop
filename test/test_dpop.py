import authlib.jose
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from dpop import generate_dpop_proof, validate_dpop_proof


def test_generate_dpop_proof():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    print(encoded_jwt)

    a = jwt.decode(encoded_jwt, public_key, algorithms=["EdDSA"])
    print(a)

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        access_token="a_random1tokenvalues"
    )
    print(encoded_jwt)

    a = jwt.decode(encoded_jwt, public_key, algorithms=["EdDSA"])
    print(a)


def test_validate_dpop():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        access_token="a_random1tokenvalues"
    )

    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues") is not False

    public_jwk = authlib.jose.JsonWebKey.import_key(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    ).as_dict()

    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues",
        key_check=True,
        public_keys=[public_jwk]) is not False
