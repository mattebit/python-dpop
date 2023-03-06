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
        access_token="a_random1tokenvalues",
    )

    # Standard valid proof
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues")[0] is not False

    public_key_str = str(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), "utf-8")

    # validate key
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues",
        public_keys_nonce={public_key_str: ""})[0] is not False

    # Wong signing key
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues",
        public_keys_nonce={"wrong signing key": "arandomnonce"})[0] is False

    # Wong nonce in dpop
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token="a_random1tokenvalues",
        public_keys_nonce={public_key_str: "arandomnonce"})[0] is False

