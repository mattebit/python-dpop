import authlib.jose
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import requests
import pytest

from dpop import generate_dpop_proof


def test_generate_dpop_proof():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    # public_jwk = jwk.dumps(public_key)

    private_jwk = authlib.jose.JsonWebKey.import_key(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    public_jwk = authlib.jose.JsonWebKey.import_key(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    print(encoded_jwt)

    a = jwt.decode(encoded_jwt, public_key, algorithms=["ES384"])
    print(a)

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        access_token="a_random1tokenvalues"
    )
    print(encoded_jwt)

    a = jwt.decode(encoded_jwt, public_key, algorithms=["ES384"])
    print(a)