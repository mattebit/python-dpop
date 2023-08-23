import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from dpop import generate_dpop_proof, validate_dpop_proof


def test_generate_dpop_proof():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))



    a = jwt.decode(encoded_jwt, public_key, algorithms=["EdDSA"])


    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        access_token="a_random1tokenvalues"
    )


    a = jwt.decode(encoded_jwt, public_key, algorithms=["EdDSA"])



def test_validate_dpop():
    private_bytes_client = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDnZP9K6uST8bqyuQC9wS8IlQA00/8CnHunh3XH4zsbQ\n-----END PRIVATE KEY-----\n'
    public_bytes_client = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAe0cHEaYCZVWfm2WEW3C8/uiCrTXR/E8NKyy65lY+nvI=\n-----END PUBLIC KEY-----\n'

    private_bytes_token_issuer = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBPv+ec/mYBpl2ODg0lIbP7CT+5fHpZojnZ9XZ0KMYcD\n-----END PRIVATE KEY-----\n'
    public_bytes_token_issuer = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAnjEY3vO9ZByayyLKvv/GZXJjH7jmmKLpvFK5xFMSu7w=\n-----END PUBLIC KEY-----\n'

    private_key: Ed25519PrivateKey = load_pem_private_key(private_bytes_client, password=None)
    public_key: Ed25519PublicKey = load_pem_public_key(public_bytes_client)
    public_key_str = str(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), "utf-8")

    at = "eyJhbGciOiJFZERTQSIsImtleSI6eyJjcnYiOiJFZDI1NTE5Iiwia2lkIjoiRWNRMUJHVHBCNXJHM3BRc205NmEydWlNSkxPeHJnZU9KaUdfV1JIdWExRSIsImt0eSI6Ik9LUCIsIngiOiJuakVZM3ZPOVpCeWF5eUxLdnZfR1pYSmpIN2ptbUtMcHZGSzV4Rk1TdTd3In0sInR5cCI6ImFwcGxpY2F0aW9uL2F0K2p3dCJ9.eyJpc3MiOiJlbGVjdG9yYWwtcm9sbCIsImV4cCI6MTY3OTE1MjU1OC43NzEwNDcsImF1ZCI6Ik5TIiwic3ViIjoiTlMiLCJjbGllbnRfaWQiOiJhYmNkZWZnaCIsImlhdCI6MTY3ODI4ODU0OC43NzEwNTcsImp0aSI6IjIxNDQzNTc2LWJkYzQtMTFlZC05OGEyLTY3MWJkOGE1MmMyYSIsImNuZiI6eyJqa3QiOiJpSm1VUm55U0dwZFB6SFVyaHZXa2twRTNSX3B3bkZaVHFjZmcyVzNrRXJ3In19.GlfL16uynh5oldvEVDs8iZPHOtDvhpOsrcHCUM1JOq9-OxTzRACFoeSAaTiSePogmTvFpmCpmZI6ofltv4xICQ"

    encoded_jwt = generate_dpop_proof(
        "GET",
        "google.com",
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        access_token=at,
    )

    token_issuer_pubkey: Ed25519PublicKey = load_pem_public_key(public_bytes_token_issuer)

    token_issuer_pubkey_bytes = token_issuer_pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # Standard valid proof
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token=at,
        token_issuer_pubkey=token_issuer_pubkey_bytes,
        audience="NS")[0] is not False

    # validate key
    assert validate_dpop_proof(
        encoded_jwt,
        "GET",
        "google.com",
        presented_access_token=at,
        token_issuer_pubkey=token_issuer_pubkey_bytes,
        audience="NS")[0] is not False


"""
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

"""
