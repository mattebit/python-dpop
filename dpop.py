import base64
import datetime
import hashlib
import os

import authlib.jose
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import requests

# This package implements the IETF draft https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop


def generate_dpop_proof(http_method: str,
                        http_url: str,
                        private_key: bytes,
                        public_key: bytes,
                        nonce: str = "",
                        access_token: str = ""):
    """
    Generates a dpop proof JWT.
    :param http_method: the method of the request where the DPoP proof will be inserted
    :param http_url: the url of the request where the DPoP proof will be inserted
    :param private_key: the private key to use to sign the JWT
    :param public_key: the public key to be attached to the JWT
    :param nonce: When the authentication server or resource server provides a DPoP-Nonce HTTP header in a response
        pass such nonce value, in order to insert it in the DPoP
    :param access_token: When the DPoP proof is used in conjunction with the presentation of an access token in
        protected resource access, there is the need to pass such token, to be included in the DPoP
    :return:
    """
    public_jwk = authlib.jose.JsonWebKey.import_key(
        public_key
    )

    # TODO: validate url and keep only URI
    # TODO validate method

    # Unique identifier 96 bits random
    jti = str(base64.b64encode(os.urandom(12)), "utf-8")

    header = {
            "jti": jti,
            "htm": http_method,
            "htu": http_url,
            "iat": (datetime.datetime.now() - datetime.timedelta(seconds=5)).timestamp()
        }

    if nonce != "":
        header["nonce"] = nonce

    if access_token != "":
        base64_token = base64.b64encode(bytes(access_token, "ascii"))
        h = hashlib.sha256(base64_token).hexdigest()
        header["ath"] = h

    encoded_jwt = jwt.encode(
        header,
        private_key,
        algorithm="ES384",  # MUST NOT BE symmetric
        headers={
            "typ": "dpop+jwt",
            "key": public_jwk.as_dict()  # representation of the public key in JWK
        })

    return encoded_jwt


def validate_dpop_proof(req: requests.request):
    pass
