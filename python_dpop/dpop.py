import base64
import datetime
import hashlib
import os

import authlib.jose
import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

# This package implements the IETF draft https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop

REQUIRED_CLAIMS = ["jti", "htm", "htu", "iat"]
SUPPORTED_ALGS = ["ES384"]


def generate_dpop_proof(http_method: str,
                        http_url: str,
                        private_key: bytes,
                        public_key: bytes,
                        body: dict[str: str] = None,
                        headers: dict[str: str] = None,
                        alg: str = "ES384",
                        nonce: str = "",
                        access_token: str = ""):
    """
    Generates a dpop proof JWT. Used by a client to generate a DPoP proof to be send to the server
    :param alg:
    :param http_method: the method of the request where the DPoP proof will be inserted
    :param http_url: the url of the request where the DPoP proof will be inserted
    :param body: If you need to add content in the body
    :param headers: If you need additional headers pass them here. Note that if a header is already present,it will be
        overwritten with the new given value
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
        "typ": "dpop+jwt",
        "key": public_jwk.as_dict(),  # representation of the public key in JWK
        "jti": jti,
        "htm": http_method,
        "htu": http_url,
        "iat": (datetime.datetime.now() - datetime.timedelta(seconds=5)).timestamp()
    }

    if headers is not None:
        for k in headers.keys():
            header[k] = headers[k]

    if nonce != "":
        header["nonce"] = nonce

    if access_token != "":
        base64_token = base64.b64encode(bytes(access_token, "ascii"))
        h = hashlib.sha256(base64_token).hexdigest()
        header["ath"] = h

    encoded_jwt = jwt.encode(
        body if body is not None else {},
        private_key,
        algorithm=alg,  # MUST NOT BE symmetric
        headers=header)

    return encoded_jwt


def validate_dpop_proof(dpop_proof_jwt: str,
                        http_method: str,
                        http_url: str,
                        key_check: bool = False,
                        alg: str = "ES384",
                        nonce: str = "",
                        presented_access_token: str = "",
                        public_keys: list[dict[str:str]] = None) -> bool:
    """
    Used to validate a DPoP proof received from a client.
    :param public_keys: With this variable, you can provide a list of public_keys (in jwk format) to check if the
        public key of the dpop matches one of them
    :param dpop_proof_jwt:
    :param http_method:
    :param http_url:
    :param alg:
    :param nonce:
    :param presented_access_token:
    :return: true if the DPoP proof is valid, False otherwise
    """

    header = jwt.get_unverified_header(dpop_proof_jwt)

    if header["typ"] != "dpop+jwt":
        return False

    if not header["alg"] in SUPPORTED_ALGS:
        return False

    if key_check:
        if public_keys is None:
            raise ValueError("public_keys parameter is None")

        if not header["key"] in public_keys:
            return False

    public_key = jwt.algorithms.ECAlgorithm.from_jwk(header["key"])

    # verify jwk is a public key
    if not isinstance(public_key, EllipticCurvePublicKey):
        return False

    try:
        body = jwt.decode(dpop_proof_jwt, public_key, alg)
    except jwt.DecodeError:
        return False

    try:
        for i in REQUIRED_CLAIMS:
            if header[i] is None:
                return False
    except KeyError:
        return False

    if header['htm'] != http_method:
        return False

    if header["htu"] != http_url:
        return False

    if nonce != "":
        if header["nonce"] != nonce:
            return False

    iat = datetime.datetime.fromtimestamp(header["iat"])
    if (iat - datetime.datetime.now()) > datetime.timedelta(hours=24):  # TODO: check if it is reasonable
        return False

    if presented_access_token != "":
        base64_token = base64.b64encode(bytes(presented_access_token, "ascii"))
        h = hashlib.sha256(base64_token).hexdigest()
        if not header["ath"] == h:
            return False

    return True
