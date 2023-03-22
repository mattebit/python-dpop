import base64
import datetime
import hashlib
import os
from urllib.parse import urlparse

import authlib.jose
import jwt
import jwt.algorithms
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# This package implements the IETF draft https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop

REQUIRED_CLAIMS = ["jti", "htm", "htu", "iat"]
SUPPORTED_ALGS = ["EdDSA"]


def generate_dpop_proof(http_method: str,
                        http_url: str,
                        private_key: bytes,
                        public_key: bytes,
                        headers: dict[str: str] = None,
                        alg: str = "EdDSA",
                        nonce: str = "",
                        access_token: str = "",
                        body: dict[str:str] = None):
    """
    Generates a dpop proof JWT. Used by a client to generate a DPoP proof to be send to the server
    :param alg:
    :param http_method: the method of the request where the DPoP proof will be inserted
    :param http_url: the url of the request where the DPoP proof will be inserted
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

    header = {
        "typ": "dpop+jwt",
        "key": public_jwk.as_dict()  # representation of the public key in JWK
    }

    if headers is not None:
        for k in headers.keys():
            header[k] = headers[k]

    # Unique identifier 96 bits random
    jti = str(base64.b64encode(os.urandom(12)), "utf-8")

    url_parsed = urlparse(http_url)
    # Url needs to be cleaned by any query element or fragments https://docs.python.org/3/library/urllib.parse.html
    normalized_url = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"

    b = {
        "jti": jti,
        "htm": http_method,
        "htu": normalized_url,
        "iat": (datetime.datetime.now() - datetime.timedelta(seconds=5)).timestamp()
    }

    if body is not None:
        if not isinstance(body, dict):
            raise ValueError("invalid type o body, should be dict")

        for i in body.keys():
            b[i] = body[i]


    if access_token != "":
        base64_token = base64.b64encode(bytes(access_token, "ascii"))
        b['ath'] = hashlib.sha256(base64_token).hexdigest()

    if nonce != "":
        b["nonce"] = nonce

    encoded_jwt = jwt.encode(
        b,
        private_key,
        algorithm=alg,  # MUST NOT BE symmetric
        headers=header)

    return encoded_jwt


def validate_dpop_proof(dpop_proof_jwt: str,
                        http_method: str,
                        http_url: str,
                        presented_access_token: str = "",
                        token_issuer_pubkey: bytes = None,
                        audience=None,
                        public_keys_nonce: dict[str:str] = None) \
        -> tuple[bool, dict[str:str] | None, dict[str:str] | None]:
    """
    Used to validate a DPoP proof received from a client.
    :param public_keys_nonce: If you want to check that the dpop jwt is using one of the previous registered public keys
        With this variable, you can provide the public_keys (in str of bytes format) to check if the public key of the
        dpop matches one of them. As keys of the dictionary provide the public key, as value you can insert a nonce, if
        you hava previously issued one. Note that if nothing is provided, the dpop proof will be checked only as
        "self-signed".
    :param dpop_proof_jwt: the dpop proof jwt, string as received in the request
    :param http_method: the method of the request that contained the dpop proof
    :param http_url: the url of the request that contained the dopo proof
    :param presented_access_token: insert the access token presented by the client in his request to validate it against
     assumes a JWT access token conform to RFC9068
     the dpop proof
    :param audience when a client is presenting an access token, the server receiveing the token (the one
        calling this function) should include its audience value (defined beforehand with the issuer of the token), to
        be sure the token is meant to be used on him
    :param token_issuer_pubkey the public key of the issuer to validate the presented access token
    :return: a tuple containing (isvalid, header, body)
    """

    header = jwt.get_unverified_header(dpop_proof_jwt)

    if header["typ"] != "dpop+jwt":
        return False, None, None

    if not header["alg"] in SUPPORTED_ALGS:
        return False, None, None

    public_key = jwt.algorithms.OKPAlgorithm.from_jwk(header["key"])

    # verify jwk is a public key
    if not isinstance(public_key, Ed25519PublicKey):
        return False, None, None

    try:
        body = jwt.decode(dpop_proof_jwt,
                          public_key,
                          header["alg"],
                          options={"require": REQUIRED_CLAIMS})
    except (jwt.DecodeError, jwt.MissingRequiredClaimError):
        return False, None, None

    if public_keys_nonce is not None:
        if public_keys_nonce is None:
            raise ValueError("public_keys parameter is None")

        found = False
        for k in public_keys_nonce.keys():
            if str(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), "utf-8") == k:
                found = True
                if public_keys_nonce[k] != "":
                    # if nonce is present with key check it wrt the value in the dpop
                    try:
                        found = (body["nonce"] == public_keys_nonce[k])
                    except KeyError:
                        found = False

        if not found:
            return False, None, None

        if not str(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), "utf-8") \
               in public_keys_nonce.keys():
            return False, None, None

    if body['htm'] != http_method:
        return False, None, None

    url_parsed = urlparse(http_url)
    # Url needs to be cleaned by any query element or fragments https://docs.python.org/3/library/urllib.parse.html
    normalized_url = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"

    if body["htu"] != normalized_url:
        return False, None, None

    iat = datetime.datetime.fromtimestamp(body["iat"])
    if (iat - datetime.datetime.now()) > datetime.timedelta(hours=24):  # TODO: check if it is reasonable
        return False, None, None

    # If an access token is presented, validate it
    if presented_access_token != "":
        base64_token = base64.b64encode(bytes(presented_access_token, "ascii"))
        h = hashlib.sha256(base64_token).hexdigest()
        if not body["ath"] == h:
            return False, None, None

        if audience is None:
            return False, None, None

        if token_issuer_pubkey is None:
            raise ValueError("token issuer public key not provided")

        decoded_at = jwt.decode(presented_access_token,
                                key=token_issuer_pubkey,
                                algorithms=["EdDSA"],
                                audience=audience)

        if not "cnf" in decoded_at.keys():
            return False, None, None

        if not "jkt" in decoded_at["cnf"]:
            return False, None, None

        dpop_pubkey_jwk = authlib.jose.JsonWebKey.import_key(
            public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        dpop_pubkey_thumbprint = dpop_pubkey_jwk.thumbprint()

        # validate jwk thumbprint of public key in cnf field in access token with
        # jwk thumprint of jwt dpop proof's public key, MUST be the same
        if dpop_pubkey_thumbprint != decoded_at['cnf']['jkt']:
            return False, None, None

    return True, header, body
