import datetime
import hashlib
import json
import os
from base64 import urlsafe_b64encode
from time import perf_counter_ns

import SD_JWT
from Resolver import Resolver
from Utils.Exceptions import DigestNotFoundException, ValidityPeriodException, HolderProofRequiredException
from cryptography.hazmat.primitives.asymmetric import ed25519


def _base64url_encode(b: bytes) -> str:
    return urlsafe_b64encode(b).decode('utf-8').rstrip("=")


def generate_salt() -> str:
    return str(_base64url_encode(os.urandom(16)))


def generate_disclosure(salt: str, claim_name: str, claim_value: str) -> str:
    """
    This function encodes a disclosure. The result should be hashed before sharing the VC.
    :param salt: Salt value for this disclosure
    :param claim_name: Claim Name to be encoded
    :param claim_value: Claim Value to be encoded
    :return: Encoded Disclosure
    """
    if claim_name == "_sd" or claim_name == "...":
        raise ValueError("Claim_name may not be '_sd' or '...'")
    json_encoded = json.dumps([salt, claim_name, claim_value])
    return _base64url_encode(bytes(json_encoded, 'utf-8'))


def hash_disclosure(disclosure: str):
    """
    Hashes a disclosure (for example created with generate_disclosure()).
    This uses SHA-256 to create a non-reversible digest and protest the claim name and value from unauthorized reading
    :param disclosure: The disclosure string, base64-encoded. Can be created with generate_disclosure()
    :return: SHA-256 digest of Disclosure.
    """
    h = hashlib.new('sha256')
    h.update(disclosure.encode())
    return _base64url_encode(h.digest())


def sign_vc(vc, private_key: ed25519.Ed25519PrivateKey):
    """
    This creates a signature over a Verifiable Credential Document
    :param vc: VC Document
    :param private_key: Private key of signer
    :return: Signature
    """
    return private_key.sign(
        bytes(json.dumps(vc), 'utf-8')
    )


def verify_vc_signature(sd_jwt, public_key: ed25519.Ed25519PublicKey):
    """
    This verifies the signature of a VC in SD-JWT format.
    Raises InvalidSignatureException if signature is incorrect.
    :param sd_jwt: VC in SD-JWT format
    :param public_key: Public Key of alleged signer
    """
    public_key.verify(
        sd_jwt.signature,
        bytes(json.dumps(sd_jwt.document.to_dict()), 'utf-8'),
    )


def is_digest_at_path(digest: str, cred_subject: dict, disclosure: list[str]):
    """
    This checks whether a digest is present in a VC under the given path
    This can be used to verify a Presentation Submission
    :param digest: Digest to be found
    :param cred_subject: The Credential Subject JSON of the VC as a dict
    :param disclosure: list of salt, claim name and claim value
    :return: True if digest is found, False otherwise
    """
    path = disclosure[1].split('.')
    for i in range(len(path) - 1):
        cred_subject = cred_subject[path[i]]
    if digest in cred_subject["_sd"]:
        return True
    return False


def _insert_claim(claim_path, claim_value, subject: dict):
    """
    This is a helper function to create a plaintext VC from a SD-JWT only containing the disclosed information.
    After return, subject contains the given claim_value at claim_path
    :param claim_path: Claim path to be inserted
    :param claim_value: Claim value to be inserted
    :param subject: Credential Subject to insert claim into
    """
    if len(claim_path) == 1:
        subject[claim_path[0]] = claim_value
        return
    if claim_path[0] not in subject:
        subject[claim_path[0]] = {}
    _insert_claim(claim_path[1:], claim_value, subject[claim_path[0]])


def verify_vp(sd_jwt: 'SD_JWT.SelectiveDisclosureJWT', resolver: Resolver, peer_did, timer) -> 'SD_JWT.W3CVerifiableCredential':
    """
    This takes an SD_JWT and checks that the hashes match, the VC is indeed signed by the claimed issuer, and it is
    within the validity period. On successful verification, the plaintext VC is returned including all disclosed claims
    :param sd_jwt: SD-JWT to verify
    :param resolver: Resolver to use to retrieve Issuer DID Doc
    :param peer_did: DID of VP Holder
    :param timer: Timer for performance measurement
    :return: VC with disclosed claim names and values in plaintext
    """
    vp = sd_jwt.document

    # check that SD-JWT subject DID matches peer's DID
    if isinstance(vp.credential_subject, dict):
        vp_did = vp.credential_subject['id']
    else:
        vp_did = vp.credential_subject.id
    if not vp_did == peer_did:
        raise HolderProofRequiredException("VP DID " + vp.id + " does not match peer's DID " + peer_did)

    # check validity period
    if vp.validFrom is not None and vp.validFrom > datetime.date.today():
        raise ValidityPeriodException("Only valid from " + vp.validFrom.isoformat())
    if vp.validUntil is not None and vp.validUntil < datetime.date.today():
        raise ValidityPeriodException("Only valid until " + vp.validUntil.isoformat())

    # check that all digests appear in the VC and create plaintext VC
    plaintext_subject = {"id": vp.credential_subject["id"],
                         "type": vp.credential_subject["type"]}
    for disclosure in sd_jwt.disclosures:
        digest = hash_disclosure(generate_disclosure(disclosure[0], disclosure[1], disclosure[2]))
        if is_digest_at_path(digest, vp.credential_subject, disclosure):
            _insert_claim(disclosure[1].split('.'), disclosure[2], plaintext_subject)
        else:
            raise DigestNotFoundException(disclosure)

    # check that Issuer signature is correct
    start = perf_counter_ns()
    issuer_verkey = resolver.resolve_for_verkey(sd_jwt.document.issuer)
    end = perf_counter_ns()
    timer.vc_resolve_time += (end - start)
    verify_vc_signature(sd_jwt, issuer_verkey)

    return SD_JWT.W3CVerifiableCredential(
        context=vp.context,
        type=vp.type,
        id=vp.id,
        issuer=vp.issuer,
        credential_subject=plaintext_subject,
        validFrom=vp.validFrom,
        validUntil=vp.validUntil,
        name=vp.name,
        description=vp.description
    )
