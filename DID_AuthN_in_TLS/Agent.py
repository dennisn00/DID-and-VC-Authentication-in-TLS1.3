
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import Holder
from Client import Client
from Issuer import PassportIssuer, UniversityDegreeIssuer, OrganizationIssuer
from SD_JWT import SelectiveDisclosureJWT
from Server import Server
from Utils.DIDCertificateUtils import generate_did_certificate
from Verifier import Verifier


class Agent:
    """
    This class holds all information for a single actor in the ecosystem.
    It can be used to create an associated client, server, verifier, holder and issuer with all connected functionalities.
    """

    def __init__(self, did, private_key: Ed25519PrivateKey, common_name,
                 vp_exchange_protocols, did_methods):
        self.did = did
        self.private_key: Ed25519PrivateKey = private_key
        self.common_name = common_name
        self.did_certificate_file = "./tmp/" + "".join(x for x in common_name if x.isalnum()) + "_cert.pem"
        generate_did_certificate(common_name, private_key.public_key(), private_key, did, self.did_certificate_file)
        self.vp_exchange_protocols = vp_exchange_protocols
        self.did_methods = did_methods
        self.sd_jwts: list[SelectiveDisclosureJWT] = []

        # these will be initialized lazily
        self._server = None
        self._client = None
        self._passport_issuer = None
        self._degree_issuer = None
        self._organization_name_issuer = None
        self._verifier = None
        self._holder = None

    def get_server(self):
        if self._server is None:
            self._server = Server(self)
        return self._server

    def get_client(self):
        if self._client is None:
            self._client = Client(self)
        return self._client

    def get_passport_issuer(self):
        if self._passport_issuer is None:
            self._passport_issuer = PassportIssuer(self)
        return self._passport_issuer

    def get_degree_issuer(self):
        if self._degree_issuer is None:
            self._degree_issuer = UniversityDegreeIssuer(self)
        return self._degree_issuer

    def get_org_name_issuer(self):
        if self._organization_name_issuer is None:
            self._organization_name_issuer = OrganizationIssuer(self)
        return self._organization_name_issuer

    def get_verifier(self):
        if self._verifier is None:
            self._verifier = Verifier()
        return self._verifier

    def get_holder(self) -> Holder:
        if self._holder is None:
            self._holder = Holder.Holder(self)
        return self._holder
