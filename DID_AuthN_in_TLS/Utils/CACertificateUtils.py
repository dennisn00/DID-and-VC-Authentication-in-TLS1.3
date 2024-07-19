import datetime
import os.path
from abc import abstractmethod, ABC
from dataclasses import dataclass
from time import perf_counter_ns

from OpenSSL import SSL
from OpenSSL.crypto import X509, PKey
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509 import Certificate, ocsp
from cryptography.x509.ocsp import OCSPResponseBuilder, load_der_ocsp_response, OCSPResponse, OCSPResponseStatus

# see Readme for explanation
_root_ca_cert_path = "./tmp/root_ca_cert.pem"
root_ca_key_path = "./tmp/root_ca_skey.pem"
ocsp_cert_path = "./tmp/ocsp_cert.pem"
ocsp_key_path = "./tmp/ocsp_skey.pem"


class CATestSubjectIF(ABC):
    """
    This interface provides a single function for testing CA-based mTLS handshakes.
    This should be implemented by a client agent as well as a server agent.
    This makes it easier for testing, as client and server can be treated the same when calling the testing function.
    """

    @abstractmethod
    def test_ca(self, endpoint, iterations=1000, allow_resumption=False, chain_length=0,
                use_ocsp_stapling=False, self_sign=False):
        """
        Run multiple mTLS handshakes using CA-issued certificates and measure the performance
        :param endpoint: Tuple consisting of Server IP-Address and Server Port, e.g. ('192.168.178.100', 50000)
        :param iterations: Number of handshakes to perform.
        :param allow_resumption: If set to True, only the first handshake is a complete handshake.
        All following handshakes are resumed using TLS Pre-Shared Keys, skipping peer authentication.
        :param chain_length: Number of intermediate certificates in the chain.
        :param use_ocsp_stapling: If True, OCSP Stapling is used. Requires OCSP Certificate and Secret key to
        be present at path specified above
        :param self_sign: if True, certifcates are self-signed, no CA is used.
        :return: List of CAPerformanceResults, one for each iteration
        """
        pass


@dataclass
class CAPerformanceResult:
    """
    Stores the performance results of a single handshake, all time values in ms.
    The values will differ for client and server, as they are measure differently.
    Client: Total handshake time starts when ClientHello is sent, ends when Finished is sent
    Server: Total handshake time starts when ClientHello is received, ends when Client Finished is verified.
    """
    total_handshake_time: float
    handle_hello_time: float  # time to handle the hello messages
    cert_verify_time: float  # time to verify the peer's certificate message
    sent_cert_msg_size: int  # size of the certificate message sent in bytes


class CATimer:
    """
    This class stores timestamps for a single handshake to later create a CAPerformanceResult.
    To work properly, the callbacks provided need to be passed to set_info_callback and set_message_callback, resp.
    See create_test_context() in this file as an example
    """

    def __init__(self):
        self.start_time_handshake = 0
        self.end_time_handshake = 0
        self.end_time_hello = 0
        self.start_time_hello = 0
        self.start_time_cert_verify = 0
        self.end_time_cert_verify = 0
        self.sent_cert_msg_size = 0

    def reset(self):
        self.__init__()

    def get_result(self):
        """
        :return: CAPerformanceResult for this mTLS handshake
        """
        return CAPerformanceResult((self.end_time_handshake - self.start_time_handshake) / 1_000_000,
                                   (self.end_time_hello - self.start_time_hello) / 1_000_000,
                                   (self.end_time_cert_verify - self.start_time_cert_verify) / 1_000_000,
                                   self.sent_cert_msg_size)

    def ca_timer_server_cb(self, _, where):
        """
        Callback for the server to use. This needs to be passed to ctx.set_info_callback().
        Not required for the client, as the handshake termination is marked by sending the finished message.
        :param _: Connection object
        :param where: OpenSSL code for the event that triggered this callback being called.
        """
        if where == SSL.SSL_CB_HANDSHAKE_DONE:
            self.end_time_handshake = perf_counter_ns()
            # on the server side, certificate verification finishes when the handshake is done
            # the message_callback cannot catch that, so it's done here
            # if session_resumption is used, end_time_cert_verify should not be set
            # this is to ensure by checking that start_time_cert_verify has been set
            if self.end_time_cert_verify == 0 and not self.start_time_cert_verify == 0:
                self.end_time_cert_verify = self.end_time_handshake

    def message_callback(self, write, content_type, msg: bytes):
        """
        Callback for both peers to use to be notified of incoming and outgoing messages, for performance measurement.
        This needs to be passed to ctx.set_message_callback().
        :param write: True if the message triggering this call was written by the peer, False if message was received.
        :param content_type: OpenSSL Code for Content Type (Application data, handshake message, ...).
        :param msg: The message sent/received
        """
        if not content_type == 22:
            # Message is not a handshake message
            return
        now = perf_counter_ns()
        # msg_type determines which handshake message was sent/received.
        msg_type = int(msg.hex()[:2], 16)
        if msg_type == 1:  # Client Hello
            self.start_time_handshake = now
            if not write:
                self.start_time_hello = now
        if msg_type == 2:  # Server Hello
            if write:
                # for the server, writing the Server Hello indicates that the Client Hello Handling is completed
                self.end_time_hello = now
            else:
                # for the client, receving the Server Hello indicates that Hello Handling is starting
                self.start_time_hello = now
        if msg_type == 11:  # Certificate Message
            if write:
                self.sent_cert_msg_size = len(msg)
                if not self.start_time_cert_verify == 0:
                    # This is only set on the client side. Server use the info_callback above to set this
                    # Client writing the Certificate Message indicates that certificate verification is completed.
                    self.end_time_cert_verify = now
            else:
                self.start_time_cert_verify = now
        if msg_type == 8 and not write:  # Encrypted Extensions were read -> handling of Server Hello is done.
            self.end_time_hello = now


def write_cert(path, cert: Certificate):
    """
    Write a certificate to the file system.
    :param path: Path to write the certificate to
    :param cert: Certificate to write
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def write_skey(path, skey: ed25519.Ed25519PrivateKey):
    """
    Write secret key to file system
    :param path: Path to write to
    :param skey: Secret key to write to file system
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(skey.private_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption()))


def read_skey(path) -> ed25519.Ed25519PrivateKey:
    """
    Read the secret key from the file system
    :param path: Path to the key file
    :return: Private key
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)


def read_cert(path) -> Certificate:
    """
    Read certificate from file system
    :param path: Path to certificate file
    :return: Certificate
    """
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def get_ocsp_cert() -> Certificate:
    """
    Returns OCSP Responder certificate.
    If no such certificate exists at standard path yet, it is created.
    :return: OCSP Responder certificate
    """
    if not os.path.isfile(ocsp_cert_path):
        build_ocsp_cert()
    return read_cert(ocsp_cert_path)


def _build_root_ca_cert():
    """
    Creates Root CA Certificate and writes it to standard path defined above.
    Hardcoded private key is used to allow two peers on separate machines to use the same root CA.
    """
    root_ca_key: ed25519.Ed25519PrivateKey = ed25519.Ed25519PrivateKey.from_private_bytes(
        b'\x18Y\xa3\x9c\x19\xbd\xd1[(2\xdb\x12\xd0\xb5\xfb\xcbh\xdb\x86\xd8i\xbd\x02\xb8\xa2\xa9\xdag\xc0\xc0\xaa\xf6')
    write_skey(root_ca_key_path, root_ca_key)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Berlin"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ROOT CERTIFICATE AUTHORITY"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")
    ])
    cert = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer)
            .public_key(root_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100))
            .add_extension(x509.BasicConstraints(True, None), True)
            .sign(root_ca_key, algorithm=None))
    write_cert(_root_ca_cert_path, cert)


def get_root_ca_cert() -> Certificate:
    """
    Returns Root CA certificate.
    If no such certificate exists at standard path yet, it is created.
    :return: Root CA certificate
    """
    if not os.path.isfile(_root_ca_cert_path):
        _build_root_ca_cert()
    return read_cert(_root_ca_cert_path)


def create_certificate_chain(chain_length, org_name, common_name, agent_skey: ed25519.Ed25519PrivateKey,
                             self_sign=False) -> list[Certificate]:
    """
    Creates a certificate chain of variable length for an entity up to the standard root CA
    :param chain_length: Number of intermediate certificates. Root and entity certificate are not included in this.
    Set to zero if no intermediate certificates should be used.
    :param org_name: Organisation Name for x509 Name
    :param common_name: Common Name for x509 Name
    :param agent_skey: Agent private key, for possible self-signing and for deriving public key
    :param self_sign: True if entity certificate should be self-signed. This creates a chain of a single certificate.
    :return: List of Certificates that form the chain, with entity certificate at first position and root certificate
    in the end.
    """
    if self_sign:
        chain_length = 0
    certificates: list[Certificate] = [get_root_ca_cert()] if not self_sign else []
    last_key: ed25519.Ed25519PrivateKey = read_skey(root_ca_key_path) if not self_sign else agent_skey
    for i in range(chain_length + 1):
        if i == chain_length:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Berlin"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
            ])
            private_key = None
            public_key = agent_skey.public_key()
        else:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Berlin"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA " + str(i))
            ])
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        cert = ((x509.CertificateBuilder().subject_name(subject)
                 .issuer_name(certificates[0].subject if not self_sign else subject)
                 .public_key(public_key)
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                 .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100))
                 .add_extension(x509.BasicConstraints(i != chain_length, None), critical=True))
                .sign(last_key, algorithm=None))
        certificates.insert(0, cert)
        last_key = private_key
    return certificates


def build_ocsp_cert():
    """
    Create OCSP Certificate. Uses hardcoded private key to allow two peers on separate machines to use the same
    OCSP Responder.
    Certificate is written to standard path defined above.
    """
    ocsp_key = ed25519.Ed25519PrivateKey = ed25519.Ed25519PrivateKey.from_private_bytes(
        b'M\x97\xb9\xaf\xb5\xe2\xf6\xf3.\x0e\xad\xc4_{/\xe2\r:\x1e\xc0N\xae\xf7\xf3^Z\xb0\xed\xba\xe3\x07\xb2')
    write_skey(ocsp_key_path, ocsp_key)
    issuer: x509.Name = get_root_ca_cert().subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")
    ])
    root_ca_key: ed25519.Ed25519PrivateKey = read_skey(root_ca_key_path)
    cert = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer)
            .public_key(ocsp_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100))
            .sign(root_ca_key, algorithm=None))
    write_cert(ocsp_cert_path, cert)


def create_ocsp_response(chain: list[Certificate]) -> bytes:
    """
    Creates an OCSP Response to be stapled to certificate chain
    :param chain: Chain of certificates to staple response to
    :return: response bytes
    """
    server_cert = chain[0]
    ocsp_key: ed25519.Ed25519PrivateKey = read_skey(ocsp_key_path)
    builder = OCSPResponseBuilder()
    builder = builder.add_response(
        cert=server_cert,
        issuer=chain[1],
        algorithm=hashes.SHA256(),
        cert_status=x509.ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.datetime.now() - datetime.timedelta(days=1),
        next_update=datetime.datetime.now() + datetime.timedelta(days=7),
        revocation_time=None,
        revocation_reason=None
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, get_ocsp_cert())

    ocsp_response = builder.sign(
        private_key=ocsp_key,
        algorithm=None
    ).public_bytes(serialization.Encoding.DER)

    return ocsp_response


def verify_ocsp_response(_, res: bytes, __) -> bool:
    """
    Verify revocation status of a received certificate using the stapled ocsp response
    :param _: Connection Object
    :param res: OCSP Response bytes
    :param __: Arbitrary data
    :return: True if response is valid, false otherwise
    """
    ocsp_response: OCSPResponse = load_der_ocsp_response(res)

    if not ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
        return False

    now = datetime.datetime.now()
    if now < ocsp_response.this_update or now > ocsp_response.next_update:
        # OCSP Response is not valid yet/anymore
        return False

    # verify signature, this will throw an exception if unsuccessful
    get_ocsp_cert().public_key().verify(ocsp_response.signature, ocsp_response.tbs_response_bytes)

    return True


def create_test_context(method: int, allow_resumption, chain_length, skey: ed25519.Ed25519PrivateKey, use_ocsp_stapling,
                        org_name, common_name, is_client, ca_timer: CATimer, self_sign=False) -> SSL.Context:
    """
    Creates an SSL Context for testing.
    :param method: OpenSSL Method Code to indicate whether subject is client (SSL.TLS_CLIENT_METHOD) or
    server (SSL.TLS_SERVER_METHOD).
    :param allow_resumption: If True, peers try to resume session after an initial, full handshake. Speeds up connection
    as authentication only needs to be performed once.
    :param chain_length: Number of intermediate certificates to be used by this peer
    :param skey: Secret Key of the subject.
    :param use_ocsp_stapling: If True, OCSP Stapling is used for Revocation Checking.
    :param org_name: Organisation Name for the x509 Name field
    :param common_name: Common Name for the x509 Name field
    :param is_client: True if subject is the client, false if subject is server
    :param ca_timer: CATimer object. Will be filled with performance data during the handshake
    :param self_sign: If True, no CAs are used and certificates are self-signed
    :return: SSL Context for testing
    """
    test_context = SSL.Context(method)
    test_context.use_privatekey(PKey.from_cryptography_key(skey))

    # set custom verification for self-signed certificates
    def self_sign_verify(_, __, error_number, ___, ok):
        if error_number == SSL.X509VerificationCodes.ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            # This error can be ignored as we expect self-signed certificates
            return True
        if error_number != 0:
            print(error_number)
        return ok

    # standard certificate verification does not work if self-signed certificates are used, this custom callback is used
    verify_cb = None if not self_sign else self_sign_verify
    test_context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)

    # set cache for resumption
    if not allow_resumption:
        test_context.set_session_cache_mode(SSL.SESS_CACHE_OFF)
    elif is_client:
        test_context.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
    else:
        test_context.set_session_cache_mode(SSL.SESS_CACHE_SERVER)
        test_context.set_session_id(b"performance_test")

    # create certificate chain
    cert_chain: list[Certificate] = create_certificate_chain(chain_length, org_name, common_name, skey, self_sign)

    # add certificates to context
    for cert in cert_chain[1:]:
        test_context.add_extra_chain_cert(X509.from_cryptography(cert))
    test_context.use_certificate(X509.from_cryptography(cert_chain[0]))
    if not self_sign:
        test_context.get_cert_store().add_cert(X509.from_cryptography(get_root_ca_cert()))

    # add OCSP Stapling
    if use_ocsp_stapling:
        ocsp_response: bytes = create_ocsp_response(cert_chain)
        if is_client:
            test_context.set_ocsp_client_callback(verify_ocsp_response)
        else:
            test_context.set_ocsp_server_callback(lambda _, data: data, ocsp_response)

    # set callbacks for performance measurement
    test_context.set_info_callback(lambda conn, where, _: ca_timer.ca_timer_server_cb(conn, where))
    test_context.set_msg_callback(
        lambda write, _, content_type, msg, __: ca_timer.message_callback(write, content_type, msg))
    return test_context
