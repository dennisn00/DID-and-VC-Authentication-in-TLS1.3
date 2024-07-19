import datetime
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from time import perf_counter_ns

import Resolver
from Constants import DID_INDEX
from Extensions.DIDMethodsExtension import DIDMethodsExtension
from Extensions.PresentationExchangeProtocolExtension import PresentationExchangeProtocolExtension
from OpenSSL import SSL
from OpenSSL.SSL import Context
from OpenSSL.crypto import PKey
from Utils.Exceptions import CertificateKeyDoesNotMatchException
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID


class DIDTestSubjectIF(ABC):
    """
    This interface provides two functions for testing DID-based mTLS handshakes including VC exchange.
    This should be implemented by a client agent as well as a server agent.
    This makes it easier for testing, as client and server can be treated the same when calling the testing function.
    """
    @abstractmethod
    def test_did(self, endpoint, iterations=1000, allow_resumption=False, resolver="", handshake_only=True,
                 vp_exchange_cb=None, handshake_done_cb=None):
        """
        Run multiple mTLS handshakes using DID-based, self-signed certificates and VCs and meaasure the performance
        :param endpoint: Tuple consisting of Server IP-Address and Server Port, e.g. ('192.168.178.100', 50000)
        :param iterations: Number of handshakes to perform.
        :param allow_resumption: If set to True, only the first handshake is a complete handshake. All following handshakes
        are resumed using TLS Pre-Shared Keys, skipping peer authentication.
        :param resolver: DID Resolver to use for resolving DIDs of peer and VC Issuer.
        Resolver.py provides resolver instances to use.
        :param handshake_only: If True, only the mTLS handshake is performed, providing DID Authentication,
        If False, VCs are exchanged too.
        :param vp_exchange_cb: Callback function that is called when a VP Exchange message (for example, a VP Request or a VP Submission)
        is received. This function should return a response (e.g. a VP Submission or application data).
        :param handshake_done_cb: Callback function that is called when the handshake is completed.
        This should return aither application data to send or a VP Request.
        :return: List of DIDPerformanceResults, one for each iteration
        """
        pass

    @abstractmethod
    def test_did_with_app_data(self, endpoint, payload, num_of_msgs, resolver=Resolver.IndyDriverResolver):
        """
        Runs a single mTLS handshakes using DID-based, self-signed certificates and
        exchanges application data on the TLS-secured channel. Measures the performance.
        :param endpoint: Tuple consisting of Server IP-Address and Server Port, e.g. ('192.168.178.100', 50000)
        :param payload: Dummy payload that is send in each application data message.
        :param num_of_msgs: Number of application data messages to exchange in each direction.
        :param resolver: DID Resolver to use for resolving DIDs of peer and VC Issuer.
        Resolver.py provides resolver instances to use.
        :return: Dictionary with Performance Results.
        """
        pass


@dataclass
class DidPerformanceResult:
    """
    Stores the performance results of a single handshake and subsequent vp exhange,
    all time values in ms.
    The values will differ for client and server, as they are measure differently.
    Client: Total handshake time starts when ClientHello is sent, ends when Finished is sent
    Server: Total handshake time starts when ClientHello is received, ends when Client Finished is verified.
    """
    total_handshake_time: float
    resolve_time: float # time to resolve DID of peer
    handle_hello_time: float # time to handle the hello messages
    cert_verify_without_resolve: float # time to verify the peer's certificate message, resolving time is excluded
    vc_exchange: float # total time for VC Exchange
    vc_request_build: float # time to build VC Request
    vc_request_handle: float # time to handle received VC request and build response
    vc_submission_handle: float # time to handle received submission, resolving not included
    vc_resolve_time: float # resolving of Issuer DID for received VP
    sent_cert_msg_size: int # size of the certificate message sent in bytes


class DIDTimer:
    """
    This class stores timestamps for a single handshake and VC exchange to later create a DIDPerformanceResult.
    To work properly, the callbacks provided need to be passed to set_info_callback and set_message_callback, resp.
    See create_did_test_context() in this file as an example
    """
    def __init__(self):
        self.start_time_handshake = 0
        self.end_time_handshake = 0
        self.start_time_hello = 0
        self.end_time_hello = 0
        self.start_time_resolve = 0
        self.end_time_resolve = 0
        self.start_time_cert_verify = 0
        self.end_time_cert_verify = 0
        self.sent_cert_msg_size = 0
        self.start_vc_exchange = 0
        self.end_vc_exchange = 0
        self.start_vc_request_build = 0
        self.end_vc_request_build = 0
        self.start_vc_request_handle = 0
        self.end_vc_request_handle = 0
        self.start_vc_submission_handle = 0
        self.end_vc_submission_handle = 0
        self.vc_resolve_time = 0

    def reset(self):
        self.__init__()

    def get_result(self):
        """
        :return: DIDPerformanceResult for this mTLS handshake and VC exchange
        """
        resolve_time = self.end_time_resolve - self.start_time_resolve
        return DidPerformanceResult((self.end_time_handshake - self.start_time_handshake) / 1_000_000,
                                    resolve_time / 1_000_000,
                                    (self.end_time_hello - self.start_time_hello) / 1_000_000,
                                    (self.end_time_cert_verify - self.start_time_cert_verify - resolve_time) / 1_000_000,
                                    (self.end_vc_exchange - self.start_vc_exchange) / 1_000_000,
                                    (self.end_vc_request_build - self.start_vc_request_build) / 1_000_000,
                                    (self.end_vc_request_handle - self.start_vc_request_handle) / 1_000_000,
                                    (self.end_vc_submission_handle - self.start_vc_submission_handle) / 1_000_000,
                                    self.vc_resolve_time / 1_000_000,
                                    self.sent_cert_msg_size)

    def did_info_callback(self, _, where):
        """
        Callback for the server to use. This needs to be passed to ctx.set_info_callback().
        Not required for the client, as the handshake termination is marked by sending the finished message.
        :param _: Connection object
        :param where: OpenSSL code for the event that triggered this callback being called.
        """
        if where == SSL.SSL_CB_HANDSHAKE_DONE:
            self.end_time_handshake = perf_counter_ns()
            if self.end_time_cert_verify == 0 and not self.start_time_cert_verify == 0:
                self.end_time_cert_verify = self.end_time_handshake

    def message_callback(self, write, content_type, msg: bytes):
        """
        Callback for both peers to use to be notified of incoming and outgoing messages, for performance measurement.
        This needs to be passed to ctx.set_message_callback().
        :param write: True if the message the triggered this call was written by the peer, False if message was received.
        :param content_type: OpenSSL Code for Content Type (Application data, handshake message, ...).
        :param msg: The message sent/received
        """
        # content types: HANDSHAKE (22), RT_HEADER (256), CHANGE_CIPHER_SPEC (20), ALERT (21)
        if not content_type == 22:
            return
        now = perf_counter_ns()
        msg_type = int(msg.hex()[:2], 16)
        if msg_type == 1:  # Client Hello
            self.start_time_handshake = now
            if not write:
                self.start_time_hello = now
        if msg_type == 2:  # Server Hello
            if write:
                self.end_time_hello = now
            else:
                self.start_time_hello = now
        if msg_type == 11:  # Certificates
            if write:
                self.sent_cert_msg_size = len(msg)
                if not self.start_time_cert_verify == 0:
                    # This is only set on the client side. Server use the info_callback above to set this
                    self.end_time_cert_verify = now
            else:
                self.start_time_cert_verify = now
        if msg_type == 8 and not write:  # Encrypted Extensions were read -> handling of Server Hello is done.
            self.end_time_hello = now


#
# Returns True on success, False otherwise
def verify_did_cert(connection: SSL.Connection, x509_cert: x509, error_num, resolver, timer: DIDTimer):
    """
    This receives a certificate and checks that the DID is present in the SAN field.
    Then, the corresponding DID Document is looked up to check that the public keys match.
    :param connection: Connection object on which the certificate was received
    :param x509_cert: Received certificate
    :param error_num: Error Number from OpenSSL pre-verification.
    :param resolver: Resolver object to resolve DID of peer
    :param timer: Timer object to fill with time measurements
    :return: True if certificate is accepted, False otherwise
    """

    # OpenSSL will call verify_cert with the same cert repeatedly if there are errors detected with the cert.
    # We only want to perform actual verification (with ledger access) once, namely when error_num == 0
    # Thus, all errors should be handled before actual verification starts.
    if error_num in (
            SSL.X509VerificationCodes.ERR_CERT_HAS_EXPIRED, SSL.X509VerificationCodes.ERR_CERT_NOT_YET_VALID):
        print("Received certificate is expired or not valid yet. Aborting connection")
        return False
    if error_num == SSL.X509VerificationCodes.ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        # This error can be ignored as we expect self-signed certificates
        return True
    if error_num != 0:
        print("Encountered unknown error number: " + str(error_num))
        return False

    # actual certificate verification
    timer.start_time_cert_verify = perf_counter_ns()

    # extract DID and Public Key from certificate
    cert: x509.Certificate = x509_cert.to_cryptography()
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    did = san.value.get_values_for_type(x509.UniformResourceIdentifier)[0]
    certificate_key = cert.public_key()

    # resolve DID
    timer.start_time_resolve = perf_counter_ns()
    resolved_key = resolver.resolve_for_verkey(did)
    timer.end_time_resolve = perf_counter_ns()

    # check that DIDs match between the DID Document and the certificate
    if not certificate_key.public_bytes_raw() == resolved_key.public_bytes_raw():
        raise CertificateKeyDoesNotMatchException(resolved_key, certificate_key)

    # store DID in the connection object and finish
    connection.set_ex_data(DID_INDEX, did)
    timer.end_time_cert_verify = perf_counter_ns()
    return True


def generate_did_certificate(common_name, public_key, private_key, did, cert_file):
    """
    Generates a self-signed certificate with provided DID in the Subject Alternative Name Field
    :param common_name: Common Name of Subject. Can be a dummy-value
    :param public_key: Public key of subject
    :param private_key: Private key of subject for self-signing
    :param did: DID of subject
    :param cert_file: Path to store the certificate in
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject  # certificate is self-signed
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
    ).add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(did)]),
        critical=False
        # if critical is false, a recipient of this cert will not abort if he does not recognize the extension
    ).sign(private_key, algorithm=None)
    os.makedirs(os.path.dirname(cert_file), exist_ok=True)
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def create_did_test_context(method: int, skey: ed25519.Ed25519PrivateKey, vp_protocols, did_methods, cert_file,
                            allow_resumption, did_timer: DIDTimer, resolver: Resolver) -> Context:
    """
    Creates an SSL Context for testing.
    :param method: OpenSSL Method Code to indicate whether subject is client (SSL.TLS_CLIENT_METHOD) or server (SSL.TLS_SERVER_METHOD).
    :param skey: Secret Key of the subject.
    :param vp_protocols: list of supported presentation exchange protocols.
    :param did_methods: list of supported DID Methods. The subject must be able to resolve DIDs for these methods.
    :param cert_file: Path to store the certificate file to
    :param allow_resumption: If True, peers try to resume session after an initial, full handshake. Speeds up connection
    as authentication only needs to be performed once.
    :param did_timer: DIDTimer object. Will be filled with performance data during the handshake
    :param resolver: Resolver object to use for DID Resolution.
    :return: SSL Context for testing
    """

    test_context = SSL.Context(method)
    test_context.use_privatekey(PKey.from_cryptography_key(skey))
    test_context.use_certificate_file(cert_file, filetype=SSL.FILETYPE_PEM)

    # add extensions
    did_methods_extension = DIDMethodsExtension(did_methods)
    did_methods_extension.add_to_context(test_context)
    exchange_prot_extension = PresentationExchangeProtocolExtension(vp_protocols)
    exchange_prot_extension.add_to_context(test_context)

    # set up for resumption
    if not allow_resumption:
        test_context.set_session_cache_mode(SSL.SESS_CACHE_OFF)
    else:
        test_context.set_session_cache_mode(SSL.SESS_CACHE_BOTH)
        test_context.set_session_id(b"did_performance_test")

    # set up callbacks for time measurements
    test_context.set_info_callback(lambda conn, where, _: did_timer.did_info_callback(conn, where))
    test_context.set_msg_callback(
        lambda write, _, content_type, msg, __: did_timer.message_callback(write, content_type, msg))
    test_context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                            lambda conn, cert, err_num, _, __: verify_did_cert(conn, cert, err_num, resolver,
                                                                               did_timer))
    return test_context
