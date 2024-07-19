import socket
import struct

from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import Agent
import Resolver
from Constants import MESSAGE_TYPE_PRESENTATION_EXCHANGE, DID_INDEX, SUBMISSION_ACK
from Utils.CACertificateUtils import *
from Utils.DIDCertificateUtils import DIDTimer, DIDTestSubjectIF, create_did_test_context


def _send_bytes(ssl_connection: SSL.Connection, message: bytes, message_type: int):
    """
       Packs message to include a header with length information (8 bytes) and message type (1 byte).
       Then the message is sent on the specified SSL Connection
       :param ssl_connection: Connection to send the message on
       :param message: Message to send
       :param message_type: Message type of message to send. See Constants.py for available types.
       :return: None
       """
    header = struct.pack('>Qb', len(message), message_type)
    ssl_connection.sendall(header + message)


def create_socket(endpoint):
    """
    Create server socket as specified endpoint and listen for incoming connections.
    :param endpoint: Endpoint to open socket on.
    :return: Opened server socket.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(endpoint)
    server_socket.listen(5)
    return server_socket


def recv_all(sock, length):
    """
    Receive on message on the given socket. Reads specified number of bytes.
    :param sock: Socket to receive message on
    :param length: Length of message in bytes
    :return: received message
    """
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise ValueError("Socket closed")
        data += more
    return data


def send_msg(sock, msg):
    """
    Send application data without type information.
    :param sock: Socket to send message on
    :param msg: Message to send
    """
    msg = msg.encode()
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


class Server(CATestSubjectIF, DIDTestSubjectIF):
    """
    This class is supposed to used in connection with an agent.
    It provides server functionality.
    """

    def __init__(self, agent: Agent):
        self.did_certificates = {agent.did: agent.did_certificate_file}
        self.private_key: Ed25519PrivateKey = agent.private_key
        self.did_timer: DIDTimer = DIDTimer()
        self.ca_timer: CATimer = CATimer()
        self.vp_exchange_protocols = agent.vp_exchange_protocols
        self.did_methods = agent.did_methods

    def _handle_sni(self, ssl_connection: SSL.Connection):
        """
        This is called if a SNI extension was present in the ClientHello.
        It searches for the matching certificate to use and loads that into the connection
        :param ssl_connection: SSL connection on which the SNI was encountered
        """
        sni_data = ssl_connection.get_servername()
        if sni_data is None:
            return
        try:
            ssl_connection.use_certificate(
                crypto.load_certificate(crypto.FILETYPE_PEM, self.did_certificates[sni_data]))
        except KeyError:
            raise SSL.Error("No certificate found for " + str(sni_data))

    # This creates a socket and listens. Upon a client request, this performs a handshake and then closes the
    # connection.
    def test_did(self, endpoint, iterations=1000, allow_resumption=True, resolver=Resolver.CacheResolver,
                 handshake_only=True, vp_exchange_cb=None, handshake_done_cb=None):
        """
        This function can be used to test the handshake performance by performing handshakes in a loop.
        Callbacks can be used to exchange VP Exchange Messages. This function does not permit application messages.
        :param endpoint: Local endpoint to use for the communication.
        :param iterations: Number of handshakes performed
        :param resumption: If True, session resumption with PSKs is offered on every handshake except for the first on
        :param resolver: Resolver to use for resolution of the client DID
        :param handshake_only: If True, iteration ends immediately after the handshake. If False, callbacks are called
        to exchange VPs
        :param vp_exchange_cb: Callback that is called upon receiving a VP Exchange message (submission or request).
        If the received exchange message should be answered, this callback should return the response.
        :param handshake_done_cb: Callback that is called upon finishing the handshake. This callback can return a
        VP Request to be sent to the client.
        :return: List of DIDPerformanceResults, one for each iteration
        """
        results = []
        server_socket = create_socket(endpoint)
        test_context = create_did_test_context(SSL.TLS_SERVER_METHOD, self.private_key, self.vp_exchange_protocols,
                                               self.did_methods, next(iter(self.did_certificates.values())),
                                               allow_resumption, self.did_timer, resolver)
        test_context.set_tlsext_servername_callback(lambda conn: self._handle_sni(conn))

        for i in range(iterations):
            print('\rIteration ' + str(i + 1) + "/" + str(iterations), end='', flush=True)
            self.did_timer.reset()
            client_socket, client_address = server_socket.accept()
            connection = SSL.Connection(test_context, client_socket)
            connection.set_accept_state()
            try:
                connection.do_handshake()
                if allow_resumption and handshake_only:
                    connection.send(b'\x00')  # Sending a single byte of application data.
                    if not i == 0:
                        results.append(self.did_timer.get_result())
                elif handshake_only:
                    results.append(self.did_timer.get_result())
                else:
                    self.did_timer.start_vc_exchange = perf_counter_ns()
                    peer_did = connection.get_ex_data(DID_INDEX)
                    send_req_answered = False
                    recv_req_answered = False
                    self.did_timer.start_vc_request_build = perf_counter_ns()
                    res, res_type = handshake_done_cb(peer_did)
                    self.did_timer.end_vc_request_build = perf_counter_ns()
                    _send_bytes(connection, res, res_type)
                    while not (send_req_answered and recv_req_answered):
                        # receive a message
                        header = connection.recv(9)
                        msg_length, msg_type = struct.unpack('>Qb', header)
                        message = connection.recv(msg_length)
                        if msg_type == MESSAGE_TYPE_PRESENTATION_EXCHANGE:
                            response, res_type = vp_exchange_cb(peer_did, message, self.did_timer, resolver)
                            if res_type == SUBMISSION_ACK:
                                # submission was accepted
                                send_req_answered = True
                            else:
                                _send_bytes(connection, response, res_type)
                                recv_req_answered = True
                    self.did_timer.end_vc_exchange = perf_counter_ns()
                    results.append(self.did_timer.get_result())
            except SSL.Error as e:
                raise e
            finally:
                if connection.shutdown() == 0:
                    connection.shutdown()
                client_socket.close()
        print()
        return results

    def test_did_with_app_data(self, endpoint, _, num_of_msgs, resolver=Resolver.IndyDriverResolver):
        """
        This establishes a DID authenticated TLS channel and then sends the payload repeatedly
        :param endpoint: Local endpoint to use for the communication.
        :param _: Payload to send repeatedly. Unused, since payload received from the client is used.
        :param num_of_msgs: This number specifies how often the payload is to be sent in each direction.
        :param resolver: Resolver to use for resolution of the server DID
        :return: Dictionary with performance information for the complete exchange. See below for definition.
        """
        results = {
            "handshake_duration": -1,
            "total_duration": -1,
            "resolve_time": -1,
            "handle_hello_time": -1,
            "cert_verify_time": -1
        }
        server_socket = create_socket(endpoint)
        test_context = create_did_test_context(SSL.TLS_SERVER_METHOD, self.private_key, self.vp_exchange_protocols,
                                               self.did_methods, next(iter(self.did_certificates.values())),
                                               False, self.did_timer, resolver)
        self.did_timer.reset()
        client_socket, client_address = server_socket.accept()
        start_time = perf_counter_ns()
        connection = SSL.Connection(test_context, client_socket)
        connection.set_accept_state()
        payload = None
        try:
            connection.do_handshake()
            for _ in range(num_of_msgs):
                msg_len = struct.unpack('>I', recv_all(connection, 4))[0]
                data = recv_all(connection, msg_len).decode()
                if not payload:
                    payload = data
            for _ in range(num_of_msgs):
                send_msg(connection, payload)
        finally:
            if connection.shutdown() == 0:
                connection.shutdown()
            client_socket.close()
        end_time = perf_counter_ns()
        res = self.did_timer.get_result()
        results["total_duration"] = (end_time - start_time) / 1_000_000
        results["handshake_duration"] = res.total_handshake_time
        results["resolve_time"] = res.resolve_time
        results["handle_hello_time"] = res.handle_hello_time
        results["cert_verify_time"] = res.cert_verify_without_resolve
        return results

    def test_ca(self, endpoint, iterations=1000, allow_resumption=False, chain_length=0,
                use_ocsp_stapling=False, self_sign=False):
        """
        This tests a CA-based handshake repeatedly. No application data is sent.
        :param endpoint: Local endpoint to use for the communication.
        :param iterations: Number of iterations for the handshake.
        :param allow_resumption: If True, session resumption is offered after the initial, complete handshake.
        :param chain_length: Number of intermediate certificates in the used certificate chain, not including the
        server certificate and the root certificate. If 0, no intermediate certificates are used.
        :param use_ocsp_stapling: If True, OCSP Stapling is used to prove that the certificate is not revoked.
        This uses the OCSP Responder as defined in CACertificateUtils.py
        :param self_sign: If True, the certificate is self-signed and certificate chain is used.
        :return: List of CAPerformanceResults. One for each iteration.
        """
        results = []
        server_socket = create_socket(endpoint)
        test_context = create_test_context(SSL.TLS_SERVER_METHOD, allow_resumption, chain_length, self.private_key,
                                           use_ocsp_stapling, 'Server', 'localhost', False, self.ca_timer, self_sign)
        for i in range(iterations):
            self.ca_timer.reset()
            client_socket, _ = server_socket.accept()
            connection = SSL.Connection(test_context, client_socket)
            connection.set_accept_state()
            connection.do_handshake()
            try:
                connection.send(b'\x00')  # Sending a single byte of application data.
            except Exception as e:
                print(f"Error sending application data: {e}")
            if not allow_resumption or not i == 0:
                # this makes sure that the first iteration of a test with resumption is not written to the results
                results.append(self.ca_timer.get_result())
            if connection.shutdown() == 0:
                connection.shutdown()
            client_socket.close()
        return results
