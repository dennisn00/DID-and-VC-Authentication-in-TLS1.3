import socket
import struct

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


class Client(CATestSubjectIF, DIDTestSubjectIF):
    """
    This class is supposed to used in connection with an agent.
    It provides client functionality.
    """

    def __init__(self, agent: Agent):
        self.private_key = agent.private_key
        self.cert_file = agent.did_certificate_file
        self.vp_exchange_protocols = agent.vp_exchange_protocols
        self.did_methods = agent.did_methods
        self.did_timer = DIDTimer()
        self.ca_timer = CATimer()


    def test_did(self, endpoint, iterations=1000, resumption=False, resolver=Resolver.CacheResolver,
                 handshake_only=True,
                 vp_exchange_cb=None, handshake_done_cb=None):
        """
        This function can be used to test the handshake performance by performing handshakes in a loop.
        Callbacks can be used to exchange VP Exchange Messages. This function does not permit application messages.
        :param endpoint: Server endpoint to connect to
        :param iterations: Number of handshakes performed
        :param resumption: If True, session resumption with PSKs is attempted on every handshake except for the first on
        :param resolver: Resolver to use for resolution of the server DID
        :param handshake_only: If True, iteration ends immediately after the handshake. If False, callbacks are called
        to exchange VPs
        :param vp_exchange_cb: Callback that is called upon receiving a VP Exchange message (submission or request).
        If the received exchange message should be answered, this callback should return the response.
        :param handshake_done_cb: Callback that is called upon finishing the handshake. This callback can return a
        VP Request to be sent to the server.
        :return: List of DIDPerformanceResults, one for each iteration
        """
        results = []
        session = None
        test_context = create_did_test_context(SSL.TLS_CLIENT_METHOD, self.private_key, self.vp_exchange_protocols,
                                               self.did_methods, self.cert_file, resumption, self.did_timer, resolver)
        for i in range(iterations):
            print('\rIteration ' + str(i + 1) + "/" + str(iterations), end='', flush=True)
            self.did_timer.reset()

            # prepare socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_connection = SSL.Connection(test_context, client_socket)
            ssl_connection.connect(endpoint)
            if resumption and session:
                ssl_connection.set_session(session)

            try:
                ssl_connection.do_handshake()

                # if resumption is used, wait for one byte of app data. This ensures that the server has actually
                # send the New Ticket Messages. Only then can the session be stored
                if resumption and handshake_only:
                    data = ssl_connection.recv(1)
                    if data:
                        session = ssl_connection.get_session()
                    if not i == 0:
                        results.append(self.did_timer.get_result())
                elif handshake_only:
                    # if no VP exchange should be done, save result and continue loop
                    results.append(self.did_timer.get_result())
                else:
                    # this performs VP exchange using the provided callbacks
                    self.did_timer.start_vc_exchange = perf_counter_ns()
                    peer_did = ssl_connection.get_ex_data(DID_INDEX)
                    send_req_answered = recv_req_answered = False
                    self.did_timer.start_vc_request_build = perf_counter_ns()
                    res, res_type = handshake_done_cb(peer_did)
                    self.did_timer.end_vc_request_build = perf_counter_ns()
                    _send_bytes(ssl_connection, res, res_type)
                    while not (send_req_answered and recv_req_answered):
                        # receive a message
                        header = ssl_connection.recv(9)
                        msg_length, msg_type = struct.unpack('>Qb', header)
                        message = ssl_connection.recv(msg_length)

                        if msg_type == MESSAGE_TYPE_PRESENTATION_EXCHANGE:
                            response, res_type = vp_exchange_cb(peer_did, message, self.did_timer, resolver)
                            if res_type == SUBMISSION_ACK:
                                # submission was accepted, no response needed
                                send_req_answered = True
                            else:
                                _send_bytes(ssl_connection, response, res_type)
                                recv_req_answered = True
                    self.did_timer.end_vc_exchange = perf_counter_ns()
                    results.append(self.did_timer.get_result())

            except SSL.Error as e:
                raise e
            finally:
                if ssl_connection.shutdown() == 0:
                    ssl_connection.shutdown()
                client_socket.close()
        print()
        return results

    def test_did_with_app_data(self, endpoint, payload, num_of_msgs, resolver=Resolver.IndyDriverResolver):
        """
        This establishes a DID authenticated TLS channel and then sends the payload repeatedly
        :param endpoint: Server endpoint to connect to
        :param payload: Payload to send repeatedly
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
        test_context = create_did_test_context(SSL.TLS_CLIENT_METHOD, self.private_key, self.vp_exchange_protocols,
                                               self.did_methods, self.cert_file,
                                               False, self.did_timer, resolver)
        self.did_timer.reset()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start_time = perf_counter_ns()
        ssl_connection = SSL.Connection(test_context, client_socket)
        ssl_connection.connect(endpoint)

        try:
            ssl_connection.do_handshake()
            for _ in range(num_of_msgs):
                send_msg(ssl_connection, payload)
            for _ in range(num_of_msgs):
                msg_len = struct.unpack('>I', recv_all(ssl_connection, 4))[0]
                data = recv_all(ssl_connection, msg_len).decode()
        finally:
            if ssl_connection.shutdown() == 0:
                ssl_connection.shutdown()
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
        :param endpoint: Server endpoint to connect to.
        :param iterations: Number of iterations for the handshake.
        :param allow_resumption: If True, session resumption is attempted after the initial, complete handshake.
        :param chain_length: Number of intermediate certificates in the used certificate chain, not including the
        client certificate and the root certificate. If 0, no intermediate certificates are used.
        :param use_ocsp_stapling: If True, OCSP Stapling is used to prove that the certificate is not revoked.
        This uses the OCSP Responder as defined in CACertificateUtils.py
        :param self_sign: If True, the certificate is self-signed and certificate chain is used.
        :return: List of CAPerformanceResults. One for each iteration.
        """
        results = []
        session = None
        test_context = create_test_context(SSL.TLS_CLIENT_METHOD, allow_resumption, chain_length,
                                           self.private_key, use_ocsp_stapling, "Client",
                                           "localhost", True, self.ca_timer, self_sign)
        for i in range(iterations):
            self.ca_timer.reset()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_connection = SSL.Connection(test_context, client_socket)

            if use_ocsp_stapling:
                ssl_connection.request_ocsp()
            if allow_resumption and session:
                ssl_connection.set_session(session)

            ssl_connection.connect(endpoint)
            ssl_connection.do_handshake()
            try:
                data = ssl_connection.recv(1)
                if data:
                    if allow_resumption:
                        session = ssl_connection.get_session()
            except Exception as e:
                print(f"Error receiving application data: {e}")
            if not allow_resumption or not i == 0:
                results.append(self.ca_timer.get_result())
            if ssl_connection.shutdown() == 0:
                ssl_connection.shutdown()
            client_socket.close()
        return results
