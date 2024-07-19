import json

from Constants import PRESENTATION_EXCHANGE_PROTOCOL_INDEX
from Enums.PresentationExchangeProtocol import PresentationExchangeProtocol
from OpenSSL import SSL


class PresentationExchangeProtocolExtension:
    # this is an unused extension type. If other extensions are implemented, make sure the extension types differ.
    EXT_TYPE = 0xFF03

    def __init__(self, presentation_exchange_protocols: list[PresentationExchangeProtocol]):
        """
        This stores all supported presentation exchange protocols.
        The protocols actually used are connection-specific and thus will be stored in the connection object
        :param presentation_exchange_protocols: List of protocols supported by the peer
        """
        self.presentation_exchange_protocols = presentation_exchange_protocols

    def add_cb_client(self, _):
        """
        Callback for the client to use when creating a ClientHello message.
        :return: all client-supported presentation exchange protocols to be added to the ClientHello.
        """
        pep_ext = {'vp_protocols': self.presentation_exchange_protocols}
        return json.dumps(pep_ext).encode('UTF-8')

    def add_cb_server(self, ssl_connection):
        """
        Callback for the server to use when building the EncryptedExtensions.
        :param ssl_connection: Connection object
        :return: List of all presentation exchange protocols supported by client and server, if any. If the client did
        not send any protocols, or no protocols is supported by both peers, return None.
        """
        try:
            protocols_ext = {'vp_protocols': ssl_connection.get_ex_data(PRESENTATION_EXCHANGE_PROTOCOL_INDEX)}
            return json.dumps(protocols_ext).encode('UTF-8')
        except:
            return None

    def parse_cb_server(self, ssl_connection, inbytes):
        """
        Callback for the server to call when this extension has been found in a Client Hello.
        This stores all protocols supported by both peers in the connection object.
        :param ssl_connection: Connection object
        :param inbytes: The content of the received extension
        """
        protocols_ext = json.loads(inbytes.decode('utf-8'))
        client_protocols = protocols_ext['vp_protocols']
        selected_protocol = next((p for p in self.presentation_exchange_protocols if p in client_protocols), None)
        ssl_connection.set_ex_data(PRESENTATION_EXCHANGE_PROTOCOL_INDEX, selected_protocol)

    def parse_cb_client(self, ssl_connection, inbytes):
        """
        Callback for the client to call when this extension has been found in the Encrypted Extensions.
        This writes the received protocols to the connection object.
        :param ssl_connection: Connection object
        :param inbytes: Content of the received extension
        """
        pep_ext = json.loads(inbytes.decode('utf-8'))
        ssl_connection.set_ex_data(PRESENTATION_EXCHANGE_PROTOCOL_INDEX, pep_ext['vp_protocols'])

    def add_to_context(self, ssl_ctx):
        """
        This registers the extension within the context using the callbacks specified above.
        After calling this, the callbacks above are called on every new connection when the TLS handshake is performed.
        :param ssl_ctx: Context that this extension should be used in
        """
        add_cb_helper = lambda ssl, ext_type, ctx: (
            self.add_cb_client(ssl)) if ctx == SSL.SSL_EXT_CLIENT_HELLO else self.add_cb_server(ssl)
        parse_cb_helper = lambda ssl, ext_type, ctx, inbytes: (self.parse_cb_server(ssl, inbytes)) \
            if ctx == SSL.SSL_EXT_CLIENT_HELLO else self.parse_cb_client(ssl, inbytes)
        return ssl_ctx.add_custom_ext(self.EXT_TYPE, SSL.SSL_EXT_CLIENT_HELLO | SSL.SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                      add_cb_helper, parse_cb_helper)
