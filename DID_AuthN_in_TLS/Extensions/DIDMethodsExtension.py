import json

from Constants import DID_METHOD_INDEX
from Enums.DIDMethods import DIDMethod
from OpenSSL import SSL


class DIDMethodsExtension:
    # this is an unused extension type. If other extensions are implemented, make sure the extension types differ.
    EXT_TYPE = 0xFF02

    def __init__(self, did_methods: list[DIDMethod]):
        """
        This stores all supported DID methods.
        The DID methods actually used are connection-specific and thus will be stored in the connection object
        :param did_methods: list of DID methods supported by the caller
        """
        self.did_methods = did_methods

    def add_cb_client(self, _):
        """
        Callback for the client to use when creating a ClientHello message.
        :return: all client-supported DID methods to be added to the ClientHello.
        """
        supported_did_methods_ext = {'did_methods': self.did_methods}
        return json.dumps(supported_did_methods_ext).encode('UTF-8')

    def add_cb_server(self, ssl_connection):
        """
        Callback for the server to use when building the EncryptedExtensions.
        :param ssl_connection: Connection object
        :return: List of all DID Methods supported by client and server, if any. If the client did not send DID methods,
        or no DID method is supported by both peers, return None.
        """
        try:
            supporter_did_methods_ext = {'did_methods': ssl_connection.get_ex_data(DID_METHOD_INDEX)}
            return json.dumps(supporter_did_methods_ext).encode('UTF-8')
        except:
            return None

    def parse_cb_server(self, ssl_connection, inbytes):
        """
        Callback for the server to call when this extension has been found in a Client Hello.
        This stores all DID methods supported by both peers in the connection object.
        :param ssl_connection: Connection object
        :param inbytes: The content of the received extension
        """
        did_method_ext = json.loads(inbytes.decode('utf-8'))
        client_did_methods = did_method_ext['did_methods']
        selected_did_methods = [method for method in self.did_methods if method in client_did_methods]
        ssl_connection.set_ex_data(DID_METHOD_INDEX, selected_did_methods)

    def parse_cb_client(self, ssl_connection, inbytes):
        """
        Callback for the client to call when this extension has been found in the Encrypted Extensions.
        This writes the received DID methods to the connection object.
        :param ssl_connection: Connection object
        :param inbytes: Content of the received extension
        """
        did_method_ext = json.loads(inbytes.decode('utf-8'))
        ssl_connection.set_ex_data(DID_METHOD_INDEX, did_method_ext['did_methods'])

    def add_to_context(self, ssl_ctx):
        """
        This registers the extension within the context using the callbacks specified above.
        After calling this, the callbacks above are called on every new connection when the TLS handshake is performed.
        :param ssl_ctx: Context that this extension should be used in
        """
        add_cb_helper = lambda ssl, ext_type, ctx: (
            self.add_cb_client(ssl)) if ctx == SSL.SSL_EXT_CLIENT_HELLO else self.add_cb_server(ssl)

        parse_cb_helper = lambda ssl, ext_type, ctx, inbytes: (
            self.parse_cb_server(ssl, inbytes)) if ctx == SSL.SSL_EXT_CLIENT_HELLO else self.parse_cb_client(ssl,
                                                                                                             inbytes)

        return ssl_ctx.add_custom_ext(self.EXT_TYPE, SSL.SSL_EXT_CLIENT_HELLO | SSL.SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                      add_cb_helper, parse_cb_helper)
