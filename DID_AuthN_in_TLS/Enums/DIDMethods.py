from enum import Enum


# this is a subclass of str to allow for JSON Serialization
class DIDMethod(str, Enum):
    '''
    This class allows specifying supported DID Methods.
    These values should be used in the Client Hello and Encrypted Extensions to communicate acceptable DID Methods
    (see DIDMethodsExtension.py).
    This can be extended if other methods are needed.
    '''
    PEER = "0",
    INDY = "1"

