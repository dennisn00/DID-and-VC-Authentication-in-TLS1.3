from enum import Enum


# this is a subclass of str to allow for JSON Serialization
class PresentationExchangeProtocol(str, Enum):
    """
    This class allows specifying supported Presentation Exchange Protocol.
    These values should be used in the Client Hello and Encrypted Extensions to negotiate a single protocol supported
    by both peers (see PresentationExchangeProtocolExtension.py).
    This can be extended if other protocols are needed.
    Only the DIF protocol is actually implemented in this repo
    """
    DIF = "DIF"
    ARIES = "Aries"
