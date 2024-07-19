class DigestNotFoundException(Exception):
    def __init__(self, disclosure_missing):
        super().__init__("Digest was not found for disclosure " + str(disclosure_missing))


class ValidityPeriodException(Exception):
    def __init__(self, message):
        super().__init__(message)


class CertificateKeyDoesNotMatchException(Exception):
    def __init__(self, resolved_key, cert_key):
        super().__init__("Certificate Key does not match key provided in DID Document.\n"
                         "Key in DID Document is " + str(resolved_key) + "\n"
                         "Key in certificate is " + str(cert_key))


class HolderProofRequiredException(Exception):
    def __init__(self, message):
        super().__init__(message)