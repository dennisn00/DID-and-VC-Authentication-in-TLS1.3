import json
import logging
import subprocess
import urllib.request
from abc import ABC, abstractmethod

import base58
import multibase
from cryptography.hazmat.primitives.asymmetric import ed25519
from peerdid.dids import resolve_peer_did


class Resolver(ABC):
    """
    This Interface can be implemented to provide a custom DID resolver.
    Some example implementations are given below.
    """
    @abstractmethod
    def start(self, pool: str):
        """
        Starts the resolver and opens the pool, if necessary.
        :param pool: Pool to be opened
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Stop the resolver and free up the resources.
        """
        pass

    @abstractmethod
    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve a DID and return the verkey. If several verkeys are present, return the first one.
        :param did: DID to be resolved
        :return: Public Key present in DID Document "authentication" section.
        """
        pass


def get_skey_from_file(did, file="secrets.json") -> ed25519.Ed25519PrivateKey:
    """
    Retrieves secret key from a file. This can be used to simulate a cache, if all private keys are available local.
    Example file is given in secrets.json.
    :param did: DID to get secret key for.
    :param file: File to search for key in.
    :return: Secret key of DID Document
    """
    with open(file) as json_file:
        secrets = json.load(json_file)
    entry = secrets[did]
    if "skey_hex" in entry:
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["skey_hex"]))
    if "seed" in entry:
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(entry["seed"], 'utf-8'))


class CacheResolver(Resolver):
    """
    Implementation of the Resolver interface that uses a local file with all secret keys to simulate a cache.
    """
    def start(self, pool: str):
        pass

    def stop(self):
        pass

    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve by retrieving secret key from local file, then return corresponding private key.
        :param did: DID to be resolved
        :return: Verkey of DID Document
        """
        return get_skey_from_file(did).public_key()

    def __str__(self):
        return "CACHE"


class IndyCliResolver(Resolver):
    """
    Implementation of the Resolver interface that uses the indy-cli-rs to resolve DIDs.
    This requires the genesis file (*.txn) for each pool/ledger to be available in the indy-cli directory with the
    name <pool_name>.txn
    """
    def __init__(self):
        self.indy_cli_proc = None
        self.pool = ""

    def start(self, pool: str):
        """
        This starts the resolver by creating a subprocess and opening the pool
        :param pool: Pool to be opened.
        :return:
        """
        self.pool = pool
        self.indy_cli_proc = subprocess.Popen(
            ["indy-cli-rs"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.indy_cli_proc.stdin.write("-pool delete " + pool + "\n")
        self.indy_cli_proc.stdin.write("pool create " + pool + " gen_txn_file=./indy-cli/" + pool + ".txn\n")
        self.indy_cli_proc.stdin.write("pool connect " + pool + "\n")
        self.indy_cli_proc.stdin.flush()
        for _ in range(8):
            self.indy_cli_proc.stdout.readline()

    def stop(self):
        """
        Stops the process to free up resources
        """
        if self.indy_cli_proc:
            self.indy_cli_proc.terminate()
            self.indy_cli_proc.wait()

    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve DID using the indy-cli-rs subprocess
        :param did: DID to be resolved
        :return: Verkey of DID Document
        """
        if self.indy_cli_proc is None:
            raise Exception("indy_cli_proc is not initialized yet. Call start(pool: str) before resolving.")
        did_ending = did.split(':')[-1]
        found = False
        while not found:
            try:
                self.indy_cli_proc.stdin.write("ledger get-nym did=" + did_ending + "\n")
                self.indy_cli_proc.stdin.flush()
                verkey = None
                for _ in range(15):
                    line: str = self.indy_cli_proc.stdout.readline()
                    if line.startswith("Transaction response has not been received"):
                        break
                    if "Verkey" in line:
                        self.indy_cli_proc.stdout.readline()
                        verkey = self.indy_cli_proc.stdout.readline().split('|')[3].strip()
                        found = True
                        break
            except BrokenPipeError:
                logging.info("Broken Pipe, retrying")
            if not found and self.indy_cli_proc:
                logging.info("No verkey found, retrying")
                self.stop()
                self.start(self.pool)
        public_bytes = base58.b58decode(bytes(verkey, 'utf-8'))
        return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    def __str__(self):
        return "indy-cli-rs"


# using Peer DIDs
class PeerResolver(Resolver):
    """
    Implementation of the Resolver interface that uses the Peer Resolver. Can only be used for PeerDIDs/PrivateDIDs
    """
    def start(self, pool: str):
        pass

    def stop(self):
        pass

    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve DID using the Peer Resolver
        :param did: DID to be resolved. Needs to be a PeerDID/PrivateDID
        :return: Verkey of DID Document
        """
        res = resolve_peer_did(did)
        did_doc = json.loads(res.to_json())
        key_string = next(vm for vm in did_doc['verificationMethod'] if vm['type'] == 'Ed25519VerificationKey2020')[
            'publicKeyMultibase']
        public_bytes = bytearray(multibase.decode(bytes(key_string, 'utf-8')))[2:]
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_bytes))

    def __str__(self):
        return "PEER"


class UniversalResolver(Resolver):
    """
    Implementation of the Resolver interface that uses the Universal Resolver. Note that this assumes that an instance
    of the Universal Resolver is available at http://localhost:8080
    """
    def start(self, pool: str):
        pass

    def stop(self):
        pass

    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve DID using the Universal Resolver
        :param did: DID to be resolved
        :return: Verkey of DID Document
        """
        response = urllib.request.urlopen("http://localhost:8080/1.0/identifiers/" + did).read()
        did_doc = json.loads(response.decode('utf-8'))['didDocument']
        key_string = next(vm for vm in did_doc['verificationMethod'] if vm['type'] == 'Ed25519VerificationKey2018')[
            'publicKeyBase58']
        public_bytes = base58.b58decode(bytes(key_string, 'utf-8'))
        return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    def __str__(self):
        return "http://localhost:8080/1.0/identifiers/"


class IndyDriverResolver(Resolver):
    """
    Implementation of the Resolver interface that uses the Indy Driver of Universal Resolver. Note that this assumes
    that an instance of the Driver is available at http://localhost:8128
    """
    def start(self, pool: str):
        pass

    def stop(self):
        pass

    def resolve_for_verkey(self, did: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve DID using the Indy Driver of the Universal Resolver
        :param did: DID to be resolved
        :return: Verkey of DID Document
        """
        response = urllib.request.urlopen("http://localhost:8128/1.0/identifiers/" + did).read()
        did_doc = json.loads(response.decode('utf-8'))['didDocument']
        key_string = next(vm for vm in did_doc['verificationMethod'] if vm['type'] == 'Ed25519VerificationKey2018')[
            'publicKeyBase58']
        public_bytes = base58.b58decode(bytes(key_string, 'utf-8'))
        return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

    def __str__(self):
        return "http://localhost:8128/1.0/identifiers/"

# static instances to use for performance testing
CacheResolver = CacheResolver()
indy_cli_resolver = IndyCliResolver()
PeerResolver = PeerResolver()
UniversalResolver = UniversalResolver()
IndyDriverResolver = IndyDriverResolver()
