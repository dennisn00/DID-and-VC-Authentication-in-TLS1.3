import base58
import ed25519


def generate_keypair():
    """
    This helps to generate keypairs to use with the Von-Network, as VON is a bit particular about special chars in Verkeys
    Generated Keys are printed to the stdout
    """
    while True:
        private_key, public_key = ed25519.create_keypair()
        # this ensures forbidden chars are not present in the verkey
        if any(x in public_key.to_ascii(encoding='base64').decode('utf-8') for x in
               ('0', 'o', 'O', 'l', 'I', '+', '/', '=')):
            continue
        break
    print("Public Key (Verkey):", base58.b58encode(public_key.to_bytes()))
    print("Public Key in hex:", public_key.to_ascii(encoding='hex'))
    print("Seed:", private_key.to_seed().hex())
    print("Private Bytes:", private_key.to_seed())


generate_keypair()
