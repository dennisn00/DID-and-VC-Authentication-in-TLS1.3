## Setup

### Install Requirements
In a terminal, run `openssl version` to check the install version of OpenSSL. If OpenSSL is not installed, or the version
is lower than 3.0.2, install version 3.0.2.
I would recommend to set up this project and its dependencies in a virtual environment.
For this, open a console and navigate to the directory of this project.
There, create a virtual environment with `python3 -m venv didtls`. This creates a virtual environment name `didtls`
that can be activated with `source didtls/bin/activate`.

This project requires modified versions of the `cryptography` library and of `pyOpenSSL`.
Clone these into directory outside of this project using
`git clone https://github.com/dennisn00/cryptography.git` and
`git clone https://github.com/dennisn00/pyopenssl.git`.

After cloning and activating the virtual environment, `cd` into the cryptography directory and install rust with
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`.
Install cryptography into the environment using `pip install -e . --no-binary cryptography`.
Then, `cd` into the pyOpenSSL directory and run `pip install -e .` 
to install pyOpenSSL.

Within the environment, install the other dependencies with
`pip install base58 py-multibase peerdid jsonpath_rw`

### Add keys to project

The agents need to have access to their local keypairs (that is the authentication key / verkey from the DID Document).
For this, you can use `secret.json`. Add the DIDs of all agents you want to run on this machine (that includes issuers, clients and servers).
Include either `skey` or `seed` to allow the agent to obtain the private key, 
as well as `verkey` (the public key, optional) and `name` (optional).
This assumes that these DIDs and the verkeys have been written to the ledger.


### Using a custom Ledger and/or Resolver

Resolver.py has offers an interface to easily create new resolvers. These resolvers can
then handle custom ledgers internally. The file also provides some  implementations for the Universal Resolver, the indy-cli-rs
and PeerDIDs, amongst others. 

#### Universal Resolver / Indy Driver
The Universal resolver requires a local instance of the resolver running (for example in a Docker container) at localhost:8080.
This address can be changed in Resolver.py if necessary.
If a custom ledger is to be used with the Universal Resolver, register that ledger/pool with your local instance of the Universal Resolver
(see https://github.com/decentralized-identity/uni-resolver-driver-did-indy/?tab=readme-ov-file#usage-with-local-von-network for an example
of how to use an Indy Network with the Universal Resolver).

#### Indy-CLI-rs
Install the CLI as described [here](https://github.com/hyperledger/indy-cli-rs?tab=readme-ov-file#installation).
For the indy-cli-rs, ledgers/pools can be added by adding their genesis file to the indy-cli directory in this project with
the file name `<pool_name>.txn`. When starting the IndyCliResolver, user `<pool_name>` to refer to that pool.

#### Cache Resolver
The Cache Resolver uses a local file to simulate caching. For this, you can use `secrets.json`, and replace
the DIDs, verkeys and skeys with your keys and DIDs. Instead of "skey", "seed" can be used.
