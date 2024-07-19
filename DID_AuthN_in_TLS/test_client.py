import json
from dataclasses import asdict
from time import perf_counter_ns

import Resolver
import Utils.DIDCertificateUtils
from Agent import Agent
from Constants import MESSAGE_TYPE_PRESENTATION_EXCHANGE, SUBMISSION_ACK
from Enums.DIDMethods import DIDMethod
from Enums.PresentationExchangeProtocol import PresentationExchangeProtocol as VCProtocol
from SD_JWT import DIFRequestPresentation, DateJSONEncoder, SubmitPresentation


def vp_exchange_cb(agent: Agent, did: str, message: bytes, timer: Utils.DIDCertificateUtils.DIDTimer,
                   resolver: Resolver.Resolver):
    obj = json.loads(message.decode('utf-8'))
    if "presentation_submission" in obj:
        try:
            timer.start_vc_submission_handle = perf_counter_ns()
            submission = SubmitPresentation.from_dict(obj)
            acc = agent.get_verifier().handle_dif_submit_presentation(submission, did, resolver, timer)
            timer.end_vc_submission_handle = perf_counter_ns()
            if acc:
                return None, SUBMISSION_ACK
            print("Submission not accepted, aborting")
            return None, None
        except KeyError:
            print("SUBMISSION has an incorrect format")
            return None
    elif "presentation_definition" in obj:
        try:
            timer.start_vc_request_handle = perf_counter_ns()
            req: DIFRequestPresentation = DIFRequestPresentation.from_dict(obj)
            ret = json.dumps(agent.get_holder().handle_dif_req_pres(req).to_dict(), cls=DateJSONEncoder).encode('utf-8')
            timer.end_vc_request_handle = perf_counter_ns()
            return ret, MESSAGE_TYPE_PRESENTATION_EXCHANGE
        except KeyError:
            print("DIFRequestPresentation has an incorrect format")
            return None
    print("Received VP Exchange Message is neither a request, nor a submission. Aborting...")
    return None, None


def handshake_done_cb(agent: Agent, did: str):
    return (json.dumps(asdict(agent.get_verifier().create_dif_organization_name_vc_request(did)),
                       cls=DateJSONEncoder).encode('utf-8'), MESSAGE_TYPE_PRESENTATION_EXCHANGE)


# Prepare Agents and VCs for idunion-test network
issuer_did_idunion = "did:indy:idunion:test:8G6ng6cn8iNnkU265MbGgJ"
client_did_idunion = "did:indy:idunion:test:SEaGofSEGTir5KR5THUhBN"
# load private keys from file secrets.json
issuer_private_key_idunion = Resolver.get_skey_from_file(issuer_did_idunion, file="secrets.json")
client_private_key_idunion = Resolver.get_skey_from_file(client_did_idunion, file="secrets.json")

# create agents for client and issuer
client_agent = Agent(client_did_idunion, client_private_key_idunion, "Agent_2", [VCProtocol.DIF],
                     [DIDMethod.INDY])

issuer_agent_idunion = Agent(issuer_did_idunion, issuer_private_key_idunion, "passport_issuer", [VCProtocol.DIF],
                             [DIDMethod.INDY])

passport_vc = issuer_agent_idunion.get_passport_issuer().issue_example_vc_passport(client_agent.did, "John",
                                                                                   "Smith",
                                                                                   "1990-01-01", "Street", "12345",
                                                                                   "Berlin")
client_agent.sd_jwts.append(passport_vc)
degree_vc = issuer_agent_idunion.get_degree_issuer().issue_example_vc_degree(client_agent.did, "John", "Smith",
                                                                             "2024-06-05", "MSc", "Computer Science",
                                                                             5.0)
client_agent.sd_jwts.append(degree_vc)

endpoint = ('localhost', 50001)
resolver = Resolver.indy_cli_resolver

resolver.start("idunion_test")
result = client_agent.get_client().test_did(
    endpoint=endpoint,
    iterations=10,
    resumption=False,
    resolver=resolver,
    handshake_only=False,
    vp_exchange_cb=lambda did, msg, timer, resolver: vp_exchange_cb(client_agent, did, msg, timer, resolver),
    handshake_done_cb=lambda did: handshake_done_cb(client_agent, did)
)
print(result)
resolver.stop()


