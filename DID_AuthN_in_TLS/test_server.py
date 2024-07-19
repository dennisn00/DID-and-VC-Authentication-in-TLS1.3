import json
from dataclasses import asdict
from time import perf_counter_ns

import Agent
import Resolver
import Utils.DIDCertificateUtils
from Constants import MESSAGE_TYPE_PRESENTATION_EXCHANGE, SUBMISSION_ACK
from Enums.DIDMethods import DIDMethod
from Enums.PresentationExchangeProtocol import PresentationExchangeProtocol as VCProtocol
from SD_JWT import SubmitPresentation, DIFRequestPresentation, DateJSONEncoder


def vp_exchange_cb(agent: Agent.Agent, did: str, message: bytes, timer: Utils.DIDCertificateUtils.DIDTimer,
                   resolver: Resolver.Resolver) -> (
        bytes, int):
    obj = json.loads(message)
    if "presentation_submission" in obj:
        try:
            timer.start_vc_submission_handle = perf_counter_ns()
            submission = SubmitPresentation.from_dict(obj)
            acc = agent.get_verifier().handle_dif_submit_presentation(submission, did, resolver, timer)
            timer.end_vc_submission_handle = perf_counter_ns()
            if acc:
                return None, SUBMISSION_ACK
            print("Submission not accepted, aborting")
            return None
        except KeyError:
            print("SUBMISSION has an incorrect format")
            return None
    elif "presentation_definition" in obj:
        try:
            timer.start_vc_request_handle = perf_counter_ns()
            req = DIFRequestPresentation.from_dict(obj)
            ret = json.dumps(agent.get_holder().handle_dif_req_pres(req).to_dict(), cls=DateJSONEncoder).encode('utf-8')
            timer.end_vc_request_handle = perf_counter_ns()
            return ret, MESSAGE_TYPE_PRESENTATION_EXCHANGE
        except KeyError:
            print("DIFRequestPresentation has an incorrect format")
            return None
    print("Received VP Exchange Message is neither a request, nor a submission. Aborting...")
    return None


def handshake_done_cb(agent: Agent.Agent, peer_did: str):
    return json.dumps(asdict(agent.get_verifier().create_dif_student_vc_request(peer_did, with_auth=True))).encode(
        'utf-8'), MESSAGE_TYPE_PRESENTATION_EXCHANGE


# Prepare Agents and VCs for idunion-test network
server_did_idunion_test = "did:indy:idunion:test:y77ZersNcdw9QaT2Jwucv"
server_private_key = Resolver.get_skey_from_file(server_did_idunion_test)
org_issuer_did_idunion_test = "did:indy:idunion:test:8G6ng6cn8iNnkU265MbGgJ"
org_issuer_private_key = Resolver.get_skey_from_file(org_issuer_did_idunion_test)
server_agent = Agent.Agent(server_did_idunion_test, server_private_key, "Agent_1_idunion",
                           [VCProtocol.DIF, VCProtocol.ARIES], [DIDMethod.INDY])
org_issuer_agent_idunion = Agent.Agent(org_issuer_did_idunion_test, org_issuer_private_key, "Org Name Issuer IDUnion",
                                       [VCProtocol.DIF], [DIDMethod.INDY])
org_vc = org_issuer_agent_idunion.get_org_name_issuer().issue_example_vc_org_name(server_agent.did,
                                                                                  "Example Org")
server_agent.sd_jwts.append(org_vc)

endpoint = ('localhost', 50001)
resolver = Resolver.indy_cli_resolver

resolver.start(pool="idunion_test")
result = server_agent.get_server().test_did(
    endpoint=endpoint,
    iterations=10,
    allow_resumption=False,
    resolver=resolver,
    handshake_only=False,
    vp_exchange_cb=lambda did, msg, timer, resolver: vp_exchange_cb(server_agent, did, msg, timer, resolver),
    handshake_done_cb=lambda did: handshake_done_cb(server_agent, did)
)
print(result)
resolver.stop()
