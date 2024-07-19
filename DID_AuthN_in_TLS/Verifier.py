import logging
import uuid

from jsonpath_rw import parse

from Resolver import Resolver
from SD_JWT import *
from Utils.Exceptions import ValidityPeriodException, DigestNotFoundException
from Utils.SelectiveDisclosureJWTUtils import verify_vp


class Verifier:
    """
    Extension for an Agent Object that provides functionality for verifying VPs
    """

    def __init__(self):
        self.open_requests: dict[str, list[DIFRequestPresentation]] = {}

    def _open_request(self, did: str, request: DIFRequestPresentation):
        """
        Stores an opened request to retrieve later when submission is received
        :param did: DID of peer that request was sent to
        :param request: Request that was sent
        """
        if did not in self.open_requests:
            self.open_requests[did] = []
        self.open_requests[did].append(request)

    def create_dif_request_presentation(self, comment: str,
                                        input_descriptors: list[PresentationInputDescriptor],
                                        did: str) -> DIFRequestPresentation:
        """
        Creates a Presentation Request according to DIF Format
        :param comment: Comment to be included in the request. Optional.
        :param input_descriptors: Input Descriptors to be included. These describe the required claims and acceptable responses.
        :param did: DID of the peer that the request is targeting.
        :return: Presentation Request
        """
        presentation_definition = PresentationDefinition(
            id=str(uuid.uuid4()),
            input_descriptors=input_descriptors,
        )
        request = DIFRequestPresentation(comment=comment, presentation_definition=presentation_definition)
        self._open_request(did, request)
        return request

    def handle_dif_submit_presentation(self, submission: SubmitPresentation, did: str, resolver: Resolver, timer):
        """
        This handles a received Presentation Submission by verifying that all requested claims were submitted and all
        submitted VPs are valid
        :param submission: Received Submission to be checked
        :param did: DID of peer that submitted the VPs
        :param resolver: Resolver to use for resolution of the issuer DIDs
        :param timer: DIDTimer for performance measurement
        :return: True if all requested claims were submitted and the VP is valid, False otherwise.
        """
        # find matching request
        request = next(req for req in self.open_requests[did] if
                       req.presentation_definition.id == submission.presentation_submission.definition_id)
        data = self.verify_submit_presentation(submission, request, did, resolver, timer)
        if data is None:
            return False
        logging.info("This is the received data:")
        logging.info(data)
        # Here could be some mechanism to check that the received claim values are acceptable.
        return True

    def handle_req_input(self, submission: SubmitPresentation, req_input, resolver: Resolver, peer_did, timer):
        """
        For a submission and a single requested input, check that the input is present in the submission and that
        the corresponding vp is valid
        :param submission: Received submission
        :param req_input: Request input to search for in submission
        :param resolver: Resolver for resolution of issuer DID
        :param peer_did: Expected DID of peer that sent submission
        :param timer: DIDTimer for performance measurement
        :return: Plaintext VP, that is a W3C VC with claim names and values in plaintext. This only includes disclosed
        claims.
        """
        mapping = next(i for i in submission.presentation_submission.descriptor_map if i.id == req_input.id)
        path = parse(mapping.path)
        vp = SelectiveDisclosureJWT.from_dict(path.find(submission.to_dict())[0].value)
        # check that all request disclosures are presented
        for f in req_input.constraints.fields:
            # throws StopIteration if none is found
            next(d for d in vp.disclosures if ("$." + d[1]) in f.path)
        plaintext_vp = verify_vp(vp, resolver, peer_did, timer)
        return plaintext_vp

    def verify_submit_presentation(self, submission: SubmitPresentation, request: DIFRequestPresentation, peer_did,
                                   resolver: Resolver, timer) -> list[W3CVerifiableCredential] | None:
        """
        Check that a submission matches with a sent request. This checks that the definition IDs match, and
        that all requested inputs are disclosed.
        :param submission: Received Submission
        :param request: Matching Request sent by this agent
        :param peer_did: DID of the peer.
        :param resolver: Resolver to use for resolution of the issuer DID
        :param timer: DIDTimer for performance measurement.
        :return: List of Plaintext VPs, one for each submitted VP. This is a W3C VC with claim names and values in
        plaintext. This only includes disclosed claims.
        """
        ret = []
        # Check if definition IDs match
        if submission.presentation_submission.definition_id != request.presentation_definition.id:
            return None

        # check that all requested inputs are present and disclosed
        for req_input in request.presentation_definition.input_descriptors:
            try:
                ret.append(self.handle_req_input(submission, req_input, resolver, peer_did, timer))
            except StopIteration | ValidityPeriodException | DigestNotFoundException:
                # no matching InputDescriptorMap was found or disclosure was not found or vc is not valid anymore or
                # digest of disclosure was not found in VC
                return None
        return ret

    ###### example implementations
    def create_dif_student_vc_request(self, did: str, with_auth=False) -> DIFRequestPresentation:
        last_name_field = Field(path=["$.last_name"], optional=False, name="Last Name",
                                purpose="Purpose")
        postal_code_field = Field(path=["$.address.postal_code"], optional=False, name="Postal code",
                                  purpose="Purpose")

        constraints = Constraints(fields=[last_name_field, postal_code_field])

        passport_input_descriptor = PresentationInputDescriptor(
            name="Passport Input",
            purpose="To verify your identity",
            id=str(uuid.uuid4()),
            constraints=constraints
        )

        input_descriptors = [passport_input_descriptor]
        if with_auth:
            grad_date_field = Field(path=["$.graduation_date", "$.date_of_graduation"], optional=False,
                                    name="Date of Graduation", purpose="Purpose")
            avg_grade_field = Field(path=["$.avg_grade"], optional=False, name="Average Grade",
                                    purpose="Purpose")

            constraints_degree = Constraints(fields=[grad_date_field, avg_grade_field])
            degree_input_descriptor = PresentationInputDescriptor(
                name="University Degree Input",
                purpose="To verify your degree",
                id=str(uuid.uuid4()),
                constraints=constraints_degree
            )
            input_descriptors.append(degree_input_descriptor)

        request_presentation = self.create_dif_request_presentation(
            comment="Requesting passport details",
            input_descriptors=input_descriptors,
            did=did,
        )
        return request_presentation

    def create_dif_organization_name_vc_request(self, did: str):
        organization_name_field = Field(path=["$.organization_name"], optional=False, name="organization_name")

        organization_name_input_descriptor = PresentationInputDescriptor(
            name="organization_name Input",
            purpose="To verify your organization name",
            id=str(uuid.uuid4()),
            constraints=Constraints(fields=[organization_name_field])
        )

        request_presentation = self.create_dif_request_presentation(
            comment="Requesting organization name",
            input_descriptors=[organization_name_input_descriptor],
            did=did,
        )
        return request_presentation

