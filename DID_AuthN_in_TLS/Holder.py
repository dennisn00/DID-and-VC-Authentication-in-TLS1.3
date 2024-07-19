import logging
import uuid

import Agent
import SD_JWT


def _is_field_in_sd_jwt(sd_jwt: SD_JWT.SelectiveDisclosureJWT, f: SD_JWT.Field):
    """
    This checks whether a specified Field is present in the disclosures of an SD-JWT.
    :param sd_jwt: SD-JWT to search field in
    :param f: Field to be search
    :return: True if field is found, False otherwise.
    """
    for disclosure in sd_jwt.disclosures:
        for path in f.path:
            if str(path)[2:] == disclosure[1]:
                return True
    return False


def _does_candidate_sd_jwt_conform_to_input_descriptor(sd_jwt: SD_JWT.SelectiveDisclosureJWT,
                                                       input_desc: SD_JWT.PresentationInputDescriptor):
    """
    This checks whether an SD-JWT includes ALL fields requested in an InputDescriptor
    :param sd_jwt: SD-Jwt to search fields in
    :param input_desc: InputDescriptor that includes all requested fields
    :return: True if sd_jwt does contain all requested fields, False otherwise
    """
    for f in input_desc.constraints.fields:
        if not _is_field_in_sd_jwt(sd_jwt, f) and not f.optional:
            return False
    return True


def _get_requested_disclosures(sd_jwt: SD_JWT.SelectiveDisclosureJWT, input_desc: SD_JWT.PresentationInputDescriptor):
    """
    Get all disclosures (as a list of 3 strings: salt, claim name and claim value) that were requested in the InputDescriptor
    :param sd_jwt: sSD-JWT to get disclosures from
    :param input_desc: InputDescriptor to determine which disclosures are required
    :return: List of requested disclosures
    """
    disclosures = []
    for f in input_desc.constraints.fields:
        for disclosure in sd_jwt.disclosures:
            for path in f.path:
                if str(path)[2:] == disclosure[1]:
                    disclosures.append(disclosure)
    return disclosures


class Holder:
    """
    Extension to an Agent object, adds Holder functionality. This includes storing SD-JWTs and presenting them in response
    to Presentation Requests.
    """

    def __init__(self, agent: Agent):
        self.sd_jwts: list[SD_JWT.SelectiveDisclosureJWT] = agent.sd_jwts

    def handle_dif_req_pres(self, request: SD_JWT.DIFRequestPresentation):
        """
        Handle an incoming VP Request in DIF Format. This scans the stored SD-JWTs and if matching claims were found,
        builds a response to the request. This assumes that the user agrees to share all information.
        :param request: The incoming request
        :return: Presentation submission
        """
        logging.info("Received Presentation Request " + str(request.presentation_definition.name) + " with purpose " + str(
            request.presentation_definition.purpose))

        submit_presentation = SD_JWT.SubmitPresentation(
            type=["VerifiablePresentation"],
            presentation_submission=SD_JWT.PresentationSubmission(
                id=str(uuid.uuid4()),
                definition_id=request.presentation_definition.id,
                descriptor_map=[]
            ),
            verifiable_credential=[]
        )

        for input_descriptor in request.presentation_definition.input_descriptors:
            logging.info("Requested Input: ", input_descriptor.name)
            logging.info("Purpose: ", input_descriptor.purpose)

            for sd_jwt in self.sd_jwts:
                if not _does_candidate_sd_jwt_conform_to_input_descriptor(sd_jwt, input_descriptor):
                    continue
                disclosures = _get_requested_disclosures(sd_jwt, input_descriptor)
                logging.info("The following fields were requested: ")
                for f in input_descriptor.constraints.fields:
                    logging.info(f.to_string())
                logging.info(
                    "Found candidate SD_JWT in wallet with Name " + sd_jwt.document.name + ". This would disclose the "
                                                                                           "following values: ")
                for disclosure in disclosures:
                    logging.info(str(disclosure[1]) + ": " + str(disclosure[2]))
                # for performance tests, we assume that users agree to send all requested disclosures
                #x = input("Do you want to disclose these? (y/n)")
                #if x == "y":
                if True:
                    if sd_jwt.signature not in [vc.signature for vc in submit_presentation.verifiable_credential]:
                        submit_presentation.verifiable_credential.append(SD_JWT.SelectiveDisclosureJWT(
                            document=sd_jwt.document,
                            signature=sd_jwt.signature,
                            disclosures=[]
                        ))
                    index = [i for i, v in enumerate(submit_presentation.verifiable_credential) if
                             v.signature == sd_jwt.signature][0]
                    submit_presentation.verifiable_credential[index].disclosures.extend(disclosures)
                    mapping = SD_JWT.InputDescriptorMapping(
                        id=input_descriptor.id,
                        format="jwt_vc",
                        path="$.verifiable_credential[" + str(index) + "]"
                    )
                    submit_presentation.presentation_submission.descriptor_map.append(mapping)
        return submit_presentation
