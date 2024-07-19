import uuid
from datetime import timedelta, date

import Agent
from SD_JWT import CredentialSubject, W3CVerifiableCredential, SelectiveDisclosureJWT
from Utils.SelectiveDisclosureJWTUtils import *


class PassportIssuer:
    """
    This is an extension to the agent object that provides an example issuer that can issue Passport VCs in the SD-JWT format.
    """

    def __init__(self, agent: Agent):
        self.did = agent.did
        self.private_key = agent.private_key

    def issue_example_vc_passport(self, subject_did: str, first_name: str, last_name: str, birthdate: str,
                                  street_address: str, postal_code: str, city: str):
        """
        Creates and signs a VC for the subject containing the given information
        :param subject_did: DID of the passport holder
        :param first_name: First name of the passport holder
        :param last_name: Last name of the passport holder
        :param birthdate: Birthdate of the passport holder
        :param street_address: Street address of the passport holder
        :param postal_code: Postal Code of the passport holder
        :param city: City of the passport holder
        :return: SD-JWT with passport information of the holder
        """
        # There should be some mechanism here for the issuer to check that the data is correct before issuing.
        # This is omitted here as it is outside of scope for this project

        disclosures = [[generate_salt(), "first_name", first_name],
                       [generate_salt(), "last_name", last_name],
                       [generate_salt(), "birthdate", birthdate]]

        address_disclosures = ([[generate_salt(), "address.postal_code", postal_code],
                                [generate_salt(), "address.city", city],
                                [generate_salt(), "address.street_address", street_address]])

        subject = CredentialSubject(
            id=subject_did,
            _sd=[hash_disclosure(generate_disclosure(d[0], d[1], d[2])) for d in disclosures],
            type="PassportCredential",
            nested_claims={"address": CredentialSubject(
                _sd=[hash_disclosure(generate_disclosure(d[0], d[1], d[2])) for d in
                     address_disclosures],
                type="PostalAddressCredential"
            )}
        )

        vc = W3CVerifiableCredential(
            context=["https://www.w3.org/2018/credentials/v1"],
            type=["VerifiableCredential", "PassportCredential"],
            id=str(uuid.uuid4()),
            issuer=self.did,
            validFrom=date.today(),
            validUntil=date.today() + timedelta(days=365 * 5),
            name="Passport",
            description="Passport issued by country",
            credential_subject=subject
        )

        return SelectiveDisclosureJWT.from_skey(
            document=vc,
            disclosures=disclosures + address_disclosures,
            skey=self.private_key
        )


class UniversityDegreeIssuer:
    """
    This is an extension to the agent object that provides an example issuer that can issue University Degree VCs in the SD-JWT format.
    """

    def __init__(self, agent: Agent):
        self.did = agent.did
        self.private_key = agent.private_key

    def issue_example_vc_degree(self, subject_did: str, first_name: str, last_name: str, graduation_date: datetime,
                                degree: str, subject: str, avg_grade: float):
        """
        Creates and signs a VC for the subject containing the given information
        :param subject_did: DID of the degree holder
        :param first_name: First name of the degree holder
        :param last_name: Last name of the degree holder
        :param graduation_date: Graduation Date of the degree holder
        :param degree: Degree Type of the degree holder (e.g. "MSc", "BA")
        :param subject: Degree Subject of the degree holder (e.g. "Computer Science", "Biology")
        :param avg_grade: Average Grade of the degree holder
        :return: SD-JWT with degree information of the holder
        """
        # There should be some mechanism here for the issuer to check that the data is correct before issuing.
        # This is omitted here as it is outside of scope for this project

        disclosures = [[generate_salt(), "first_name", first_name],
                       [generate_salt(), "last_name", last_name],
                       [generate_salt(), "graduation_date", graduation_date],
                       [generate_salt(), "degree", degree],
                       [generate_salt(), "subject", subject],
                       [generate_salt(), "avg_grade", avg_grade]]

        subject = CredentialSubject(
            id=subject_did,
            _sd=[hash_disclosure(generate_disclosure(d[0], d[1], d[2])) for d in disclosures],
            type="UniversityDegreeCredential",
            nested_claims={}
        )

        vc = W3CVerifiableCredential(
            context=["https://www.w3.org/2018/credentials/v1"],
            type=["VerifiableCredential", "UniversityDegreeCredential"],
            id=str(uuid.uuid4()),
            issuer=self.did,
            validFrom=date.today(),
            name="University Degree",
            description="Degree issued by Example University",
            credential_subject=subject
        )

        degree_jwt = SelectiveDisclosureJWT.from_skey(
            document=vc,
            disclosures=disclosures,
            skey=self.private_key
        )

        return degree_jwt


class OrganizationIssuer:
    """
    This is an extension to the agent object that provides an example issuer that can issue Organization VCs in the SD-JWT format.
    These VCs attest membership in a specified organization.
    """
    def __init__(self, agent: Agent):
        self.did = agent.did
        self.private_key = agent.private_key

    def issue_example_vc_org_name(self, subject_did: str, organization_name: str):
        """
        Creates and signs a VC for the subject containing the given information
        :param subject_did: DID of the subject
        :param organization_name: Organization Name that the subject is member of
        :return: SD-JWT with provided information
        """

        # There should be some mechanism here for the issuer to check that the data is correct before issuing.
        # This is omitted here as it is outside of scope for this project
        disclosures = [[generate_salt(), "organization_name", organization_name]]

        subject = CredentialSubject(
            id=subject_did,
            _sd=[hash_disclosure(generate_disclosure(d[0], d[1], d[2])) for d in disclosures],
            type="OrganizationCredential",
            nested_claims={}
        )

        vc = W3CVerifiableCredential(
            context=["https://www.w3.org/2018/credentials/v1"],
            type=["VerifiableCredential", "OrganizationCredential"],
            id=str(uuid.uuid4()),
            issuer=self.did,
            validFrom=date.today(),
            validUntil=date.today() + timedelta(days=90),
            name="Organization Name",
            description="Organization Name issued by some authority",
            credential_subject=subject
        )

        return SelectiveDisclosureJWT.from_skey(
            document=vc,
            disclosures=disclosures,
            skey=self.private_key
        )
