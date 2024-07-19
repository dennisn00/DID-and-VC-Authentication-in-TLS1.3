import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

import Utils.SelectiveDisclosureJWTUtils


#################### Verifiable Credential ############################
@dataclass
class CredentialSubject:
    """
    This contains the claims of the VC as defined in the W3C VC Model and the SD-JWT format
    """
    _sd: list[str]  # the hash digest of all non-nested claims
    type: str = None
    nested_claims: dict[str, 'CredentialSubject'] = field(default_factory=dict)
    id: str = None  # the DID of the subject of these claims, can be None for nested claims

    def to_dict(self):
        dictionary = {
            "_sd": self._sd
        }
        if self.id is not None and self.id != "":
            dictionary["id"] = self.id
        if self.type is not None:
            dictionary["type"] = self.type
        for (claim_name, claim_subject) in self.nested_claims.items():
            dictionary[claim_name] = claim_subject.to_dict()
        return dictionary

    @classmethod
    def from_dict(cls, subject_dict: dict) -> 'CredentialSubject':
        return cls(
            _sd=subject_dict["_sd"],
            id=subject_dict["id"] if "id" in subject_dict else None,
            type=subject_dict["type"] if "type" in subject_dict else None,
            nested_claims={claim_name: CredentialSubject.from_dict(claim_value_dict)
                           for (claim_name, claim_value_dict) in subject_dict.items()
                           if claim_name not in ["_sd", "type", "id"]}
        )


# This follows the W3C specification for VCs. Some optional fields were omitted because they
# were either already present in the wrapping sd_jwt class, or they were adding
# unnecessary complexity
@dataclass
class W3CVerifiableCredential:
    context: list[str]  # this points to definitions of types and claim names used in this VC
    type: list[str]
    id: str
    issuer: str
    credential_subject: CredentialSubject | dict
    validFrom: Optional[datetime.date] = None
    validUntil: Optional[datetime.date] = None
    name: Optional[str] = None
    description: Optional[str] = None

    # While the W3C spec usually assumes plaintext claim values this will use hashes for the CredentialSubject.
    # Type Credential Subject should only be used for construction. The to_dict() function converts it into
    # a dict with flattened nested_claims before signing.

    def to_dict(self) -> dict:
        dictionary = {
            "context": self.context,
            "type": self.type,
            "id": self.id,
            "issuer": self.issuer,
            "credential_subject": self.credential_subject if isinstance(self.credential_subject,
                                                                       dict) else self.credential_subject.to_dict()
        }
        if self.validFrom is not None:
            dictionary["validFrom"] = self.validFrom.isoformat()
        if self.validUntil is not None:
            dictionary["validUntil"] = self.validUntil.isoformat()
        if self.name is not None and self.name != "":
            dictionary["name"] = self.name
        if self.description is not None and self.description != "":
            dictionary["description"] = self.description
        return dictionary

    @classmethod
    def from_dict(cls, obj):
        return cls(obj["context"], obj["type"], obj["id"], obj["issuer"],
                   CredentialSubject.from_dict(obj["credential_subject"]),
                   datetime.date.fromisoformat(obj["validFrom"]) if "validFrom" in obj else None,
                   datetime.date.fromisoformat(obj["validUntil"]) if "validUntil" in obj else None,
                   obj["name"] if "name" in obj else None,
                   obj["description"] if "description" in obj else None
                   )

        # This is an externally secured VC. The VC is in the document, the signature secures it


@dataclass
class SelectiveDisclosureJWT:
    document: W3CVerifiableCredential
    signature: bytes
    # Disclosures are lists of lists, where an inner list has three elements: salt, claim name and claim value.
    # There is one list per claim. In a Presentation, there should be one list per disclosed claim
    disclosures: list[list[str]] # disclosures provide the inputs for the hash digests

    def __init__(self, document: W3CVerifiableCredential | dict, signature: bytes, disclosures: list[list[str]]):
        if isinstance(document.credential_subject, CredentialSubject):
            document.credential_subject = document.credential_subject.to_dict()
        self.document = document
        self.disclosures = disclosures
        self.signature = signature

    def to_dict(self) -> dict:
        return {
            "document": self.document.to_dict(),
            "signature": self.signature.decode('latin1'),
            "disclosures": self.disclosures
        }

    @classmethod
    def from_dict(cls, obj: dict):
        return cls(W3CVerifiableCredential.from_dict(obj["document"]),
                   obj["signature"].encode('latin1'),
                   obj["disclosures"])

    @classmethod
    def from_skey(cls, document: W3CVerifiableCredential, disclosures: list[list[str]], skey: ed25519.Ed25519PrivateKey):
        """
        This creates an SD-JWT from a VC Document, a list of disclosures, and the issuer's secret key for signing
        :param document: VC to include as document.
        :param disclosures: List of disclosures included in the document.
        :param skey: Secret key of issuer for signing of the Credential
        """
        return cls(document, Utils.SelectiveDisclosureJWTUtils.sign_vc(document.to_dict(), skey), disclosures)


######################### REQUESTING PRESENTATION OF A VP #############################

@dataclass
class Field:
    path: list[str]
    id: Optional[str] = None
    purpose: Optional[str] = None
    name: Optional[str] = None
    # omission indicates that field is required
    optional: Optional[bool] = False
    additional_properties: dict[str, Any] = None

    def to_string(self) -> str:
        return "Field(Name: " + str(self.name) + ", Purpose: " + str(self.purpose) + ", Optional: " + str(
            self.optional) + ")"


class LimitDisclosure(Enum):
    REQUIRED = 'required'  # holder must limit submitted fields to those listed in fields
    PREFERRED = 'preferred'  # holder should limit submitted fields to those listed in fields


@dataclass
class Constraints:
    fields: list[Field]
    # omission signalizes that holder may submit fields not described in fields
    limit_disclosure: Optional[LimitDisclosure] = None

    @classmethod
    def from_dict(cls, obj: dict):
        limit_disclosure = obj["limit_disclosure"] if "limit_disclosure" in obj else None
        return cls([Field(**f) for f in obj["fields"]], limit_disclosure)


@dataclass
class PresentationInputDescriptor:
    id: str  # must be unique among PresentationInputDescriptors in the same Presentation Definition
    constraints: Constraints
    name: Optional[str] = None
    purpose: Optional[str] = None

    @classmethod
    def from_dict(cls, obj: dict):
        constraints = Constraints.from_dict(obj["constraints"])
        name = obj["name"] if "name" in obj else None
        purpose = obj["purpose"] if "purpose" in obj else None
        return cls(obj["id"], constraints, name, purpose)


@dataclass
class PresentationDefinition:
    id: str
    input_descriptors: list[PresentationInputDescriptor]
    name: Optional[str] = None
    purpose: Optional[str] = None

    @classmethod
    def from_dict(cls, obj: dict):
        name = obj["name"] if "name" in obj else None
        purpose = obj["purpose"] if "purpose" in obj else None
        input_descriptors = [PresentationInputDescriptor.from_dict(dict_entry) for dict_entry in
                             obj["input_descriptors"]]
        return cls(obj["id"], input_descriptors, name, purpose)


@dataclass
class DIFRequestPresentation:
    comment: str  # provide a purpose for the user to decide whether to share this info or not
    presentation_definition: PresentationDefinition

    @classmethod
    def from_dict(cls, obj):
        return cls(obj["comment"], PresentationDefinition.from_dict(obj["presentation_definition"]))


############################ PRESENTING A VP ###########################
@dataclass
class InputDescriptorMapping:
    id: str  # should match id in InputDescriptor
    format: str
    path: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "format": self.format,
            "path": self.path
        }

    @classmethod
    def from_dict(cls, obj: dict):
        return cls(obj["id"], obj["format"], obj["path"])


@dataclass
class PresentationSubmission:
    id: str
    definition_id: str  # must be an id of a valid PresentationDefinition
    descriptor_map: list[InputDescriptorMapping]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "definition_id": self.definition_id,
            "descriptor_map": [i.to_dict() for i in self.descriptor_map]
        }

    @classmethod
    def from_dict(cls, obj: dict):
        return cls(obj["id"], obj["definition_id"],
                   [InputDescriptorMapping.from_dict(i) for i in obj["descriptor_map"]])


@dataclass
class SubmitPresentation:
    type: list[str]
    presentation_submission: PresentationSubmission
    verifiable_credential: list[SelectiveDisclosureJWT]

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "presentation_submission": self.presentation_submission.to_dict(),
            "verifiable_credential": [vc.to_dict() for vc in self.verifiable_credential]
        }

    @classmethod
    def from_dict(cls, obj: dict):
        return cls(obj["type"],
                   PresentationSubmission.from_dict(obj["presentation_submission"]),
                   [SelectiveDisclosureJWT.from_dict(vc) for vc in obj["verifiable_credential"]]
                   )

class DateJSONEncoder(json.JSONEncoder):
    """
    This allows dates to be encoded in iso Format
    """
    def default(self, obj):
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)
