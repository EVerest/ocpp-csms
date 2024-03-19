# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
import sys
import os
from pathlib import Path
import base64

JOSEV_WORK_DIR = Path(__file__).parent / 'Josev'
sys.path.append(JOSEV_WORK_DIR.as_posix())

from iso15118.shared.security import (
    CertPath,
    KeyEncoding,
    KeyPasswordPath,
    KeyPath,
    create_signature,
    encrypt_priv_key,
    get_cert_cn,
    load_cert,
    load_priv_key,
)
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    EMAID,
    CertificateChain,
    DHPublicKey,
    EncryptedPrivateKey,
    ResponseCode,
    SubCertificates
)
from iso15118.shared.messages.iso15118_2.body import Body, CertificateInstallationRes
from iso15118.shared.messages.enums import Namespace
from iso15118.shared.exi_codec import EXI
from iso15118.shared.exificient_exi_codec import ExificientEXICodec
from iso15118.shared.exceptions import EncryptionError, PrivateKeyReadError

class EXIGenerator:

    def __init__(self, certs_path):
        self.certs_path = certs_path
        EXI().set_exi_codec(ExificientEXICodec())

    def generate_certificate_installation_res(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:

        cert_install_req_exi = base64.b64decode(base64_encoded_cert_installation_req)
        cert_install_req = EXI().from_exi(cert_install_req_exi, namespace)
        try:
            dh_pub_key, encrypted_priv_key_bytes = encrypt_priv_key(
                oem_prov_cert=load_cert(os.path.join(self.certs_path, CertPath.OEM_LEAF_DER)),
                priv_key_to_encrypt=load_priv_key(
                    os.path.join(self.certs_path, KeyPath.CONTRACT_LEAF_PEM),
                    KeyEncoding.PEM,
                    os.path.join(self.certs_path, KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD),
                ),
            )
        except EncryptionError:
            raise EncryptionError(
                "EncryptionError while trying to encrypt the private key for the "
                "contract certificate"
            )
        except PrivateKeyReadError as exc:
            raise PrivateKeyReadError(
                f"Can't read private key to encrypt for CertificateInstallationRes:"
                f" {exc}"
            )

        # The elements that need to be part of the signature
        contract_cert_chain = CertificateChain(
            id="id1",
            certificate=load_cert(os.path.join(self.certs_path, CertPath.CONTRACT_LEAF_DER)),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(os.path.join(self.certs_path, CertPath.MO_SUB_CA2_DER)),
                    load_cert(os.path.join(self.certs_path, CertPath.MO_SUB_CA1_DER)),
                ]
            ),
        )
        encrypted_priv_key = EncryptedPrivateKey(
            id="id2", value=encrypted_priv_key_bytes
        )
        dh_public_key = DHPublicKey(id="id3", value=dh_pub_key)
        emaid = EMAID(
            id="id4", value=get_cert_cn(load_cert(os.path.join(self.certs_path, CertPath.CONTRACT_LEAF_DER)))
        )
        cps_certificate_chain = CertificateChain(
            certificate=load_cert(os.path.join(self.certs_path, CertPath.CPS_LEAF_DER)),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(os.path.join(self.certs_path, CertPath.CPS_SUB_CA2_DER)),
                    load_cert(os.path.join(self.certs_path, CertPath.CPS_SUB_CA1_DER)),
                ]
            ),
        )

        cert_install_res = CertificateInstallationRes(
            response_code=ResponseCode.OK,
            cps_cert_chain=cps_certificate_chain,
            contract_cert_chain=contract_cert_chain,
            encrypted_private_key=encrypted_priv_key,
            dh_public_key=dh_public_key,
            emaid=emaid,
        )

        try:
            # Elements to sign, containing its id and the exi encoded stream
            contract_cert_tuple = (
                cert_install_res.contract_cert_chain.id,
                EXI().to_exi(
                    cert_install_res.contract_cert_chain, Namespace.ISO_V2_MSG_DEF
                ),
            )
            encrypted_priv_key_tuple = (
                cert_install_res.encrypted_private_key.id,
                EXI().to_exi(
                    cert_install_res.encrypted_private_key, Namespace.ISO_V2_MSG_DEF
                ),
            )
            dh_public_key_tuple = (
                cert_install_res.dh_public_key.id,
                EXI().to_exi(cert_install_res.dh_public_key, Namespace.ISO_V2_MSG_DEF),
            )
            emaid_tuple = (
                cert_install_res.emaid.id,
                EXI().to_exi(cert_install_res.emaid, Namespace.ISO_V2_MSG_DEF),
            )

            elements_to_sign = [
                contract_cert_tuple,
                encrypted_priv_key_tuple,
                dh_public_key_tuple,
                emaid_tuple,
            ]
            # The private key to be used for the signature
            signature_key = load_priv_key(
                os.path.join(self.certs_path, KeyPath.CPS_LEAF_PEM),
                KeyEncoding.PEM,
                os.path.join(self.certs_path, KeyPasswordPath.CPS_LEAF_KEY_PASSWORD),
            )

            signature = create_signature(elements_to_sign, signature_key)

        except PrivateKeyReadError as exc:
            raise Exception(
                "Can't read private key needed to create signature "
                f"for CertificateInstallationRes: {exc}",
            )
        except Exception as exc:
            raise Exception(f"Error creating signature {exc}")

        header = MessageHeaderV2(
            session_id=cert_install_req.header.session_id,
            signature=signature,
        )
        body = Body.parse_obj({"CertificateInstallationRes": cert_install_res.dict()})
        to_be_exi_encoded = V2GMessageV2(header=header, body=body)
        exi_encoded_cert_installation_res = EXI().to_exi(
            to_be_exi_encoded, Namespace.ISO_V2_MSG_DEF
        )

        base64_encode_cert_install_res = base64.b64encode(
            exi_encoded_cert_installation_res
        ).decode("utf-8")

        return base64_encode_cert_install_res
