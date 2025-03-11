# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
import logging
from datetime import datetime
import json
import sys

from ocpp.charge_point import snake_to_camel_case, asdict, remove_nones
from ocpp.v16.datatypes import (
    IdTagInfo,
)
from ocpp.v16 import call, call_result
from ocpp.v16.enums import (
    Action,
    RegistrationStatus,
    AuthorizationStatus,
    GenericStatus,
    DataTransferStatus,
    CertificateSignedStatus
)
from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call_result
from ocpp.v16.enums import Action, RegistrationStatus

# for OCPP1.6 PnC whitepaper:
from ocpp.v201 import call_result as call_result201
from ocpp.v201.datatypes import IdTokenInfoType
from ocpp.v201.enums import (AuthorizationStatusEnumType, GenericStatusEnumType,
                             GetCertificateStatusEnumType, Iso15118EVCertificateStatusEnumType)
from exi_generator import EXIGenerator

logging.basicConfig(level=logging.INFO)


class ChargePoint16(cp):
    def __init__(self, *args, iso15118_certs, **kwargs):
        super().__init__(*args, **kwargs)
        self.iso15118_certs = iso15118_certs
        if iso15118_certs:
            self.exi_generator = EXIGenerator(
                certs_path=self.iso15118_certs.as_posix())
        else:
            self.exi_generator = None

    @on(Action.boot_notification)
    def on_boot_notification(
        self, charge_point_vendor: str, charge_point_model: str, **kwargs
    ):
        return call_result.BootNotification(
            current_time=datetime.utcnow().isoformat(),
            interval=10,
            status=RegistrationStatus.accepted,
        )

    @on(Action.heartbeat)
    def on_heartbeat(self, **kwargs):
        return call_result.Heartbeat(current_time=datetime.utcnow().isoformat())

    @on(Action.authorize)
    def on_authorize(self, **kwargs):
        id_tag_info = IdTagInfo(status=AuthorizationStatusEnumType.accepted)
        return call_result.Authorize(id_tag_info=id_tag_info)

    @on(Action.meter_values)
    def on_meter_values(self, **kwargs):
        return call_result.MeterValues()

    @on(Action.status_notification)
    def on_status_notification(self, **kwargs):
        return call_result.StatusNotification()

    @on(Action.start_transaction)
    def on_start_transaction(self, **kwargs):
        id_tag_info = IdTagInfo(status=AuthorizationStatus.accepted)
        return call_result.StartTransaction(transaction_id=1, id_tag_info=id_tag_info)

    @on(Action.stop_transaction)
    def on_stop_transaction(self, **kwargs):
        return call_result.StopTransaction()

    @on(Action.diagnostics_status_notification)
    def on_diagnostics_status_notification(self, **kwargs):
        return call_result.DiagnosticsStatusNotification()

    @on(Action.sign_certificate)
    def on_sign_certificate(self, **kwargs):
        self.csr = kwargs['csr']
        return call_result.SignCertificate(GenericStatus.accepted)

    @on(Action.security_event_notification)
    def on_security_event_notification(self, **kwargs):
        return call_result.SecurityEventNotification()

    @on(Action.signed_firmware_status_notification)
    def on_signed_update_firmware_status_notificaion(self, **kwargs):
        return call_result.SignedFirmwareStatusNotification()

    @on(Action.log_status_notification)
    def on_log_status_notification(self, **kwargs):
        return call_result.LogStatusNotification()

    @on(Action.firmware_status_notification)
    def on_firmware_status_notification(self, **kwargs):
        return call_result.FirmwareStatusNotification()

    @on(Action.data_transfer)
    def on_data_transfer(self, **kwargs):
        req = call.DataTransfer(**kwargs)
        if req.vendor_id == 'org.openchargealliance.iso15118pnc':
            if (req.message_id == "Authorize"):
                response = call_result201.Authorize(
                    id_token_info=IdTokenInfoType(
                        status=AuthorizationStatusEnumType.accepted
                    )
                )
                return call_result.DataTransfer(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(
                        snake_to_camel_case(asdict(response))))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif (req.message_id == "CertificateSigned"):
                return call_result.DataTransfer(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "DeleteCertificate":
                return call_result.DataTransfer(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            elif req.message_id == "Get15118EVCertificate":
                if not self.exi_generator:
                    return call.create_call_error(f'iso15118 certificate path "{self.iso15118_certs.as_posix()}" not found')
                exi_request = json.loads(req.data)["exiRequest"]
                namespace = json.loads(kwargs['data'])['iso15118SchemaVersion']
                return call_result.DataTransfer(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(snake_to_camel_case(asdict(
                        call_result201.Get15118EVCertificate(
                            status=Iso15118EVCertificateStatusEnumType.accepted,
                            exi_response=self.exi_generator.generate_certificate_installation_res(
                                exi_request,
                                namespace
                            )
                        ))
                    )))
                )
            elif req.message_id == "GetCertificateStatus":
                return call_result.DataTransfer(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(snake_to_camel_case(asdict(
                        call_result201.GetCertificateStatus(
                            status=GetCertificateStatusEnumType.accepted,
                            ocsp_result="IS_FAKED"
                        )
                    ))))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "InstallCertificate":
                return call_result.DataTransfer(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            elif req.message_id == "SignCertificate":
                return call_result.DataTransfer(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(asdict(
                        call_result201.SignCertificate(
                            status=GenericStatusEnumType.accepted
                        )
                    ))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "TriggerMessage":
                return call_result.DataTransfer(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            else:
                return call_result.DataTransfer(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
        else:
            return call_result.DataTransfer(
                status=DataTransferStatus.unknown_vendor_id,
                data="Please implement me"
            )

    async def get_configuration_req(self, **kwargs):
        payload = call.GetConfiguration(**kwargs)
        return await self.call(payload)

    async def change_configuration_req(self, **kwargs):
        payload = call.ChangeConfiguration(**kwargs)
        return await self.call(payload)

    async def clear_cache_req(self, **kwargs):
        payload = call.ClearCache()
        return await self.call(payload)

    async def remote_start_transaction_req(self, **kwargs):
        payload = call.RemoteStartTransaction(**kwargs)
        return await self.call(payload)

    async def remote_stop_transaction_req(self, **kwargs):
        payload = call.RemoteStopTransaction(**kwargs)
        return await self.call(payload)

    async def unlock_connector_req(self, **kwargs):
        payload = call.UnlockConnector(**kwargs)
        return await self.call(payload)

    async def change_availability_req(self, **kwargs):
        payload = call.ChangeAvailability(**kwargs)
        return await self.call(payload)

    async def reset_req(self, **kwargs):
        payload = call.Reset(**kwargs)
        return await self.call(payload)

    async def get_local_list_version_req(self, **kwargs):
        payload = call.GetLocalListVersion()
        return await self.call(payload)

    async def send_local_list_req(self, **kwargs):
        payload = call.SendLocalList(**kwargs)
        return await self.call(payload)

    async def reserve_now_req(self, **kwargs):
        payload = call.ReserveNow(**kwargs)
        return await self.call(payload)

    async def cancel_reservation_req(self, **kwargs):
        payload = call.CancelReservation(**kwargs)
        return await self.call(payload)

    async def trigger_message_req(self, **kwargs):
        payload = call.TriggerMessage(**kwargs)
        return await self.call(payload)

    async def set_charging_profile_req(self, payload: call.SetChargingProfile):
        logging.info(payload)
        return await self.call(payload)

    async def get_composite_schedule(self, payload: call.GetCompositeSchedule) -> call_result.GetCompositeSchedule:
        return await self.call(payload)

    async def get_composite_schedule_req(self, **kwargs) -> call_result.GetCompositeSchedule:
        payload = call.GetCompositeSchedule(**kwargs)
        return await self.call(payload)

    async def clear_charging_profile_req(self, **kwargs):
        payload = call.ClearChargingProfile(**kwargs)
        return await self.call(payload)

    async def data_transfer_req(self, **kwargs):
        payload = call.DataTransfer(**kwargs)
        return await self.call(payload)

    async def extended_trigger_message_req(self, **kwargs):
        payload = call.ExtendedTriggerMessage(**kwargs)
        return await self.call(payload)

    async def certificate_signed_req(self, **kwargs):
        payload = call_result.CertificateSigned(
            CertificateSignedStatus.rejected)
        return await self.call(payload)

    async def install_certificate_req(self, **kwargs):
        payload = call.InstallCertificate(**kwargs)
        return await self.call(payload)

    async def get_installed_certificate_ids_req(self, **kwargs):
        payload = call.GetInstalledCertificateIds(**kwargs)
        return await self.call(payload)

    async def delete_certificate_req(self, **kwargs):
        payload = call.DeleteCertificate(**kwargs)
        return await self.call(payload)

    async def get_log_req(self, **kwargs):
        payload = call.GetLog(**kwargs)
        return await self.call(payload)

    async def signed_update_firmware_req(self, **kwargs):
        payload = call.SignedUpdateFirmware(**kwargs)
        return await self.call(payload)

    async def get_diagnostics_req(self, **kwargs):
        payload = call.GetDiagnostics(**kwargs)
        return await self.call(payload)

    async def update_firmware_req(self, **kwargs):
        payload = call.UpdateFirmware(**kwargs)
        return await self.call(payload)
