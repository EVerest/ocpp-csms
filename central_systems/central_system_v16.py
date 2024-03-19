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
from ocpp.v201.enums import (AuthorizationStatusType, GenericStatusType,
                             GetCertificateStatusType, Iso15118EVCertificateStatusType)
from exi_generator import EXIGenerator

logging.basicConfig(level=logging.INFO)


class ChargePoint16(cp):
    @on(Action.BootNotification)
    def on_boot_notification(
        self, charge_point_vendor: str, charge_point_model: str, **kwargs
    ):
        return call_result.BootNotificationPayload(
            current_time=datetime.utcnow().isoformat(),
            interval=10,
            status=RegistrationStatus.accepted,
        )

    @on(Action.Heartbeat)
    def on_heartbeat(self, **kwargs):
        return call_result.HeartbeatPayload(current_time=datetime.utcnow().isoformat())

    @on(Action.Authorize)
    def on_authorize(self, **kwargs):
        id_tag_info = IdTagInfo(status=AuthorizationStatus.accepted)
        return call_result.AuthorizePayload(id_tag_info=id_tag_info)

    @on(Action.MeterValues)
    def on_meter_values(self, **kwargs):
        return call_result.MeterValuesPayload()

    @on(Action.StatusNotification)
    def on_status_notification(self, **kwargs):
        return call_result.StatusNotificationPayload()

    @on(Action.StartTransaction)
    def on_start_transaction(self, **kwargs):
        id_tag_info = IdTagInfo(status=AuthorizationStatus.accepted)
        return call_result.StartTransactionPayload(transaction_id=1, id_tag_info=id_tag_info)

    @on(Action.StopTransaction)
    def on_stop_transaction(self, **kwargs):
        return call_result.StopTransactionPayload()

    @on(Action.DiagnosticsStatusNotification)
    def on_diagnostics_status_notification(self, **kwargs):
        return call_result.DiagnosticsStatusNotificationPayload()

    @on(Action.SignCertificate)
    def on_sign_certificate(self, **kwargs):
        self.csr = kwargs['csr']
        return call_result.SignCertificatePayload(GenericStatus.accepted)

    @on(Action.SecurityEventNotification)
    def on_security_event_notification(self, **kwargs):
        return call_result.SecurityEventNotificationPayload()

    @on(Action.SignedFirmwareStatusNotification)
    def on_signed_update_firmware_status_notificaion(self, **kwargs):
        return call_result.SignedFirmwareStatusNotificationPayload()

    @on(Action.LogStatusNotification)
    def on_log_status_notification(self, **kwargs):
        return call_result.LogStatusNotificationPayload()

    @on(Action.FirmwareStatusNotification)
    def on_firmware_status_notification(self, **kwargs):
        return call_result.FirmwareStatusNotificationPayload()

    @on(Action.DataTransfer)
    def on_data_transfer(self, **kwargs):
        req = call.DataTransferPayload(**kwargs)
        if req.vendor_id == 'org.openchargealliance.iso15118pnc':
            if (req.message_id == "Authorize"):
                response = call_result201.AuthorizePayload(
                    id_token_info=IdTokenInfoType(
                        status=AuthorizationStatusType.accepted
                    )
                )
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(
                        snake_to_camel_case(asdict(response))))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif (req.message_id == "CertificateSigned"):
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "DeleteCertificate":
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            elif req.message_id == "Get15118EVCertificate":
                exi_generator = EXIGenerator(certs_path=sys.argv[1])
                exi_request = json.loads(req.data)["exiRequest"]
                namespace = json.loads(kwargs['data'])['iso15118SchemaVersion']
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(snake_to_camel_case(asdict(
                        call_result201.Get15118EVCertificatePayload(
                            status=Iso15118EVCertificateStatusType.accepted,
                            exi_response=exi_generator.generate_certificate_installation_res(
                                exi_request,
                                namespace
                            )
                        ))
                    )))
                )
            elif req.message_id == "GetCertificateStatus":
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(remove_nones(snake_to_camel_case(asdict(
                        call_result201.GetCertificateStatusPayload(
                            status=GetCertificateStatusType.accepted,
                            ocsp_result="IS_FAKED"
                        )
                    ))))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "InstallCertificate":
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            elif req.message_id == "SignCertificate":
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.accepted,
                    data=json.dumps(asdict(
                        call_result201.SignCertificatePayload(
                            status=GenericStatusType.accepted
                        )
                    ))
                )
            # Should not be part of DataTransfer.req from CP->CSMS
            elif req.message_id == "TriggerMessage":
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
            else:
                return call_result.DataTransferPayload(
                    status=DataTransferStatus.unknown_message_id,
                    data="Please implement me"
                )
        else:
            return call_result.DataTransferPayload(
                status=DataTransferStatus.unknown_vendor_id,
                data="Please implement me"
            )

    async def get_configuration_req(self, **kwargs):
        payload = call.GetConfigurationPayload(**kwargs)
        return await self.call(payload)

    async def change_configuration_req(self, **kwargs):
        payload = call.ChangeConfigurationPayload(**kwargs)
        return await self.call(payload)

    async def clear_cache_req(self, **kwargs):
        payload = call.ClearCachePayload()
        return await self.call(payload)

    async def remote_start_transaction_req(self, **kwargs):
        payload = call.RemoteStartTransactionPayload(**kwargs)
        return await self.call(payload)

    async def remote_stop_transaction_req(self, **kwargs):
        payload = call.RemoteStopTransactionPayload(**kwargs)
        return await self.call(payload)

    async def unlock_connector_req(self, **kwargs):
        payload = call.UnlockConnectorPayload(**kwargs)
        return await self.call(payload)

    async def change_availability_req(self, **kwargs):
        payload = call.ChangeAvailabilityPayload(**kwargs)
        return await self.call(payload)

    async def reset_req(self, **kwargs):
        payload = call.ResetPayload(**kwargs)
        return await self.call(payload)

    async def get_local_list_version_req(self, **kwargs):
        payload = call.GetLocalListVersionPayload()
        return await self.call(payload)

    async def send_local_list_req(self, **kwargs):
        payload = call.SendLocalListPayload(**kwargs)
        return await self.call(payload)

    async def reserve_now_req(self, **kwargs):
        payload = call.ReserveNowPayload(**kwargs)
        return await self.call(payload)

    async def cancel_reservation_req(self, **kwargs):
        payload = call.CancelReservationPayload(**kwargs)
        return await self.call(payload)

    async def trigger_message_req(self, **kwargs):
        payload = call.TriggerMessagePayload(**kwargs)
        return await self.call(payload)

    async def set_charging_profile_req(self, payload: call.SetChargingProfilePayload):
        logging.info(payload)
        return await self.call(payload)

    async def get_composite_schedule(self, payload: call.GetCompositeSchedulePayload) -> call_result.GetCompositeSchedulePayload:
        return await self.call(payload)

    async def get_composite_schedule_req(self, **kwargs) -> call_result.GetCompositeSchedulePayload:
        payload = call.GetCompositeSchedulePayload(**kwargs)
        return await self.call(payload)

    async def clear_charging_profile_req(self, **kwargs):
        payload = call.ClearChargingProfilePayload(**kwargs)
        return await self.call(payload)

    async def data_transfer_req(self, **kwargs):
        payload = call.DataTransferPayload(**kwargs)
        return await self.call(payload)

    async def extended_trigger_message_req(self, **kwargs):
        payload = call.ExtendedTriggerMessagePayload(**kwargs)
        return await self.call(payload)

    async def certificate_signed_req(self, **kwargs):
        payload = call_result.CertificateSignedPayload(
            CertificateSignedStatus.rejected)
        return await self.call(payload)

    async def install_certificate_req(self, **kwargs):
        payload = call.InstallCertificatePayload(**kwargs)
        return await self.call(payload)

    async def get_installed_certificate_ids_req(self, **kwargs):
        payload = call.GetInstalledCertificateIdsPayload(**kwargs)
        return await self.call(payload)

    async def delete_certificate_req(self, **kwargs):
        payload = call.DeleteCertificatePayload(**kwargs)
        return await self.call(payload)

    async def get_log_req(self, **kwargs):
        payload = call.GetLogPayload(**kwargs)
        return await self.call(payload)

    async def signed_update_firmware_req(self, **kwargs):
        payload = call.SignedUpdateFirmwarePayload(**kwargs)
        return await self.call(payload)

    async def get_diagnostics_req(self, **kwargs):
        payload = call.GetDiagnosticsPayload(**kwargs)
        return await self.call(payload)

    async def update_firmware_req(self, **kwargs):
        payload = call.UpdateFirmwarePayload(**kwargs)
        return await self.call(payload)
