# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
import asyncio
import logging
from central_systems.central_system_v16 import ChargePoint16
from central_systems.central_system_v201 import ChargePoint201
import websockets

async def on_connect(websocket, path):
    try:
        requested_protocols = websocket.request_headers["Sec-WebSocket-Protocol"]
    except KeyError:
        logging.error(
            "Client hasn't requested any Subprotocol. Closing Connection")
        return await websocket.close()
    if websocket.subprotocol:
        logging.info("Protocols Matched: %s", websocket.subprotocol)
    else:
        logging.warning(
            "Protocols Mismatched | Expected Subprotocols: %s,"
            " but client supports  %s | Closing connection",
            websocket.available_subprotocols,
            requested_protocols,
        )
        return await websocket.close()

    if (websocket.subprotocol == "ocpp1.6"):
        charge_point_id = path.strip("/")
        logging.info(f"{charge_point_id} connected using OCPP1.6")
        cp = ChargePoint16(charge_point_id, websocket)
        await cp.start()
    else:
        charge_point_id = path.strip("/")
        cp = ChargePoint201(charge_point_id, websocket)
        logging.info(f"{charge_point_id} connected using OCPP2.0.1")
        await cp.start()

async def main():
    server = await websockets.serve(
        on_connect, "0.0.0.0", 9000, subprotocols=["ocpp1.6", "ocpp2.0.1"]
    )

    logging.info("OCPP CSMS Started listening to new connections...")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
