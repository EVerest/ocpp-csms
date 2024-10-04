# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
import asyncio
import logging
from central_systems.central_system_v16 import ChargePoint16
from central_systems.central_system_v201 import ChargePoint201
import websockets
import ssl
from pathlib import Path
import argparse

__version__ = "0.1.0"

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
    parser = argparse.ArgumentParser(
        description='A simple OCPP 1.6 and 2.0.1 CSMS')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')

    parser.add_argument('--host', type=str, default="0.0.0.0",
                        help='Host to listen on (default: 0.0.0.0)')

    parser.add_argument('--port', type=int, default=9000,
                        help='Plaintext port to listen on (default: 9000)')

    parser.add_argument('--tls-host', type=str, default=None,
                        help='TLS Host to listen on (default: value of --host (0.0.0.0))')

    parser.add_argument('--tls-port', type=int, default=9001,
                        help='TLS port to listen on (default: 9001)')

    parser.add_argument('--cert-chain', type=str, default=None,
                        help='Certificate chain to be used with TLS websockets. If not provided TLS will be disabled')

    args = parser.parse_args()

    host = args.host
    tls_host = args.tls_host
    if not tls_host:
        tls_host = host

    port = args.port
    tls_port = args.tls_port

    cert_chain = args.cert_chain
    server = await websockets.serve(
        on_connect, host, port, subprotocols=["ocpp1.6", "ocpp2.0.1"]
    )

    tls_server = None
    if cert_chain:

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        ssl_context.load_cert_chain(cert_chain)

        tls_server = await websockets.serve(
            on_connect, tls_host, tls_port, subprotocols=["ocpp1.6", "ocpp2.0.1"], ssl=ssl_context
        )

    logging.info("OCPP CSMS Started listening to new connections...")
    await server.wait_closed()
    if tls_server:
        await tls_server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
