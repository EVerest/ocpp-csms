# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2024 Pionix GmbH and Contributors to EVerest
import asyncio
import logging

import websockets.asyncio
import websockets.asyncio.server
from central_systems.central_system_v16 import ChargePoint16
from central_systems.central_system_v201 import ChargePoint201
import http
import websockets
import ssl
from pathlib import Path
import argparse

__version__ = "0.1.0"

iso15118_certs = None
reject_auth = False


async def process_request(connection, request):
    logging.info(f'request:\n{request}')
    if reject_auth:
        logging.info(
            'Rejecting authorization because of the --reject-auth command line parameter')
        return (
            http.HTTPStatus.UNAUTHORIZED,
            [],
            b'Invalid credentials\n',
        )
    return None


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
        cp = ChargePoint16(charge_point_id, websocket,
                           iso15118_certs=iso15118_certs)
        await cp.start()
    else:
        charge_point_id = path.strip("/")
        cp = ChargePoint201(charge_point_id, websocket,
                            iso15118_certs=iso15118_certs)
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

    parser.add_argument('--certs', type=str, default="../everest-core/build/dist/etc/everest/certs",
                        help='Directory containing certificates (default: ../everest-core/build/dist/etc/everest/certs)')

    parser.add_argument('certificates', type=str, default=None, nargs='?',
                        help='Directory containing certificates (default: identical to --certs')

    parser.add_argument('--reject-auth', action='store_true', default=False,
                        help='Reply with 403 error in connection')

    args = parser.parse_args()

    host = args.host
    tls_host = args.tls_host
    if not tls_host:
        tls_host = host

    port = args.port
    tls_port = args.tls_port

    cert_chain = args.cert_chain

    certs = Path(args.certs)
    if not certs.exists():
        logging.warning(
            'Directory containing certificates does not exist, ISO15118 features are not available')
    else:
        global iso15118_certs
        iso15118_certs = certs

    global reject_auth
    reject_auth = args.reject_auth

    server = await websockets.serve(
        on_connect, host, port, subprotocols=["ocpp1.6", "ocpp2.0.1"], process_request=process_request
    )

    tls_server = None
    if cert_chain:

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        ssl_context.load_cert_chain(cert_chain)

        tls_server = await websockets.serve(
            on_connect, tls_host, tls_port, subprotocols=["ocpp1.6", "ocpp2.0.1"], process_request=process_request, ssl=ssl_context
        )

    logging.info("OCPP CSMS Started listening to new connections...")
    await server.wait_closed()
    if tls_server:
        await tls_server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        exit(0)
