# OCPP1.6 and OCPP2.0.1 CSMS
This repository provides a very simple and experimental OCPP1.6 and OCPP2.0.1 CSMS based on the MIT licensed implementation of TheMobilityHouse (https://github.com/mobilityhouse/ocpp). Its main purpose is currently to demonstrate the OCPP communication involved in the Plug&Charge between EVSE and the central system. 

The CSMS will respond "friendly" to most OCPP messages initiated by the Chargepoint and the CSMS will not initiate messages itself. The CSMS includes the extension to generate a valid ISO15118 CertificateInstallationResponse triggered by a ISO15118 CertificateInstallationRequest. This requires a valid PKI for ISO15118. The path to the certificates is given as a command line argument. For the software in the loop simulation with EVerest, its recommended to use the automatically installed PKI that comes with the EVerest installation, because the certificate and key file names are currently fixed.

# Usage

In this project [Josev](https://github.com/EVerest/ext-switchev-iso15118) is needed as git submodule to generate the CertificateInstallationResponse. To clone Josev as well, execute these commands after cloning this repo:

```bash
git clone --recurse-submodules git@github.com:EVerest/ocpp-csms.git
```

Install the necessary python packages using

```bash
python3 -m pip install -r requirements.txt
```

Use the following command to start the CSMS server on localhost:9000 and provide the directory of the certificates and keys. For now, a fixed structure for the certificates and keys is required. 

```bash
python3 central_system.py <path-to-everest-certs>
```

e.g

```bash
python3 central_system.py ~/checkout/everest-workspace/everest-core/build/dist/etc/everest/certs/
```

You can now start EVerest with an OCPP configuration that points to this CSMS. The CSMS is able to handle OCPP1.6 and OCPP2.0.1 based on the specified websocket subprotol of the client.
