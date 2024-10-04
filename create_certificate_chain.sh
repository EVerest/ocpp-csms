#!/bin/bash

echo "creating certificate chain"

# create wildcard certificate
openssl req -newkey rsa:2048 -new -nodes -x509 -days 10 -keyout csms_cert_chain_key.pem -out csms_cert.pem
cat csms_cert.pem >> csms_cert_chain_key.pem