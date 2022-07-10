#!/bin/sh

python examples/conf_test3/http3_server.py -v -q /qlogstore --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem --host 2001:db8:1::10