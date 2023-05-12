#!/bin/sh
# Using IP address instead of server hostname.
# Using hostname enables hostname verification in the server tls certificate.
# Currently takes issue with 'server' complaining it doesn't match 'localhost' but I can't track down where 'localhost' is originating from :/ It's probably built into the pregenerated certs in /tests
# Would likely need to generate new certs for new hostnames which I'd rather not fool with. Just use IP.
# https://serverfault.com/questions/205793/how-can-one-distinguish-the-host-and-the-port-in-an-ipv6-url

# Providing the ssl_cert public key for testing: --certificate tests/ssl_cert.pem
# In production it would have to be pulled from DNS via the TLSA record but my DNS provider is having difficulties with TLSA at the moment.

sleep 2 ;
python examples/conf_test5/http3_client.py -v -q /qlogstore --ca-certs tests/pycacert.pem --certificate tests/ssl_cert.pem https://[2001:db8:1::10]:4433/

sleep 1 ;
python examples/conf_test5/http3_client.py -v -q /qlogstore --ca-certs tests/pycacert.pem --certificate tests/ssl_cert.pem https://[2001:db8:1::10]:4433/1234