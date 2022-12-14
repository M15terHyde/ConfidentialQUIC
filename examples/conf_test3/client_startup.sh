#!/bin/sh
# Using IP address instead of server hostname.
# Using hostname enables hostname verification in the server tls certifricate.
# Currently takes issue with 'server' complaining it doesn't match 'localhost' but I can't track down where 'localhost' is originating from :/ It's probably built into the pregenerated certs in /tests
# Would likely need to generate new certs for new hostnames which I'd rather not fool with. Just use IP.
# https://serverfault.com/questions/205793/how-can-one-distinguish-the-host-and-the-port-in-an-ipv6-url

sleep 2 ;
echo "Requesting homepage html"
python examples/conf_test3/http3_client.py -v -q /qlogstore --ca-certs tests/pycacert.pem https://[2001:db8:1::10]:4433/

sleep 1 ;
echo "Requesting 1234 bytes of data"
python examples/conf_test3/http3_client.py -v -q /qlogstore --ca-certs tests/pycacert.pem https://[2001:db8:1::10]:4433/1234