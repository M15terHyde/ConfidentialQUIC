#!/bin/sh
# Using IP address instead of server hostname.
# Using hostname enables hostname verification in the server tls certifricate.
# Currently takes issue with 'server' complaining it doesn't match 'localhost' but I can't track down where 'localhost' is originating from :/ It's probably built into the pregenerated certs in /tests
# Would likely need to generate new certs for new hostnames which I'd rather not fool with. Just use IP.
# https://serverfault.com/questions/205793/how-can-one-distinguish-the-host-and-the-port-in-an-ipv6-url

sleep 2 ;
python examples/control_test/http3_client.py --ca-certs tests/pycacert.pem https://[2001:db8:1::10]:4433/

sleep 1 ;
python examples/control_test/http3_client.py --ca-certs tests/pycacert.pem https://[2001:db8:1::10]:4433/1234