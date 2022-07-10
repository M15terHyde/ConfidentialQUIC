import asyncio
from asyncio.selector_events import _SelectorDatagramTransport
from confidentialSocket.conf_socket import ConfidentialSocket, getSystemIPv6, generateFakeIPv6, getSystemIPv6_2
from sys import stderr
from json import dumps, loads

class EchoServerProtocol:
    def connection_made(self, transport: _SelectorDatagramTransport):
        self.transport = transport
        self.sock = transport._sock

    def datagram_received(self, data, addr):
        json = data.decode(encoding='utf-8')
        print('Received %r from %s' % (json, addr), file=stderr)
        print('Send %r to %s' % (json, addr), file=stderr)
        obj = loads(json)
        reply_to = obj['reply_to']
        reply_as = obj['reply_as']
        num = obj['num']
        if num == 0:
            return
        newJson = {
            'reply_to': (self.sock.recv_ip, self.sock.recv_port, 0, 0),
            'reply_as': ('2001:db8:1::30', 10999, 0, 0),
            'num': (num-1)
            }
        self.sock.sendto(dumps(newJson).encode(), reply_to, source_address=reply_as)


async def main():
    print("Starting UDP server")
    
    # Create the confidential socket configuration
    recvIP6 = getSystemIPv6_2()
    recvPort = 8080
    print(f"Starting server on IP:{recvIP6.exploded} Port:{recvPort}")
    confSock = ConfidentialSocket()
    confSock.bind( (recvIP6.exploded, recvPort, 0, 0) ) # Docs say already connected.
    
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()
    
    # One protocol instance will be created to serve all
    # client requests.
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoServerProtocol(),
        sock=confSock)
    
    try:
        await asyncio.sleep(3600)  # Serve for 1 hour.
    finally:
        transport.close()


asyncio.run(main())