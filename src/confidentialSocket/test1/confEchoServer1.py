import asyncio
from confidentialSocket.conf_socket import ConfidentialSocket, getSystemIPv6, generateFakeIPv6, getSystemIPv6_2
from sys import stderr  # for some reason Docker won't show output from stdout

class EchoServerProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        print("!!!datagram_received!!!", file=stderr)
        print('Received %r from %s' % (message, addr), file=stderr)
        print('Send %r to %s' % (message, addr), file=stderr)
        self.transport.sendto(data, addr)


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