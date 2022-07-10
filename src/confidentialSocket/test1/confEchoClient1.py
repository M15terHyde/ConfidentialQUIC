import asyncio
from ipaddress import IPv6Address
from confidentialSocket.conf_socket import ConfidentialSocket, getSystemIPv6, generateFakeIPv6, getSystemIPv6_2

class EchoClientProtocol:
    def __init__(self, message, on_con_lost):
        self.message = message
        self.on_con_lost = on_con_lost
        self.transport = None
    
    # Base Protocol
    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        print('Send:', self.message)
        self.transport.sendto(self.message.encode())
    
    def connection_lost(self, exc):
        print("Connection closed")
        self.on_con_lost.set_result(True)

    # Datagram Protocol
    def datagram_received(self, data, addr):
        print("Received:", data.decode())
        
        print("Close the socket")
        self.transport.close()
    
    def error_received(self, exc):
        print('Error received:', exc)




# The goal in test1 is not to do anything wierd.
# The source address will be the client's real address.
# We will be checking if some of the core functionality of confSocket works.
async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()
    message = "Hello World!"

    # Create the confidential socket
    peerAddr=(IPv6Address("2001:db8:1::10").exploded, 8080, 0, 0) # Hardcoded from server
    recvIP6 = getSystemIPv6_2() 
    recvPort = 9999
    recvAddr = (recvIP6.exploded, recvPort, 0, 0)
    

    confSock = ConfidentialSocket()
    confSock.bind(recvAddr) # Setup recv
    confSock.connect( peerAddr ) # Docs say must already be connected

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoClientProtocol(message, on_con_lost),
        sock= confSock)

    try:
        await on_con_lost
    finally:
        transport.close()


asyncio.run(main())