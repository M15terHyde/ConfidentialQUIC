import asyncio
from asyncio.selector_events import _SelectorDatagramTransport
from ipaddress import IPv6Address
from confidentialSocket.conf_socket import ConfidentialSocket, getSystemIPv6, generateFakeIPv6, getSystemIPv6_2
from sys import stderr
from json import loads, dumps

class EchoClientProtocol:
    def __init__(self, obj, on_con_lost):
        self.obj = obj
        self.on_con_lost = on_con_lost
        self.transport = None
    
    # Base Protocol
    def connection_made(self, transport: _SelectorDatagramTransport):
        self.transport = transport
        self.sock: ConfidentialSocket = transport._sock
        data = dumps(self.obj)
        print(f"Sending: {data} to { self.obj['reply_as'] }", file=stderr)
        self.sock.sendto(data.encode(), (self.sock.peer_ip, self.sock.peer_port, 0, 0), source_address=self.obj['reply_as'])
    
    def connection_lost(self, exc):
        print("Connection closed")
        self.on_con_lost.set_result(True)

    # Datagram Protocol
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

    # Create the confidential socket
    peerAddr=(IPv6Address("2001:db8:1::10").exploded, 8080, 0, 0) # Hardcoded from server
    recvIP6 = getSystemIPv6_2()
    recvPort = 9999
    recvAddr = (recvIP6.exploded, recvPort, 0, 0)
    

    confSock = ConfidentialSocket()
    confSock.bind(recvAddr) # Setup recv
    confSock.connect( peerAddr ) # Docs say must already be connected

    startNum = 5
    obj = {}
    obj['reply_to'] = recvAddr
    obj['reply_as'] = ('2001:db8:1::50', 10999, 0, 0)
    obj['num'] = startNum

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoClientProtocol(obj, on_con_lost),
        sock= confSock)

    try:
        await on_con_lost
    finally:
        transport.close()


asyncio.run(main())