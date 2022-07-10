from sys import stderr
import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Callable, Optional, cast

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import NetworkAddress, QuicConnection
from aioquic.tls import SessionTicketHandler
#from .protocol import QuicConnectionProtocol, QuicStreamHandler
from .conf_protocol import QuicConnectionProtocol, QuicStreamHandler

from src.confidentialSocket.conf_socket import ConfidentialSocket, getSystemIPv6, getValidAddressTuple

__all__ = ["connect"]

# keep compatibility for Python 3.7 on Windows
if not hasattr(socket, "IPPROTO_IPV6"):
    socket.IPPROTO_IPV6 = 41


@asynccontextmanager
async def connect(
    host: str,  # peer ip
    port: int,  # peer port
    *,
    configuration: Optional[QuicConfiguration] = None,
    create_protocol: Optional[Callable] = QuicConnectionProtocol,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stream_handler: Optional[QuicStreamHandler] = None,
    wait_connected: bool = True,
    local_port: int = 0,
    send_as_ipv6: str = None,
    send_as_port: str = None,
    recv_from_ipv6: str = None,
    recv_from_port: int = None,
) -> AsyncGenerator[QuicConnectionProtocol, None]:
    """
    Connect to a QUIC server at the given `host` and `port`.
    
    :meth:`connect()` returns an awaitable. Awaiting it yields a
    :class:`~aioquic.asyncio.QuicConnectionProtocol` which can be used to
    create streams.
    
    :func:`connect` also accepts the following optional arguments:
    
    * ``configuration`` is a :class:`~aioquic.quic.configuration.QuicConfiguration`
      configuration object.
    * ``create_protocol`` allows customizing the :class:`~asyncio.Protocol` that
      manages the connection. It should be a callable or class accepting the same
      arguments as :class:`~aioquic.asyncio.QuicConnectionProtocol` and returning
      an instance of :class:`~aioquic.asyncio.QuicConnectionProtocol` or a subclass.
    * ``session_ticket_handler`` is a callback which is invoked by the TLS
      engine when a new session ticket is received.
    * ``stream_handler`` is a callback which is invoked whenever a stream is
      created. It must accept two arguments: a :class:`asyncio.StreamReader`
      and a :class:`asyncio.StreamWriter`.
    * ``local_port`` is the UDP port number that this client wants to bind.
    """
    print("conf_client::connect", file=stderr)

    loop = asyncio.get_event_loop()
    local_host = "::"
    
    # if host is not an IP address, pass it to enable SNI
    try:
        ipaddress.ip_address(host)
        server_name = None
    except ValueError:
        server_name = host
    
    # lookup remote address
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)
    
    # prepare QUIC connection
    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if configuration.server_name is None:
        configuration.server_name = server_name
    connection = QuicConnection(
        configuration=configuration, session_ticket_handler=session_ticket_handler
    )

    #TODO: Might could enable the setting of a single filed: ip or port and have a default for the other
    # Only accept packets back from this address. Server must reply as this address
    recv_from = (recv_from_ipv6, recv_from_port, 0, 0) if (recv_from_ipv6 is not None and recv_from_port is not None) else None
    print(f"conf_client recv_from: {recv_from}", file=stderr)

    #TODO Might could enable the setting of a single filed: ip or port and have a default for the other
    # The address we send as
    send_as = (send_as_ipv6, send_as_port, 0, 0) if (send_as_ipv6 is not None and send_as_port is not None) else None
    print(f"conf_client send_as: {send_as}", file=stderr)

    # explicitly enable IPv4/IPv6 dual stack
    #sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock = ConfidentialSocket()
    completed = False
    try:
        # verify valid local_port
        # port cannot be 0 for conf_cocket as the bind port defaults to send port.
        # No other changes are made to it from scapy.
        if local_port:
            bind_addr = (getSystemIPv6().exploded, local_port, 0, 0) # keep the port, get ipv6
        else:
            bind_addr = getValidAddressTuple() # get a new port inside the full address
        
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        print(f"conf_client binding to: {bind_addr}", file=stderr)
        sock.bind( bind_addr )
        completed = True
    finally:
        if not completed:
            sock.close()
    # connect
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection, stream_handler=stream_handler),
        sock=sock,
    )
    protocol = cast(QuicConnectionProtocol, protocol)
    try:
        print(f"conf_client connecting to {addr}\n as {send_as} and recv_from: {recv_from}", file=stderr)
        protocol.connect(addr, send_as=send_as, recv_from=recv_from)  # addr is destination address
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()
