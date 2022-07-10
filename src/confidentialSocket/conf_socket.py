'''
This module provides socket support for confidential connections.
It enables the specification of the public L3/IP source address
and the public L4 UDP source port. It does not support TCP.
'''


import socket
from scapy.all import IPv6, UDP
from scapy.sendrecv import send as scapy_send
from ipaddress import IPv6Address, ip_address
from typing import List, TypeAlias
from os import popen
# from socket import _Address # somehow doesn't work

from sys import stderr
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)7s: %(message)s',
    stream=stderr,
)


import pprint
pp = pprint.PrettyPrinter(indent=2)




# importing from socket doesn't work somehow
_Address: TypeAlias = tuple

# (host, port, flowinfo, scope_id)
Address6: TypeAlias = tuple[ str, int, any, any ]

# (host, port, flowinfo, scope_id, fakeSenderIP, fakeSenderPort)
ConfidentialAddress6: TypeAlias = tuple[ str, int, any, any, str, int ]




def getValidSocket(family=socket.AF_INET6, type=socket.SOCK_DGRAM) -> socket.socket:
    try:
        tempSock = socket.socket(family=family, type=type)
        tempSock.settimeout(0)
    except Exception:
        raise EnvironmentError("Could not get valid socket")
    return tempSock


def getValidAddressTuple(family=socket.AF_INET6, type=socket.SOCK_DGRAM) -> _Address:
    try:
        tempSock = getValidSocket(family, type)
        if family == socket.AF_INET6:
            tempSock.connect(('2001:db8:1::15', 8080, 0, 0))    # Causing OSError("Cannot connect to network") when run in docker-compose but works fine in JIT
        if family == socket.AF_INET:
            tempSock.connect(('9.9.9.9', 8080))
        addr = tempSock.getsockname()
    except Exception:
        raise EnvironmentError("Could not get address tuple")
    finally:
        tempSock.close()
    return addr


# return the system's valid IPv6 address. Error otherwise
def getSystemIPv6() -> IPv6Address:
    if not socket.has_ipv6:
        return EnvironmentError("IPv6 not supported")
    
    try:
        ip = getValidAddressTuple()[0]
    except Exception:
        raise EnvironmentError("Could not find IPv6 address")
    return ip_address(ip)


def getFreePort() -> int:
    try:
        port = getValidAddressTuple()[1]
    except Exception:
        raise EnvironmentError("Could not find a free port")
    return port


def getSystemIPv6_2() -> IPv6Address | bool:
    ret = popen('hostname -I').read()
    #print(f"hostname -I : {ret}")
    if len(ret) == 0:
        return False
    
    # get them individually
    ips = ret.split(' ')

    # Get rid of non IPv6
    ips6 = []
    for ip in ips:
        if ':' in ip:
            ips6.append(ip)
    if len(ips6) == 0:
        return False

    # return the first valid ipv6
    return ip_address(ips6[0])

# 
def generateFakeIPv6(origin: IPv6Address = None) -> IPv6Address | bool:
    # TODO: Generate based on input address.
    # Provide different levels of modification to get past reverse path forwarding.
    if origin is None:
        return ip_address('2001:4860:4860::8888')   # pulled from google ipv6 dns server. It's okay for now.
    
    # Change the last octet as a proof of concept
    tempAdr = origin.exploded.split(':')
    tempAdr[7]='9999'
    return ip_address(':'.join(tempAdr))




# NOTE: Due to IPv4 reliance on NAT this implementation only supports IPv6. NAT removes confidentiality
# NOTE: Although SOCK_DGRAM is UDP standard, SOCK_RAW is required to write our own L3/IP header. SCAPY uses SOCK_RAW    
# TODO: Would it be better to use a singular raw socket for both send & recv?
# NOTE: These are inherently more difficult to manage than a standard socket.
#   A lot of normal socket concepts stop working when we move data from one layer of the OSI model to another.
#   For example the intended purpose of this socket is each peer communicates their correct IP and port (L3&4) inside the data portion of the UDP datagram.
#   This socket's configuration must therefore be actively managed by the
class ConfidentialSocket():

    def __init__(self):
        # address this socket is listening on
        self.recv_ip = None
        self.recv_port = None
        # Destination address this socket sends to
        self.peer_ip = None
        self.peer_port = None
        # The address this socket will send as in outgoing packets
        self.source_ip = None
        self.source_port = None
        # Might be useful. Might only be relevant to the recv_sock which handles it anyway.
        # The address our peer is sending as. Their source_ip and source_port. Only allow messages from this address.
        #self.recv_from_ip
        #self.recv_from_port
        
        self.recv_sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)     # IPv6 only to 1 (true)

        self.closed = False
        self.type = socket.SOCK_DGRAM

        self.log = logging.getLogger('')
        self.log.setLevel(logging.INFO)#logging.DEBUG)
    

    def is_bound(self) -> bool: # Added
        return (self.recv_ip is not None) and (self.recv_port is not None)

    def is_connected(self) -> bool: # Added
        return  (self.recv_ip is not None) and (self.recv_port is not None) and \
                (self.peer_ip is not None) and (self.peer_port is not None) and \
                (self.source_ip is not None) and (self.source_port is not None)
    
    def accept(self):
        return NotImplementedError("ConfidentialSocket.accept not implemented")
    
    def bind(self,  address: _Address) -> None:
        (self.recv_ip, self.recv_port) = address[0:2]
        return self.recv_sock.bind(address)

    def close(self) -> None:
        self.closed = True
        return self.recv_sock.close()
    
    # Required reading https://linux.die.net/man/3/connect
    def connect(self,  address: _Address,  source_address: _Address = None) -> None:
        # if not bound, must bind
        if not self.is_bound():
            self.bind(getSystemIPv6(), getFreePort())

        (self.peer_ip, self.peer_port) = address[0:2]
        if source_address is not None: 
            (self.source_ip, self.source_port) = source_address[0:2]
        else: 
            (self.source_ip, self.source_port) = (self.recv_ip, self.recv_port)   # default to recv address
        return #self.recv_sock.connect(address) # Connecting recv socket would block the peer being able to send_as a different address. Connecting recv would only listen for the real address

    def connect_as(self,  address: _Address,  source_address: _Address) -> None:  # Added
        # if not bound, must bind
        if not self.is_bound():
            self.bind(getSystemIPv6(), getFreePort())

        (self.peer_ip, self.peer_port) = address[0:2]
        (self.source_ip, self.source_port) = source_address[0:2]
        return #self.recv_sock.connect(address)
    
    def connect_ex(self,  address: _Address,  source_address: _Address = None) -> int:
        # if not bound, must bind
        if not self.is_bound():
            self.bind(getSystemIPv6(), getFreePort())

        (self.peer_ip, self.peer_port) = address[0:2]
        if source_address is not None: 
            (self.source_ip, self.source_port) = source_address[0:2]
        else:
            (self.source_ip, self.source_port) = (self.recv_ip, self.recv_port)   # default to recv address
        return #self.recv_sock.connect_ex(address)

    def connect_as_ex(self,  address: _Address,  source_address: _Address) -> int:   # Added
        # if not bound, must bind
        if not self.is_bound():
            self.bind(getSystemIPv6(), getFreePort())

        (self.peer_ip, self.peer_port) = address[0:2]
        (self.source_ip, self.source_port) = source_address[0:2]
        return self.recv_sock.connect_ex(address)
    
    def detach(self) -> int:
        #return self.recv_sock.detach(*args, **kwargs)
        return NotImplementedError("ConfidentialSocket.detach not implemented")
    
    def dup(self, *args, **kwargs):
        #return self.recv_sock.dup(*args, **kwargs)
        return NotImplementedError("ConfidentialSocket.dup not implemented")

    def family(self):
        return socket.AF_INET6
    
    def fileno(self, *args, **kwargs):
        return self.recv_sock.fileno(*args, **kwargs)

    def get_inheritable(self, *args, **kwargs):
        return self.recv_sock.get_inheritable(*args, **kwargs)
    
    def getblocking(self, *args, **kwargs):
        return self.recv_sock.getblocking(*args, **kwargs)

    def getpeername(self, *args, **kwargs):
        return self.recv_sock.getpeername(*args, **kwargs)
    
    def getsockname(self, *args, **kwargs):
        return self.recv_sock.getsockname(*args, **kwargs)

    def getsockopt(self, *args, **kwargs):
        return self.recv_sock.getsockopt(*args, **kwargs)

    def gettimeout(self, *args, **kwargs):
        return self.recv_sock.gettimeout(*args, **kwargs)

    def ioctl(self, *args, **kwargs):
        return self.recv_sock.ioctl(*args, **kwargs)
    
    def listen(self, *args, **kwargs):
        return self.recv_sock.listen(*args, **kwargs)

    def makefile(self, *args, **kwargs):
        return self.recv_sock.makefile(*args, **kwargs)

    def proto(self):
        return self.recv_sock.proto
    
    def recv(self, *args, **kwargs) -> bytes:
        return self.recv_sock.recv(*args, **kwargs)
    
    def recv_into(self, *args, **kwargs) -> int:
        return self.recv_sock.recv_into(*args, **kwargs)

    def recvfrom(self, *args, **kwargs) -> tuple[bytes, any]:
        return self.recv_sock.recvfrom(*args, **kwargs)
    
    def recvfrom_into(self, *args, **kwargs) -> tuple[int, any]:
        return self.recv_sock.recvfrom_into(*args, **kwargs)
    ###
    
    def send(self, __data, __flags: int = ...) -> int:
        if self.log: self.log.debug(f"ConfidentialSendSocket.send(__data={__data} __flags={__flags}")
        assert self.is_connected()
        assert not self.closed
        pkt = IPv6( src=self.recv_ip, dst=self.peer_ip ) / UDP( sport=self.recv_port, dport=self.peer_port ) /  __data
        scapy_send(pkt, verbose=False)
    
    def sendall(self, __data, __flags: int = ...) -> None:
        if self.log: self.log.debug(f"ConfidentialSendSocket.sendall(__data={__data} __flags={__flags}")
        assert self.is_connected()
        assert not self.closed
        raise NotImplementedError("ConfidentialSendSocket.sendall not implimented")

    def sendfile(self, file, offset: int = ..., count: int | None = ...) -> int:
        if self.log: self.log.debug(f"ConfidentialSendSocket.sendfile(file={file} offset={offset} count={count}")
        assert self.is_connected()
        assert not self.closed
        raise NotImplementedError("ConfidentialSendSocket.sendfile not implimented")
    
    # (data, address, source_address=...)
    def sendto(self, *args, source_address: _Address = None) -> int:
        if self.log: self.log.debug(f"ConfidentialSendSocket.sendto(args={args} source_address={source_address} recv_addr={self.recv_ip, self.recv_port}")
        assert not self.closed

        # There are two different possible parameter positions
        __source_address = source_address if source_address != None else (self.recv_ip, self.recv_port) # default to the recv address
        __data = None
        __address: _Address = ()
        __flags: int = 0
        if len(args) == 2:
            __data = args[0]
            __address = args[1] if args[1] != None else (self.peer_ip, self.peer_port)
        elif len(args) > 2:
            __data = args[0]
            __flags = args[1]
            __address = args[2] if args[2] != None else (self.peer_ip, self.peer_port)

        pkt = IPv6( src=__source_address[0], dst=__address[0] ) / UDP( sport=__source_address[1], dport=__address[1] ) / __data
        scapy_send(pkt, verbose=False)
    
    # (data, address, source_address)
    # (data, flags, address, source_address)
    def sendto_as(self, *args, **kwargs) -> int:
        if self.log: self.log.debug(f"ConfidentialSendSocket.sendto(args={args} kwargs={kwargs}")
        #assert self.recv_ip
        #assert self.recv_port
        assert not self.closed

        # There are two different possible parameter positions
        __data = None
        __address: _Address = ()
        __source_address: _Address = ()
        __flags: int = 0
        if len(args) == 3:
            __data = args[0]
            __address = args[1]
            __source_address = args[2]
        elif len(args) > 3:
            __data = args[0]
            __flags = args[1]
            __address = args[2]
            __source_address = args[3]

        pkt = IPv6( src=__source_address[0], dst=__address[0] ) / UDP( sport=__source_address[1], dport=__address[1] ) / __data
        scapy_send(pkt, verbose=False)
    ###

    def set_inheritable(self, *args, **kwargs):
        return self.recv_sock.sendto(*args, **kwargs)

    def setblocking(self, *args, **kwargs):
        return self.recv_sock.setblocking(*args, **kwargs)

    def setsockopt(self, *args, **kwargs):
        return self.recv_sock.setsockopt(*args, **kwargs)
    
    def settimeout(self, *args, **kwargs):
        return self.recv_sock.settimeout(*args, **kwargs)
    
    def share(self, *args, **kwargs):
        return self.recv_sock.share(*args, **kwargs)
    ###
    def shutdown(self, *args, **kwargs):
        self.closed = True
        return self.recv_sock.shutdown(*args, **kwargs)
    ###
    def timeout(self, *args, **kwargs):
        return self.recv_sock.timeout(*args, **kwargs)

    def type(self):
        return self.recv_sock.type

