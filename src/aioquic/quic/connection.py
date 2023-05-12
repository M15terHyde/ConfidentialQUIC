import binascii
import logging
import os
from collections import deque
from dataclasses import dataclass
from enum import Enum
from functools import partial
from sys import stderr
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, ClassVar
from ipaddress import IPv6Address, IPv4Address, ip_address
from typing_extensions import Self

from aioquic import tls
from aioquic.buffer import (
    UINT_VAR_MAX,
    UINT_VAR_MAX_SIZE,
    Buffer,
    BufferReadError,
    size_uint_var,
)
from . import events
from .configuration import QuicConfiguration
from .crypto import CryptoError, CryptoPair, KeyUnavailableError
from .logger import QuicLoggerTrace
from .packet import (
    CONNECTION_ID_MAX_SIZE,
    NON_ACK_ELICITING_FRAME_TYPES,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ONE_RTT,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ZERO_RTT,
    PROBING_FRAME_TYPES,
    RETRY_INTEGRITY_TAG_SIZE,
    STATELESS_RESET_TOKEN_SIZE,
    QuicErrorCode,
    QuicFrameType,
    QuicProtocolVersion,
    QuicStreamFrame,
    QuicTransportParameters,
    get_retry_integrity_tag,
    get_spin_bit,
    is_draft_version,
    is_long_header,
    pull_ack_frame,
    pull_quic_header,
    pull_quic_transport_parameters,
    push_ack_frame,
    push_quic_transport_parameters,
)
from .packet_builder import (
    PACKET_MAX_SIZE,
    QuicDeliveryState,
    QuicPacketBuilder,
    QuicPacketBuilderStop,
)
from .recovery import K_GRANULARITY, QuicPacketRecovery, QuicPacketSpace
from .stream import FinalSizeError, QuicStream, StreamFinishedError

# ConfidentialQUIC New
from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PUBLIC_KEY_TYPES
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
#####

logger = logging.getLogger("quic")

CRYPTO_BUFFER_SIZE = 16384
EPOCH_SHORTCUTS = {
    "I": tls.Epoch.INITIAL,
    "H": tls.Epoch.HANDSHAKE,
    "0": tls.Epoch.ZERO_RTT,
    "1": tls.Epoch.ONE_RTT,
}
MAX_EARLY_DATA = 0xFFFFFFFF
SECRETS_LABELS = [
    [
        None,
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
    ],
    [
        None,
        None,
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_TRAFFIC_SECRET_0",
    ],
]
STREAM_FLAGS = 0x07
STREAM_COUNT_MAX = 0x1000000000000000
UDP_HEADER_SIZE = 8

NetworkAddress = Any

# frame sizes
ACK_FRAME_CAPACITY = 64  # FIXME: this is arbitrary!
APPLICATION_CLOSE_FRAME_CAPACITY = 1 + 2 * UINT_VAR_MAX_SIZE  # + reason length
CONNECTION_LIMIT_FRAME_CAPACITY = 1 + UINT_VAR_MAX_SIZE
HANDSHAKE_DONE_FRAME_CAPACITY = 1
MAX_STREAM_DATA_FRAME_CAPACITY = 1 + 2 * UINT_VAR_MAX_SIZE
NEW_CONNECTION_ID_FRAME_CAPACITY = (
    1 + 2 * UINT_VAR_MAX_SIZE + 1 + CONNECTION_ID_MAX_SIZE + STATELESS_RESET_TOKEN_SIZE
)
PATH_CHALLENGE_FRAME_CAPACITY = 1 + 8
PATH_RESPONSE_FRAME_CAPACITY = 1 + 8
PING_FRAME_CAPACITY = 1
RESET_STREAM_FRAME_CAPACITY = 1 + 3 * UINT_VAR_MAX_SIZE
RETIRE_CONNECTION_ID_CAPACITY = 1 + UINT_VAR_MAX_SIZE
STOP_SENDING_FRAME_CAPACITY = 1 + 2 * UINT_VAR_MAX_SIZE
STREAMS_BLOCKED_CAPACITY = 1 + UINT_VAR_MAX_SIZE
TRANSPORT_CLOSE_FRAME_CAPACITY = 1 + 3 * UINT_VAR_MAX_SIZE  # + reason length


def EPOCHS(shortcut: str) -> FrozenSet[tls.Epoch]:
    return frozenset(EPOCH_SHORTCUTS[i] for i in shortcut)


def dump_cid(cid: bytes) -> str:
    return binascii.hexlify(cid).decode("ascii")


def get_epoch(packet_type: int) -> tls.Epoch:
    if packet_type == PACKET_TYPE_INITIAL:
        return tls.Epoch.INITIAL
    elif packet_type == PACKET_TYPE_ZERO_RTT:
        return tls.Epoch.ZERO_RTT
    elif packet_type == PACKET_TYPE_HANDSHAKE:
        return tls.Epoch.HANDSHAKE
    else:
        return tls.Epoch.ONE_RTT


def get_transport_parameters_extension(version: int) -> tls.ExtensionType:
    if is_draft_version(version):
        return tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS_DRAFT
    else:
        return tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS


def stream_is_client_initiated(stream_id: int) -> bool:
    """
    Returns True if the stream is client initiated.
    """
    return not (stream_id & 1)


def stream_is_unidirectional(stream_id: int) -> bool:
    """
    Returns True if the stream is unidirectional.
    """
    return bool(stream_id & 2)


class Limit:
    def __init__(self, frame_type: int, name: str, value: int):
        self.frame_type = frame_type
        self.name = name
        self.sent = value
        self.used = 0
        self.value = value


class QuicConnectionError(Exception):
    def __init__(self, error_code: int, frame_type: int, reason_phrase: str):
        self.error_code = error_code
        self.frame_type = frame_type
        self.reason_phrase = reason_phrase

    def __str__(self) -> str:
        s = "Error: %d, reason: %s" % (self.error_code, self.reason_phrase)
        if self.frame_type is not None:
            s += ", frame_type: %s" % self.frame_type
        return s


class QuicConnectionAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> Tuple[str, Any]:
        return "[%s] %s" % (self.extra["id"], msg), kwargs


@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: int
    stateless_reset_token: bytes = b""
    was_sent: bool = False


class QuicConnectionState(Enum):
    FIRSTFLIGHT = 0
    CONNECTED = 1
    CLOSING = 2
    DRAINING = 3
    TERMINATED = 4


@dataclass
class QuicNetworkPath:
    # correct items
    addr: NetworkAddress    # destination address and default recv_from address
    peer_destination_id: bytes | None = None
    self_addr: NetworkAddress | None = None # Address we are listening on
    # sending false source
    send_as: NetworkAddress | None = None   # source address (optional)
    send_as_conn_id: bytes = None
    # receiving false source
    recv_from: NetworkAddress | None = None # peer's false L3 address needed to match connection (optional)
    recv_from_conn_id: bytes = None
    bytes_received: int = 0
    bytes_sent: int = 0
    is_validated: bool = False
    local_challenge: Optional[bytes] = None
    remote_challenge: Optional[bytes] = None

    def can_send(self, size: int) -> bool:
        return self.is_validated or (self.bytes_sent + size) <= 3 * self.bytes_received
    
    def __post_init__(self):
        if not self.recv_from:
            self.recv_from = self.addr


@dataclass
class QuicReceiveContext:
    epoch: tls.Epoch
    host_cid: bytes
    network_path: QuicNetworkPath
    quic_logger_frames: Optional[List[Any]]
    time: float


@dataclass
class ReplyPath:
    LENGTH: ClassVar[int] = 54
    # Server will reply to
    peer_real_addr: IPv6Address | None = None
    peer_real_port: int = 0
    # Server will reply as
    send_as_addr: IPv6Address | None = None
    send_as_port: int = 0
    # Packets received from this address will be reply to at peer_real
    recv_from_addr: IPv6Address | None = None
    recv_from_port: int = 0

    def __init__(self, obj = None) -> None:
        if isinstance(obj, (bytes,bytearray)):
            self.from_bytes(obj)

    def from_bytes(self, buf: bytes) -> Self:
        assert len(buf) == self.LENGTH
        self.peer_real_addr = IPv6Address(buf[0:16])
        self.peer_real_port = int().from_bytes(buf[16:18], byteorder='big')
        self.send_as_addr = IPv6Address(buf[18:34])
        self.send_as_port = int().from_bytes(buf[34:36], byteorder='big')
        self.recv_from_addr = IPv6Address(buf[36:52])
        self.recv_from_port = int().from_bytes(buf[52:54], byteorder='big')
        return self

    def to_bytes(self) -> bytes:
        ret = bytearray()
        # peer_real
        ret.extend(self.peer_real_addr.packed)
        ret.extend(self.peer_real_port.to_bytes(2,"big"))
        # send_as
        ret.extend(self.send_as_addr.packed)
        ret.extend(self.send_as_port.to_bytes(2,"big"))
        # recv_from
        ret.extend(self.recv_from_addr.packed)
        ret.extend(self.recv_from_port.to_bytes(2,"big"))
        return bytes(ret)
    
    def to_QuicNetworkPath(self) -> QuicNetworkPath:
        return QuicNetworkPath(
            addr = ( self.peer_real_addr.compressed, self.peer_real_port, 0, 0 ),
            self_addr = None, # caller will need to fill this out on their own from connection properties
            send_as = ( self.send_as_addr.compressed, self.send_as_port, 0, 0),
            recv_from = ( self.recv_from_addr.compressed, self.recv_from_port, 0, 0),
        )
    
    # generates a ReplyPath to send to the peer. Values must be valid from the peer's perspective.
    def prep_to_send_from_QuicNetworkPath(self, qnp: QuicNetworkPath) -> Self:
        # the server's peer addres is our own address
        self.peer_real_addr=IPv6Address(qnp.self_addr[0])
        self.peer_real_port=qnp.self_addr[1]
        # the server must send_as who we receive_from
        self.send_as_addr=IPv6Address(qnp.recv_from[0])
        self.send_as_port=qnp.recv_from[1]
        # The server must receive_from the address we send_as
        self.recv_from_addr=IPv6Address(qnp.send_as[0])
        self.recv_from_port=qnp.send_as[1]
        return self


@dataclass
class ReplyPathV2:
    # fields present
    fields_present: bytes = 0x00
    SOURCE_IP_POSITION                      = 0b10000000
    SOURCE_PORT_POSITION                    = 0b01000000
    SOURCE_CONNECTION_ID_POSITION           = 0b00100000
    REPLY_AS_SOURCE_IP_POSITION             = 0b00010000
    REPLY_AS_SOURCE_PORT_POSITION           = 0b00001000
    REPLY_AS_SOURCE_CONNECTION_ID_POSITION  = 0b00000100
    RECEIVE_FROM_SOURCE_IP_POSITION         = 0b00000010
    RECEIVE_FROM_SOURCE_PORT_POSITION       = 0b00000001
    # Sender of the ReplyPath's info
    peer_real_addr: IPv6Address | None = None
    peer_real_port: int | None = None
    peer_real_connection_id: bytes | None = None
    # Sender instructed receiver to use these:
    send_as_addr: IPv6Address | None = None
    send_as_port: int | None = None
    send_as_source_connection_id: bytes | None = None
    # Receiver should expect to receive from (useful in identifying which network path to modify from new ReplyPath)
    recv_from_addr: IPv6Address | None = None
    recv_from_port: int | None = None
    #
    _logger: QuicConnectionAdapter| None = None

    def __init__(self, obj: Buffer|None = None, logger: QuicConnectionAdapter|None = None) -> None:
        if logger:
            self._logger = logger
        if(isinstance(obj, Buffer)):
            self.from_buffer(buf=obj)

    def from_buffer(self, buf: Buffer) -> None:
        self.fields_present = buf.pull_uint8()
        if self._logger: self._logger.debug(f"First byte INT: {self.fields_present}\t HEX:{self.fields_present.to_bytes(1,'big')}")

        # source ip field
        if(self.fields_present & self.SOURCE_IP_POSITION):
            ip_version = buf.pull_uint8()
            ip_bytes_length: int = 0
            if(ip_version == 4):
                ip_bytes_length = 4
            elif(ip_version == 6):
                ip_bytes_length = 16
            
            ip_bytes = buf.pull_bytes(ip_bytes_length)
            self.peer_real_addr = IPv6Address(ip_bytes)
        
        # source port field
        if(self.fields_present & self.SOURCE_PORT_POSITION):
            self.peer_real_port = int.from_bytes(buf.pull_bytes(2), "big")
        
        # source connection id field
        if(self.fields_present & self.SOURCE_CONNECTION_ID_POSITION):
            id_bytes_length = int.from_bytes(buf.pull_bytes(1), "big")
            self.peer_real_connection_id = buf.pull_bytes(id_bytes_length)
        
        # send as ip field
        if(self.fields_present & self.REPLY_AS_SOURCE_IP_POSITION):
            ip_version = buf.pull_uint8()
            ip_bytes_length: int = 0
            if(ip_version == 4):
                ip_bytes_length = 4
            elif(ip_version == 6):
                ip_bytes_length = 16
            
            ip_bytes = buf.pull_bytes(ip_bytes_length)
            self.send_as_addr = IPv6Address(ip_bytes)
        
        # send as port field
        if(self.fields_present & self.REPLY_AS_SOURCE_PORT_POSITION):
            self.send_as_port = int.from_bytes(buf.pull_bytes(2), "big")

        # reply as source connection id field
        if(self.fields_present & self.REPLY_AS_SOURCE_CONNECTION_ID_POSITION):
            id_bytes_length = int.from_bytes(buf.pull_bytes(1), "big")
            self.send_as_source_connection_id = buf.pull_bytes(id_bytes_length)

        # receive from address
        if(self.fields_present & self.RECEIVE_FROM_SOURCE_IP_POSITION):
            ip_version = buf.pull_uint8()
            ip_bytes_length: int = 0
            if(ip_version == 4):
                ip_bytes_length = 4
            elif(ip_version == 6):
                ip_bytes_length = 16
            
            ip_bytes = buf.pull_bytes(ip_bytes_length)
            self.recv_from_addr = IPv6Address(ip_bytes)

        # receive from port
        if(self.fields_present & self.RECEIVE_FROM_SOURCE_PORT_POSITION):
            self.recv_from_port = int.from_bytes(buf.pull_bytes(2), "big")
    
    def to_bytes(self) -> bytes:
        # A NoneType value means it has not been set. Do not encode this value in the ReplyPath
        out = bytearray()
        # append the fields present byte. We will manipulate it as we go
        out.append(0b00000000)
        
        # Source IP
        if self.peer_real_addr is not None:
            out[0] |= self.SOURCE_IP_POSITION
            out.extend( self.peer_real_addr.version.to_bytes(1,"big") )
            out.extend(self.peer_real_addr.packed)
            if self._logger: self._logger.debug(f"to_bytes:peer_real_addr: out={out}")
        
        # Source port
        if self.peer_real_port is not None:
            out[0] |= self.SOURCE_PORT_POSITION
            out.extend( self.peer_real_port.to_bytes(2,"big") )
            if self._logger: self._logger.debug(f"to_bytes:peer_real_port: out={out}")
        
        # Source Connection ID
        if self.peer_real_connection_id is not None:
            out[0] |= self.SOURCE_CONNECTION_ID_POSITION
            out.extend( len(self.peer_real_connection_id).to_bytes(1,"big") )
            out.extend(self.peer_real_connection_id)
            if self._logger: self._logger.debug(f"to_bytes:peer_real_connection_id: out={out}")
        
        # Reply As source IP
        if self.send_as_addr is not None:
            out[0] |= self.REPLY_AS_SOURCE_IP_POSITION
            out.extend( self.send_as_addr.version.to_bytes(1,"big") )
            out.extend(self.send_as_addr.packed)
            if self._logger: self._logger.debug(f"to_bytes:send_as_addr: out={out}")
        
        # Reply As port
        if self.send_as_port is not None:
            out[0] |= self.REPLY_AS_SOURCE_PORT_POSITION
            out.extend( self.send_as_port.to_bytes(2,"big") )
            if self._logger: self._logger.debug(f"to_bytes:send_as_port: out={out}")
        
        # Reply As source connection ID
        if self.send_as_source_connection_id is not None:
            out[0] |= self.REPLY_AS_SOURCE_CONNECTION_ID_POSITION
            out.extend( len(self.send_as_source_connection_id).to_bytes(1,"big") )
            out.extend(self.send_as_source_connection_id)
            if self._logger: self._logger.debug(f"to_bytes:send_as_source_connection_id: out={out}")

        # Receive from source address
        if self.recv_from_addr is not None:
            out[0] |= self.RECEIVE_FROM_SOURCE_IP_POSITION
            out.extend( self.recv_from_addr.version.to_bytes(1,"big") )
            out.extend(self.recv_from_addr.packed)
            if self._logger: self._logger.debug(f"to_bytes:recv_from_addr: out={out}")

        # Receive from port
        if self.recv_from_port is not None:
            out[0] |= self.RECEIVE_FROM_SOURCE_PORT_POSITION
            out.extend( self.recv_from_port.to_bytes(2,"big") )
            if self._logger: self._logger.debug(f"to_bytes:recv_from_port: out={out}")
        
        # make it immutable and return
        return bytes(out)

    # update an exisitng QuicNetworkPath from a received ReplyPath frame.
    def update_QuicNetworkPath_from_ReplyPath(self, qnp: QuicNetworkPath) -> QuicNetworkPath:
        # source ip field
        if(self.fields_present & self.SOURCE_IP_POSITION):
            qnp.addr = [self.peer_real_addr.compressed, qnp.addr[1], qnp.addr[2], qnp.addr[3]]
        
        # source port field
        if(self.fields_present & self.SOURCE_PORT_POSITION):
            qnp.addr = [qnp.addr[0], self.peer_real_port, qnp.addr[2], qnp.addr[3]]
        
        # source connection id field
        if(self.fields_present & self.SOURCE_CONNECTION_ID_POSITION):
            qnp.peer_destination_id = self.peer_real_connection_id
        
        # send as ip field
        if(self.fields_present & self.REPLY_AS_SOURCE_IP_POSITION):
            if qnp.send_as is None:
                qnp.send_as = ['',0,0,0]
            qnp.send_as[0] = self.send_as_addr.compressed
        
        # send as port field
        if(self.fields_present & self.REPLY_AS_SOURCE_PORT_POSITION):
            if qnp.send_as is None:
                qnp.send_as = ['',0,0,0]
            qnp.send_as[1] = self.send_as_port

        # reply as source connection id field
        if(self.fields_present & self.REPLY_AS_SOURCE_CONNECTION_ID_POSITION):
            qnp.send_as_conn_id = self.send_as_source_connection_id

        # receive from address
        if(self.fields_present & self.RECEIVE_FROM_SOURCE_IP_POSITION):
            qnp.recv_from = [self.recv_from_addr, qnp.recv_from[1], qnp.recv_from[2], qnp.recv_from[3]]
        
        # receive from port
        if(self.fields_present & self.RECEIVE_FROM_SOURCE_PORT_POSITION):
            qnp.recv_from = [qnp.recv_from[0], self.recv_from_port, qnp.recv_from[2], qnp.recv_from[3]]
        
        return qnp

    # generates a ReplyPath to send to the peer. Values must be valid from the peer's perspective.
    # ie Prepare a ReplyPath for the server's perspective with data from the client's perspective.
    def prep_to_send_from_QuicNetworkPath(self, qnp: QuicNetworkPath, host_cid: Optional[QuicConnectionId]) -> Self:
        
        # Reset fields present byte
        self.fields_present = 0x00
        
        # Source IP/Port
        if qnp.self_addr is not None:
            # IP
            self.fields_present |= self.SOURCE_IP_POSITION
            self.peer_real_addr = IPv6Address(qnp.self_addr[0])
            # Port
            self.fields_present |= self.SOURCE_PORT_POSITION
            self.peer_real_port = qnp.self_addr[1]
        
        # Source Connection ID
        if host_cid is not None:
            self.fields_present |= self.SOURCE_CONNECTION_ID_POSITION
            self.peer_real_connection_id = host_cid
        
        # Reply As source IP/Port
        if qnp.recv_from is not None:
            # IP
            self.fields_present |= self.REPLY_AS_SOURCE_IP_POSITION
            self.send_as_addr = IPv6Address(qnp.recv_from[0])
            # Port
            self.fields_present |= self.REPLY_AS_SOURCE_PORT_POSITION
            self.send_as_port = qnp.recv_from[1]
        
        # Reply As source connection ID
        if qnp.recv_from_conn_id is not None:
            self.fields_present |= self.REPLY_AS_SOURCE_CONNECTION_ID_POSITION
            self.send_as_source_connection_id = qnp.recv_from_conn_id

        # Receive from IP/Port
        if qnp.send_as is not None:
            # IP
            self.fields_present |= self.RECEIVE_FROM_SOURCE_IP_POSITION
            self.recv_from_addr = IPv6Address(qnp.send_as[0])
            # Port
            self.fields_present |= self.RECEIVE_FROM_SOURCE_PORT_POSITION
            self.recv_from_port = qnp.send_as[1]
        
        return self

    def to_QuicNetworkPath(self, self_address: NetworkAddress|None = None) -> QuicNetworkPath:
        new_qnp = QuicNetworkPath(addr=[self.peer_real_addr.compressed, self.peer_real_port, 0, 0])
        new_qnp.self_addr = self_address
        return self.update_QuicNetworkPath_from_ReplyPath(new_qnp)


@dataclass
class ClientKey:
    algoithm_name: tls.CipherSuite
    algorithm_value: int
    key: bytes

    class UnsupportedCipher(TypeError):
        description = "Cipher algorithm encountered that is not supported in tls CipherSuite while generating ClientKey from bytes."

    # generate key length in bytes from alrorithm
    def key_length(self) -> int:
        return tls.CIPHER_KEY_LENGTHS[self.algorithm]

    def from_bytes(self, buf: bytes) -> Self:
        if buf[0:2] in set(i.value for i in tls.CipherSuite):
            self.algorithm_value = buf[0:2]
            for i in tls.CipherSuite:
                if i.value == self.algorithm_value:
                    self.algorithm = i
                    break
            self.key = bytes[2:2+tls.CIPHER_KEY_LENGTHS[self.algorithm]]
        else:
            raise CryptoError("Cipher algorithm encountered that is not supported in tls CipherSuite while generating ClientKey from bytes.")
        return self

    def to_bytes(self) -> bytes:
        ret = bytearray()
        ret.extend(self.algorithm_value)
        ret.extend(self.key)
        return bytes(ret)



END_STATES = frozenset(
    [
        QuicConnectionState.CLOSING,
        QuicConnectionState.DRAINING,
        QuicConnectionState.TERMINATED,
    ]
)


class QuicConnection:
    """
    A QUIC connection.
    
    The state machine is driven by three kinds of sources:
    
    - the API user requesting data to be send out (see :meth:`connect`,
      :meth:`reset_stream`, :meth:`send_ping`, :meth:`send_datagram_frame`
      and :meth:`send_stream_data`)
    - data being received from the network (see :meth:`receive_datagram`)
    - a timer firing (see :meth:`handle_timer`)
    
    :param configuration: The QUIC configuration to use.
    """
    
    def __init__(
        self,
        *,
        configuration: QuicConfiguration,
        original_destination_connection_id: Optional[bytes] = None,
        retry_source_connection_id: Optional[bytes] = None,
        session_ticket_fetcher: Optional[tls.SessionTicketFetcher] = None,
        session_ticket_handler: Optional[tls.SessionTicketHandler] = None,
        self_address: Optional[Tuple[str,int]]
    ) -> None:
        if configuration.is_client:
            assert (
                original_destination_connection_id is None
            ), "Cannot set original_destination_connection_id for a client"
            assert (
                retry_source_connection_id is None
            ), "Cannot set retry_source_connection_id for a client"
        else:
            assert (
                configuration.certificate is not None
            ), "SSL certificate is required for a server"
            assert (
                configuration.private_key is not None
            ), "SSL private key is required for a server"
            assert (
                original_destination_connection_id is not None
            ), "original_destination_connection_id is required for a server"
        
        # configuration
        self._configuration = configuration
        self._is_client = configuration.is_client
        
        self._ack_delay = K_GRANULARITY
        # ConfidentialQUIC New
        self._client_key: Optional[ClientKey] = None
        #####
        self._close_at: Optional[float] = None
        self._close_event: Optional[events.ConnectionTerminated] = None
        self._connect_called = False
        self._cryptos: Dict[tls.Epoch, CryptoPair] = {}
        self._crypto_buffers: Dict[tls.Epoch, Buffer] = {}
        self._crypto_retransmitted = False
        self._crypto_streams: Dict[tls.Epoch, QuicStream] = {}
        self._events: Deque[events.QuicEvent] = deque()
        self._handshake_complete = False
        self._handshake_confirmed = False
        self._host_cids = [
            QuicConnectionId(
                cid=os.urandom(configuration.connection_id_length),
                sequence_number=0,
                stateless_reset_token=os.urandom(16) if not self._is_client else None,
                was_sent=True,
            )
        ]
        self.host_cid = self._host_cids[0].cid
        self._host_cid_seq = 1
        # ConfidentialQUIC new
        self._initial_asymmetric_padding = OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None,
        )
        ###
        self._local_ack_delay_exponent = 3
        self._local_active_connection_id_limit = 8
        self._local_initial_source_connection_id = self._host_cids[0].cid
        self._local_max_data = Limit(
            frame_type=QuicFrameType.MAX_DATA,
            name="max_data",
            value=configuration.max_data,
        )
        self._local_max_stream_data_bidi_local = configuration.max_stream_data
        self._local_max_stream_data_bidi_remote = configuration.max_stream_data
        self._local_max_stream_data_uni = configuration.max_stream_data
        self._local_max_streams_bidi = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_BIDI,
            name="max_streams_bidi",
            value=128,
        )
        self._local_max_streams_uni = Limit(
            frame_type=QuicFrameType.MAX_STREAMS_UNI, name="max_streams_uni", value=128
        )
        self._loss_at: Optional[float] = None
        self._network_paths: List[QuicNetworkPath] = []
        self._pacing_at: Optional[float] = None
        self._packet_number = 0
        self._parameters_received = False
        self._peer_cid = QuicConnectionId(
            cid=os.urandom(configuration.connection_id_length), sequence_number=None
        )
        self._peer_cid_available: List[QuicConnectionId] = []
        self._peer_cid_sequence_numbers: Set[int] = set([0])
        self._peer_token = b""
        self._quic_logger: Optional[QuicLoggerTrace] = None
        self._remote_ack_delay_exponent = 3
        self._remote_active_connection_id_limit = 2
        self._remote_initial_source_connection_id: Optional[bytes] = None
        self._remote_max_idle_timeout = 0.0  # seconds
        self._remote_max_data = 0
        self._remote_max_data_used = 0
        self._remote_max_datagram_frame_size: Optional[int] = None
        self._remote_max_stream_data_bidi_local = 0
        self._remote_max_stream_data_bidi_remote = 0
        self._remote_max_stream_data_uni = 0
        self._remote_max_streams_bidi = 0
        self._remote_max_streams_uni = 0
        # ConfidentialQUIC New
        self._reply_path_send: Optional[ReplyPathV2] = None # Sent to peer
        self._reply_path_receive: Optional[ReplyPathV2] = None # Received from peer
        #####
        self._retry_count = 0
        self._retry_source_connection_id = retry_source_connection_id
        # ConfidentialQUIC New
        # TODO: can't decide if this should be stored in each network path (maybe the server has multiple IP addresses?)
        # or if it should be global to the connection and an event detected when the OS tells us our IP changed.
        self.self_address: Tuple[IPv6Address|IPv4Address,int] = (ip_address(self_address[0]),self_address[1])
        #####
        self._spaces: Dict[tls.Epoch, QuicPacketSpace] = {}
        self._spin_bit = False
        self._spin_highest_pn = 0
        self._state = QuicConnectionState.FIRSTFLIGHT
        self._streams: Dict[int, QuicStream] = {}
        self._streams_blocked_bidi: List[QuicStream] = []
        self._streams_blocked_uni: List[QuicStream] = []
        self._streams_finished: Set[int] = set()
        # ConfidentialQUIC New
        self._tls_cert_public_key: Optional[CERTIFICATE_PUBLIC_KEY_TYPES]
        if configuration.tlsa_certificate:
            self._tls_cert_public_key = configuration.tlsa_certificate.public_key()
        else:
            self._tls_cert_public_key = None
        print(f"self.tls_cert_public_key: {self._tls_cert_public_key}", file=stderr)
        #####
        self._version: Optional[int] = None
        self._version_negotiation_count = 0
        
        if self._is_client:
            self._original_destination_connection_id = self._peer_cid.cid
        else:
            self._original_destination_connection_id = (
                original_destination_connection_id
            )
        
        # logging
        self._logger = QuicConnectionAdapter(
            logger, {"id": dump_cid(self._original_destination_connection_id)}
        )
        self._logger.setLevel(logging.DEBUG)
        if configuration.quic_logger:
            self._quic_logger = configuration.quic_logger.start_trace(
                is_client=configuration.is_client,
                odcid=self._original_destination_connection_id,
            )
        
        # loss recovery
        self._loss = QuicPacketRecovery(
            initial_rtt=configuration.initial_rtt,
            peer_completed_address_validation=not self._is_client,
            quic_logger=self._quic_logger,
            send_probe=self._send_probe,
            logger=self._logger,
        )
        
        # things to send
        self._close_pending = False
        self._datagrams_pending: Deque[bytes] = deque()
        self._handshake_done_pending = False
        self._ping_pending: List[int] = []
        self._probe_pending = False
        self._retire_connection_ids: List[int] = []
        self._streams_blocked_pending = False
        
        # callbacks
        self._session_ticket_fetcher = session_ticket_fetcher
        self._session_ticket_handler = session_ticket_handler
        
        # frame handlers
        self.__frame_handlers = {
            0x00: (self._handle_padding_frame, EPOCHS("IH01")),
            0x01: (self._handle_ping_frame, EPOCHS("IH01")),
            0x02: (self._handle_ack_frame, EPOCHS("IH1")),
            0x03: (self._handle_ack_frame, EPOCHS("IH1")),
            0x04: (self._handle_reset_stream_frame, EPOCHS("01")),
            0x05: (self._handle_stop_sending_frame, EPOCHS("01")),
            0x06: (self._handle_crypto_frame, EPOCHS("IH1")),
            0x07: (self._handle_new_token_frame, EPOCHS("1")),
            0x08: (self._handle_stream_frame, EPOCHS("01")),
            0x09: (self._handle_stream_frame, EPOCHS("01")),
            0x0A: (self._handle_stream_frame, EPOCHS("01")),
            0x0B: (self._handle_stream_frame, EPOCHS("01")),
            0x0C: (self._handle_stream_frame, EPOCHS("01")),
            0x0D: (self._handle_stream_frame, EPOCHS("01")),
            0x0E: (self._handle_stream_frame, EPOCHS("01")),
            0x0F: (self._handle_stream_frame, EPOCHS("01")),
            0x10: (self._handle_max_data_frame, EPOCHS("01")),
            0x11: (self._handle_max_stream_data_frame, EPOCHS("01")),
            0x12: (self._handle_max_streams_bidi_frame, EPOCHS("01")),
            0x13: (self._handle_max_streams_uni_frame, EPOCHS("01")),
            0x14: (self._handle_data_blocked_frame, EPOCHS("01")),
            0x15: (self._handle_stream_data_blocked_frame, EPOCHS("01")),
            0x16: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x17: (self._handle_streams_blocked_frame, EPOCHS("01")),
            0x18: (self._handle_new_connection_id_frame, EPOCHS("01")),
            0x19: (self._handle_retire_connection_id_frame, EPOCHS("01")),
            0x1A: (self._handle_path_challenge_frame, EPOCHS("01")),
            0x1B: (self._handle_path_response_frame, EPOCHS("01")),
            0x1C: (self._handle_connection_close_frame, EPOCHS("IH01")),
            0x1D: (self._handle_connection_close_frame, EPOCHS("01")),
            0x1E: (self._handle_handshake_done_frame, EPOCHS("1")),
            0x30: (self._handle_datagram_frame, EPOCHS("01")),
            0x31: (self._handle_datagram_frame, EPOCHS("01")),
            # ConfidentialQUIC new
            0x20: (self._handle_reply_path_frame, EPOCHS("I")), #TODO: EPOCHS
            0x21: (self._handle_client_key_frame, EPOCHS("I01")), #TODO: EPOCHS
        }

    @property
    def configuration(self) -> QuicConfiguration:
        return self._configuration

    @property
    def original_destination_connection_id(self) -> bytes:
        return self._original_destination_connection_id

    def change_connection_id(self) -> None:
        """
        Switch to the next available connection ID and retire
        the previous one.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.
        """
        if self._peer_cid_available:
            # retire previous CID
            self._retire_peer_cid(self._peer_cid)

            # assign new CID
            self._consume_peer_cid()

    def close(
        self,
        error_code: int = QuicErrorCode.NO_ERROR,
        frame_type: Optional[int] = None,
        reason_phrase: str = "",
    ) -> None:
        """
        Close the connection.

        :param error_code: An error code indicating why the connection is
                           being closed.
        :param reason_phrase: A human-readable explanation of why the
                              connection is being closed.
        """
        if self._close_event is None and self._state not in END_STATES:
            self._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._close_pending = True
    
    def connect(self, addr: NetworkAddress, now: float, self_addr: NetworkAddress|None, send_as: NetworkAddress|None = None, recv_from: NetworkAddress|None = None) -> None:
        """
        Initiate the TLS handshake.
        
        This method can only be called for clients and a single time.
        
        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.
        
        :param addr: The network address of the remote peer.
        :param now: The current time.
        """
        assert (
            self._is_client and not self._connect_called
        ), "connect() can only be called for clients and a single time"
        self._connect_called = True
        
        self._network_paths = [QuicNetworkPath( addr,
                                                is_validated=True,  # validated bc we are the client
                                                self_addr=self_addr,
                                                send_as=send_as,
                                                recv_from=recv_from
                                            )] # addr is destination address
        self._version = self._configuration.supported_versions[0]
        if send_as is not None or recv_from is not None:
            self._version = QuicProtocolVersion.CONFQ_1
        self._connect(now=now)
    
    # NOTE: Encryption of the output happens in this call.
    def datagrams_to_send(self, now: float) -> List[Tuple[bytes, QuicNetworkPath]]:
        """
        Return a list of `(data, addr)` tuples of datagrams which need to be
        sent, and the network address to which they need to be sent.

        After calling this method call :meth:`get_timer` to know when the next
        timer needs to be set.

        :param now: The current time.
        """
        network_path = self._network_paths[0]

        if self._state in END_STATES:
            self._logger.debug("connection::datagrams_to_send returning 0 datagrams")
            return []

        # build datagrams
        builder = QuicPacketBuilder(
            host_cid=self.host_cid,
            is_client=self._is_client,
            packet_number=self._packet_number,
            peer_cid=self._peer_cid.cid,
            peer_token=self._peer_token,
            quic_logger=self._quic_logger,
            spin_bit=self._spin_bit,
            version=self._version,
        )
        if self._close_pending:
            epoch_packet_types = []
            if not self._handshake_confirmed:
                epoch_packet_types += [
                    (tls.Epoch.INITIAL, PACKET_TYPE_INITIAL),
                    (tls.Epoch.HANDSHAKE, PACKET_TYPE_HANDSHAKE),
                ]
            epoch_packet_types.append((tls.Epoch.ONE_RTT, PACKET_TYPE_ONE_RTT))
            for epoch, packet_type in epoch_packet_types:
                crypto = self._cryptos[epoch]
                if crypto.send.is_valid():
                    builder.start_packet(packet_type, crypto)
                    self._write_connection_close_frame(
                        builder=builder,
                        epoch=epoch,
                        error_code=self._close_event.error_code,
                        frame_type=self._close_event.frame_type,
                        reason_phrase=self._close_event.reason_phrase,
                    )
            self._logger.info(
                "Connection close sent (code 0x%X, reason %s)",
                self._close_event.error_code,
                self._close_event.reason_phrase,
            )
            self._close_pending = False
            self._close_begin(is_initiator=True, now=now)
        else:
            # congestion control
            builder.max_flight_bytes = (
                self._loss.congestion_window - self._loss.bytes_in_flight
            )
            if self._probe_pending and builder.max_flight_bytes < PACKET_MAX_SIZE:
                builder.max_flight_bytes = PACKET_MAX_SIZE

            # limit data on un-validated network paths
            if not network_path.is_validated:
                builder.max_total_bytes = (
                    network_path.bytes_received * 3 - network_path.bytes_sent
                )

            try:
                if not self._handshake_confirmed:
                    for epoch in [tls.Epoch.INITIAL, tls.Epoch.HANDSHAKE]:
                        self._write_handshake(builder, epoch, now)
                self._write_application(builder, network_path, now)
            except QuicPacketBuilderStop:
                pass
        
        datagrams, packets = builder.flush() # The encryption happens here

        if datagrams:
            self._packet_number = builder.packet_number

            # register packets
            sent_handshake = False
            for packet in packets:
                packet.sent_time = now
                self._loss.on_packet_sent(
                    packet=packet, space=self._spaces[packet.epoch]
                )
                if packet.epoch == tls.Epoch.HANDSHAKE:
                    sent_handshake = True

                # log packet
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_sent",
                        data={
                            "frames": packet.quic_logger_frames,
                            "header": {
                                "packet_number": packet.packet_number,
                                "packet_type": self._quic_logger.packet_type(
                                    packet.packet_type
                                ),
                                "scid": dump_cid(self.host_cid)
                                if is_long_header(packet.packet_type)
                                else "",
                                "dcid": dump_cid(self._peer_cid.cid),
                            },
                            "raw": {"length": packet.sent_bytes},
                        },
                    )

            # check if we can discard initial keys
            if sent_handshake and self._is_client:
                self._discard_epoch(tls.Epoch.INITIAL)

        # return datagrams to send and the destination network address
        ret = []
        for datagram in datagrams:
            payload_length = len(datagram)
            network_path.bytes_sent += payload_length
            ret.append((datagram, network_path))

            if self._quic_logger is not None:
                self._quic_logger.log_event(
                    category="transport",
                    event="datagrams_sent",
                    data={
                        "count": 1,
                        "raw": [
                            {
                                "length": UDP_HEADER_SIZE + payload_length,
                                "payload_length": payload_length,
                            }
                        ],
                    },
                )
        self._logger.debug(f"connection::datagrams_to_send returning {len(ret)} datagrams")
        return ret

    def get_next_available_stream_id(self, is_unidirectional=False) -> int:
        """
        Return the stream ID for the next stream created by this endpoint.
        """
        stream_id = (int(is_unidirectional) << 1) | int(not self._is_client)
        while stream_id in self._streams or stream_id in self._streams_finished:
            stream_id += 4
        return stream_id

    def get_timer(self) -> Optional[float]:
        """
        Return the time at which the timer should fire or None if no timer is needed.
        """
        timer_at = self._close_at
        if self._state not in END_STATES:
            # ack timer
            for space in self._loss.spaces:
                if space.ack_at is not None and space.ack_at < timer_at:
                    timer_at = space.ack_at

            # loss detection timer
            self._loss_at = self._loss.get_loss_detection_time()
            if self._loss_at is not None and self._loss_at < timer_at:
                timer_at = self._loss_at

            # pacing timer
            if self._pacing_at is not None and self._pacing_at < timer_at:
                timer_at = self._pacing_at

        return timer_at

    def handle_timer(self, now: float) -> None:
        """
        Handle the timer.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.

        :param now: The current time.
        """
        # end of closing period or idle timeout
        if now >= self._close_at:
            if self._close_event is None:
                self._close_event = events.ConnectionTerminated(
                    error_code=QuicErrorCode.INTERNAL_ERROR,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Idle timeout",
                )
            self._close_end()
            return

        # loss detection timeout
        if self._loss_at is not None and now >= self._loss_at:
            self._logger.debug("Loss detection triggered")
            self._loss.on_loss_detection_timeout(now=now)

    def next_event(self) -> Optional[events.QuicEvent]:
        """
        Retrieve the next event from the event buffer.

        Returns `None` if there are no buffered events.
        """
        try:
            return self._events.popleft()
        except IndexError:
            return None

    def receive_datagram(self, data: bytes, addr: NetworkAddress, now: float) -> None:
        """
        Handle an incoming datagram.

        After calling this method call :meth:`datagrams_to_send` to retrieve data
        which needs to be sent.

        :param data: The datagram which was received.
        :param addr: The network address from which the datagram was received.
        :param now: The current time.
        """
        # stop handling packets when closing
        if self._state in END_STATES:
            return

        # log datagram
        if self._quic_logger is not None:
            payload_length = len(data)
            self._quic_logger.log_event(
                category="transport",
                event="datagrams_received",
                data={
                    "count": 1,
                    "raw": [
                        {
                            "length": UDP_HEADER_SIZE + payload_length,
                            "payload_length": payload_length,
                        }
                    ],
                },
            )

        # for servers, arm the idle timeout on the first datagram
        if self._close_at is None:
            self._close_at = now + self._configuration.idle_timeout

        # cycle through every packet in the datagram
        buf = Buffer(data=data)
        while not buf.eof():
            start_off = buf.tell()
            try:
                header = pull_quic_header(
                    buf, host_cid_length=self._configuration.connection_id_length
                )
            except ValueError:
                return

            # check destination CID matches
            destination_cid_seq: Optional[int] = None
            for connection_id in self._host_cids:
                if header.destination_cid == connection_id.cid:
                    destination_cid_seq = connection_id.sequence_number
                    break
            if self._is_client and destination_cid_seq is None:
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "unknown_connection_id"},
                    )
                return

            # check protocol version
            if (
                self._is_client
                and self._state == QuicConnectionState.FIRSTFLIGHT
                and header.version == QuicProtocolVersion.NEGOTIATION
                and not self._version_negotiation_count
            ):
                # version negotiation
                versions = []
                while not buf.eof():
                    versions.append(buf.pull_uint32())
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_received",
                        data={
                            "frames": [],
                            "header": {
                                "packet_type": "version_negotiation",
                                "scid": dump_cid(header.source_cid),
                                "dcid": dump_cid(header.destination_cid),
                            },
                            "raw": {"length": buf.tell() - start_off},
                        },
                    )
                if self._version in versions:
                    self._logger.warning(
                        "Version negotiation packet contains %s" % self._version
                    )
                    return
                common = [
                    x for x in self._configuration.supported_versions if x in versions
                ]
                if not common:
                    self._logger.error("Could not find a common protocol version")
                    self._close_event = events.ConnectionTerminated(
                        error_code=QuicErrorCode.INTERNAL_ERROR,
                        frame_type=QuicFrameType.PADDING,
                        reason_phrase="Could not find a common protocol version",
                    )
                    self._close_end()
                    return
                self._packet_number = 0
                self._version = QuicProtocolVersion(common[0])
                self._version_negotiation_count += 1
                self._logger.info("Retrying with %s", self._version)
                self._connect(now=now)
                return
            elif (
                header.version is not None
                and header.version not in self._configuration.supported_versions
            ):
                # unsupported version
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "unsupported_version"},
                    )
                return

            # handle retry packet
            if header.packet_type == PACKET_TYPE_RETRY:
                if (
                    self._is_client
                    and not self._retry_count
                    and header.destination_cid == self.host_cid
                    and header.integrity_tag
                    == get_retry_integrity_tag(
                        buf.data_slice(
                            start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                        ),
                        self._peer_cid.cid,
                        version=header.version,
                    )
                ):
                    if self._quic_logger is not None:
                        self._quic_logger.log_event(
                            category="transport",
                            event="packet_received",
                            data={
                                "frames": [],
                                "header": {
                                    "packet_type": "retry",
                                    "scid": dump_cid(header.source_cid),
                                    "dcid": dump_cid(header.destination_cid),
                                },
                                "raw": {"length": buf.tell() - start_off},
                            },
                        )

                    self._peer_cid.cid = header.source_cid
                    self._peer_token = header.token
                    self._retry_count += 1
                    self._retry_source_connection_id = header.source_cid
                    self._logger.info(
                        "Retrying with token (%d bytes)" % len(header.token)
                    )
                    self._connect(now=now)
                else:
                    # unexpected or invalid retry packet
                    if self._quic_logger is not None:
                        self._quic_logger.log_event(
                            category="transport",
                            event="packet_dropped",
                            data={"trigger": "unexpected_packet"},
                        )
                return

            #network_path = self._find_network_path(addr)
            # Finds QuicNetworkPath based on recv_addr
            # NOTE: Creates path if it does not exist but will not add it to the list of paths
            self._logger.debug("connection:receive_datagram first network path check")
            network_path = self._find_conf_network_path(addr)

            # server initialization
            if not self._is_client and self._state == QuicConnectionState.FIRSTFLIGHT:
                self._logger.debug("Initializing server...")
                assert (
                    header.packet_type == PACKET_TYPE_INITIAL
                ), "first packet must be INITIAL"
                self._network_paths = [network_path]
                self._version = QuicProtocolVersion(header.version)
                self._initialize(header.destination_cid)
                self._logger.debug("...initialized")

            # determine crypto and packet space
            epoch = get_epoch(header.packet_type)
            crypto = self._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self._spaces[epoch]

            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = buf.tell() + header.rest_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                    data[start_off:end_off], encrypted_off, space.expected_packet_number
                )
                print(f"-AFTER INIT DECRYPTION-\nLENGTH OF HEADER:{len(plain_header)}\nLENGTH OF DATA:{len(plain_payload)}", file=stderr)
            except KeyUnavailableError as exc:
                self._logger.debug(exc)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "key_unavailable"},
                    )

                # if a client receives HANDSHAKE or 1-RTT packets before it has handshake keys,
                # it can assume that the server's INITIAL was lost
                if (
                    self._is_client
                    and epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
                    and not self._crypto_retransmitted
                ):
                    self._loss.reschedule_data(now=now)
                    self._crypto_retransmitted = True
                continue
            except CryptoError as exc:
                self._logger.debug(exc)
                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="transport",
                        event="packet_dropped",
                        data={"trigger": "payload_decrypt_error"},
                    )
                continue
            
            # ConfidentialQUIC Asymmetric decryption
            if (not self._is_client) and (header.packet_type == PACKET_TYPE_INITIAL):
                plain_payload = self.configuration.private_key.decrypt(plain_payload, padding=self._initial_asymmetric_padding)
                print(f"-AFTER ASYM DECRYPTION-\nLENGTH OF HEADER:{len(plain_header)}\nLENGTH OF DATA:{len(plain_payload)}", file=stderr)


            # check reserved bits
            if header.is_long_header:
                reserved_mask = 0x0C
            else:
                reserved_mask = 0x18
            if plain_header[0] & reserved_mask:
                self.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Reserved bits must be zero",
                )
                return

            # log packet
            quic_logger_frames: Optional[List[Dict]] = None
            if self._quic_logger is not None:
                quic_logger_frames = []
                self._quic_logger.log_event(
                    category="transport",
                    event="packet_received",
                    data={
                        "frames": quic_logger_frames,
                        "header": {
                            "packet_number": packet_number,
                            "packet_type": self._quic_logger.packet_type(
                                header.packet_type
                            ),
                            "dcid": dump_cid(header.destination_cid),
                            "scid": dump_cid(header.source_cid),
                        },
                        "raw": {"length": end_off - start_off},
                    },
                )

            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # discard initial keys and packet space
            if not self._is_client and epoch == tls.Epoch.HANDSHAKE:
                self._discard_epoch(tls.Epoch.INITIAL)

            # update state
            if self._peer_cid.sequence_number is None:
                self._peer_cid.cid = header.source_cid
                self._peer_cid.sequence_number = 0

            if self._state == QuicConnectionState.FIRSTFLIGHT:
                self._remote_initial_source_connection_id = header.source_cid
                self._set_state(QuicConnectionState.CONNECTED)

            # update spin bit
            if not header.is_long_header and packet_number > self._spin_highest_pn:
                spin_bit = get_spin_bit(plain_header[0])
                if self._is_client:
                    self._spin_bit = not spin_bit
                else:
                    self._spin_bit = spin_bit
                self._spin_highest_pn = packet_number

                if self._quic_logger is not None:
                    self._quic_logger.log_event(
                        category="connectivity",
                        event="spin_bit_updated",
                        data={"state": self._spin_bit},
                    )

            # handle payload
            context = QuicReceiveContext(
                epoch=epoch,
                host_cid=header.destination_cid,
                network_path=network_path,
                quic_logger_frames=quic_logger_frames,
                time=now,
            )
            try:
                print("connection:receive_datagram handling the payload", file=stderr)
                is_ack_eliciting, is_probing = self._payload_received(
                    context, plain_payload
                )
            except QuicConnectionError as exc:
                self._logger.warning(exc)
                self.close(
                    error_code=exc.error_code,
                    frame_type=exc.frame_type,
                    reason_phrase=exc.reason_phrase,
                )
            if self._state in END_STATES or self._close_pending:
                return

            # re-gather network_path. It could have be updated from init packets during _payload_received
            if epoch == tls.Epoch.INITIAL:
                self._logger.debug("connection:receive_datagram network_path second check")
                network_path = self._find_conf_network_path(addr)

            # update idle timeout
            self._close_at = now + self._configuration.idle_timeout

            # handle migration
            if (
                not self._is_client
                and context.host_cid != self.host_cid
                and epoch == tls.Epoch.ONE_RTT
            ):
                self._logger.debug(
                    "Peer switching to CID %s (%d)",
                    dump_cid(context.host_cid),
                    destination_cid_seq,
                )
                self.host_cid = context.host_cid
                self.change_connection_id()

            # update network path
            if not network_path.is_validated and epoch == tls.Epoch.HANDSHAKE:
                self._logger.debug(
                    "Network path %s validated by handshake", network_path.addr
                )
                network_path.is_validated = True
            network_path.bytes_received += end_off - start_off
            if network_path not in self._network_paths:
                self._network_paths.append(network_path)
            idx = self._network_paths.index(network_path)
            if idx and not is_probing and packet_number > space.largest_received_packet:
                self._logger.debug("Network path %s promoted", network_path.addr)
                self._network_paths.pop(idx)
                self._network_paths.insert(0, network_path)

            # record packet as received
            if not space.discarded:
                if packet_number > space.largest_received_packet:
                    space.largest_received_packet = packet_number
                    space.largest_received_time = now
                space.ack_queue.add(packet_number)
                if is_ack_eliciting and space.ack_at is None:
                    space.ack_at = now + self._ack_delay

    def request_key_update(self) -> None:
        """
        Request an update of the encryption keys.
        """
        assert self._handshake_complete, "cannot change key before handshake completes"
        self._cryptos[tls.Epoch.ONE_RTT].update_key()

    def reset_stream(self, stream_id: int, error_code: int) -> None:
        """
        Abruptly terminate the sending part of a stream.

        :param stream_id: The stream's ID.
        :param error_code: An error code indicating why the stream is being reset.
        """
        stream = self._get_or_create_stream_for_send(stream_id)
        stream.sender.reset(error_code)

    def send_ping(self, uid: int) -> None:
        """
        Send a PING frame to the peer.

        :param uid: A unique ID for this PING.
        """
        self._ping_pending.append(uid)

    def send_datagram_frame(self, data: bytes) -> None:
        """
        Send a DATAGRAM frame.

        :param data: The data to be sent.
        """
        self._datagrams_pending.append(data)

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        """
        Send data on the specific stream.

        :param stream_id: The stream's ID.
        :param data: The data to be sent.
        :param end_stream: If set to `True`, the FIN bit will be set.
        """
        stream = self._get_or_create_stream_for_send(stream_id)
        stream.sender.write(data, end_stream=end_stream)

    def stop_stream(self, stream_id: int, error_code: int) -> None:
        """
        Request termination of the receiving part of a stream.

        :param stream_id: The stream's ID.
        :param error_code: An error code indicating why the stream is being stopped.
        """
        if not self._stream_can_receive(stream_id):
            raise ValueError(
                "Cannot stop receiving on a local-initiated unidirectional stream"
            )

        stream = self._streams.get(stream_id, None)
        if stream is None:
            raise ValueError("Cannot stop receiving on an unknown stream")

        stream.receiver.stop(error_code)

    # Private

    def _alpn_handler(self, alpn_protocol: str) -> None:
        """
        Callback which is invoked by the TLS engine when ALPN negotiation completes.
        """
        self._events.append(events.ProtocolNegotiated(alpn_protocol=alpn_protocol))

    def _assert_stream_can_receive(self, frame_type: int, stream_id: int) -> None:
        """
        Check the specified stream can receive data or raises a QuicConnectionError.
        """
        if not self._stream_can_receive(stream_id):
            raise QuicConnectionError(
                error_code=QuicErrorCode.STREAM_STATE_ERROR,
                frame_type=frame_type,
                reason_phrase="Stream is send-only",
            )

    def _assert_stream_can_send(self, frame_type: int, stream_id: int) -> None:
        """
        Check the specified stream can send data or raises a QuicConnectionError.
        """
        if not self._stream_can_send(stream_id):
            raise QuicConnectionError(
                error_code=QuicErrorCode.STREAM_STATE_ERROR,
                frame_type=frame_type,
                reason_phrase="Stream is receive-only",
            )

    def _consume_peer_cid(self) -> None:
        """
        Update the destination connection ID by taking the next
        available connection ID provided by the peer.
        """

        self._peer_cid = self._peer_cid_available.pop(0)
        self._logger.debug(
            "Switching to CID %s (%d)",
            dump_cid(self._peer_cid.cid),
            self._peer_cid.sequence_number,
        )

    def _close_begin(self, is_initiator: bool, now: float) -> None:
        """
        Begin the close procedure.
        """
        self._close_at = now + 3 * self._loss.get_probe_timeout()
        if is_initiator:
            self._set_state(QuicConnectionState.CLOSING)
        else:
            self._set_state(QuicConnectionState.DRAINING)

    def _close_end(self) -> None:
        """
        End the close procedure.
        """
        self._close_at = None
        for epoch in self._spaces.keys():
            self._discard_epoch(epoch)
        self._events.append(self._close_event)
        self._set_state(QuicConnectionState.TERMINATED)

        # signal log end
        if self._quic_logger is not None:
            self._configuration.quic_logger.end_trace(self._quic_logger)
            self._quic_logger = None

    def _connect(self, now: float) -> None:
        """
        Start the client handshake.
        """
        assert self._is_client

        self._close_at = now + self._configuration.idle_timeout
        self._initialize(self._peer_cid.cid)    # Local TLS init. Sets up streams for each Epoch.
        # Start TLS handshake
        self.tls.handle_message(b"", self._crypto_buffers)  # serializes/moves ClientHello into cryptoBuffer[Epoch.Initial]
        self._push_crypto_data()    # sets the crypto data for init packet to be sent
        self._push_reply_path()     # sets the ReplyPathv2 frame to be sent in the Initial Packet
        self._push_client_key()     # sets the 

    def _discard_epoch(self, epoch: tls.Epoch) -> None:
        if not self._spaces[epoch].discarded:
            self._logger.debug("Discarding epoch %s", epoch)
            self._cryptos[epoch].teardown()
            self._loss.discard_space(self._spaces[epoch])
            self._spaces[epoch].discarded = True

    def _find_network_path(self, addr: NetworkAddress) -> QuicNetworkPath:
        # check existing network paths
        for idx, network_path in enumerate(self._network_paths):
            if network_path.addr == addr:
                return network_path

        # new network path
        network_path = QuicNetworkPath(addr)
        self._logger.debug("Network path %s discovered", network_path.addr)
        return network_path

    def _find_conf_network_path(self, addr: NetworkAddress) -> QuicNetworkPath:
        self._logger.debug("connection:find_conf_network_path")
        # check existing network paths
        for idx, network_path in enumerate(self._network_paths):
            if [IPv6Address(network_path.recv_from[0]),network_path.recv_from[1]] == [IPv6Address(addr[0]), addr[1]]:
                self._logger.debug(f"Found existing network path: {network_path}")
                return network_path

        # new network path
        network_path = QuicNetworkPath(addr, is_validated=self._is_client)
        network_path.self_addr = (self.self_address[0].exploded,self.self_address[1], 0, 0)
        self._logger.debug(f"Network path {network_path} discovered")
        return network_path

    def _get_or_create_stream(self, frame_type: int, stream_id: int) -> QuicStream:
        """
        Get or create a stream in response to a received frame.
        """
        if stream_id in self._streams_finished:
            # the stream was created, but its state was since discarded
            raise StreamFinishedError

        stream = self._streams.get(stream_id, None)
        if stream is None:
            # check initiator
            if stream_is_client_initiated(stream_id) == self._is_client:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.STREAM_STATE_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Wrong stream initiator",
                )

            # determine limits
            if stream_is_unidirectional(stream_id):
                max_stream_data_local = self._local_max_stream_data_uni
                max_stream_data_remote = 0
                max_streams = self._local_max_streams_uni
            else:
                max_stream_data_local = self._local_max_stream_data_bidi_remote
                max_stream_data_remote = self._remote_max_stream_data_bidi_local
                max_streams = self._local_max_streams_bidi

            # check max streams
            stream_count = (stream_id // 4) + 1
            if stream_count > max_streams.value:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.STREAM_LIMIT_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Too many streams open",
                )
            elif stream_count > max_streams.used:
                max_streams.used = stream_count

            # create stream
            self._logger.debug("Stream %d created by peer" % stream_id)
            stream = self._streams[stream_id] = QuicStream(
                stream_id=stream_id,
                max_stream_data_local=max_stream_data_local,
                max_stream_data_remote=max_stream_data_remote,
                writable=not stream_is_unidirectional(stream_id),
            )
        return stream

    def _get_or_create_stream_for_send(self, stream_id: int) -> QuicStream:
        """
        Get or create a QUIC stream in order to send data to the peer.

        This always occurs as a result of an API call.
        """
        if not self._stream_can_send(stream_id):
            raise ValueError("Cannot send data on peer-initiated unidirectional stream")

        stream = self._streams.get(stream_id, None)
        if stream is None:
            # check initiator
            if stream_is_client_initiated(stream_id) != self._is_client:
                raise ValueError("Cannot send data on unknown peer-initiated stream")

            # determine limits
            if stream_is_unidirectional(stream_id):
                max_stream_data_local = 0
                max_stream_data_remote = self._remote_max_stream_data_uni
                max_streams = self._remote_max_streams_uni
                streams_blocked = self._streams_blocked_uni
            else:
                max_stream_data_local = self._local_max_stream_data_bidi_local
                max_stream_data_remote = self._remote_max_stream_data_bidi_remote
                max_streams = self._remote_max_streams_bidi
                streams_blocked = self._streams_blocked_bidi

            # create stream
            stream = self._streams[stream_id] = QuicStream(
                stream_id=stream_id,
                max_stream_data_local=max_stream_data_local,
                max_stream_data_remote=max_stream_data_remote,
                readable=not stream_is_unidirectional(stream_id),
            )

            # mark stream as blocked if needed
            if stream_id // 4 >= max_streams:
                stream.is_blocked = True
                streams_blocked.append(stream)
                self._streams_blocked_pending = True
        return stream

    def _handle_session_ticket(self, session_ticket: tls.SessionTicket) -> None:
        if (
            session_ticket.max_early_data_size is not None
            and session_ticket.max_early_data_size != MAX_EARLY_DATA
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.CRYPTO,
                reason_phrase="Invalid max_early_data value %s"
                % session_ticket.max_early_data_size,
            )
        self._session_ticket_handler(session_ticket)

    def _initialize(self, peer_cid: bytes) -> None:
        # TLS
        self.tls = tls.Context(
            alpn_protocols=self._configuration.alpn_protocols,
            cadata=self._configuration.cadata,
            cafile=self._configuration.cafile,
            capath=self._configuration.capath,
            cipher_suites=self.configuration.cipher_suites,
            is_client=self._is_client,
            logger=self._logger,
            max_early_data=None if self._is_client else MAX_EARLY_DATA,
            server_name=self._configuration.server_name,
            verify_mode=self._configuration.verify_mode,
        )
        self.tls.certificate = self._configuration.certificate
        self.tls.certificate_chain = self._configuration.certificate_chain
        self.tls.certificate_private_key = self._configuration.private_key
        self.tls.handshake_extensions = [
            (
                get_transport_parameters_extension(self._version),
                self._serialize_transport_parameters(),
            )
        ]

        # TLS session resumption
        session_ticket = self._configuration.session_ticket
        if (
            self._is_client
            and session_ticket is not None
            and session_ticket.is_valid
            and session_ticket.server_name == self._configuration.server_name
        ):
            self.tls.session_ticket = self._configuration.session_ticket

            # parse saved QUIC transport parameters - for 0-RTT
            if session_ticket.max_early_data_size == MAX_EARLY_DATA:
                for ext_type, ext_data in session_ticket.other_extensions:
                    if ext_type == get_transport_parameters_extension(self._version):
                        self._parse_transport_parameters(
                            ext_data, from_session_ticket=True
                        )
                        break

        # TLS callbacks
        self.tls.alpn_cb = self._alpn_handler
        if self._session_ticket_fetcher is not None:
            self.tls.get_session_ticket_cb = self._session_ticket_fetcher
        if self._session_ticket_handler is not None:
            self.tls.new_session_ticket_cb = self._handle_session_ticket
        self.tls.update_traffic_key_cb = self._update_traffic_key

        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            secret_names = [
                "server_%s_secret" % epoch_name,
                "client_%s_secret" % epoch_name,
            ]
            recv_secret_name = secret_names[not self._is_client]
            send_secret_name = secret_names[self._is_client]
            return CryptoPair(
                recv_setup_cb=partial(self._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self._log_key_retired, send_secret_name),
            )

        # CryptoPair is where all our encryption/decryption happens
        self._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.INITIAL,
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self._spaces = {
            tls.Epoch.INITIAL: QuicPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicPacketSpace(),
            tls.Epoch.ONE_RTT: QuicPacketSpace(),
        }

        self._cryptos[tls.Epoch.INITIAL].setup_initial(
            cid=peer_cid, is_client=self._is_client, version=self._version
        )

        self._loss.spaces = list(self._spaces.values())

    def _handle_ack_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ACK frame.
        """
        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._remote_ack_delay_exponent) / 1000000

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_ack_frame(ack_rangeset, ack_delay)
            )

        # check whether peer completed address validation
        if not self._loss.peer_completed_address_validation and context.epoch in (
            tls.Epoch.HANDSHAKE,
            tls.Epoch.ONE_RTT,
        ):
            self._loss.peer_completed_address_validation = True

        self._loss.on_ack_received(
            space=self._spaces[context.epoch],
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
        )

    def _handle_connection_close_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CONNECTION_CLOSE frame.
        """
        error_code = buf.pull_uint_var()
        if frame_type == QuicFrameType.TRANSPORT_CLOSE:
            frame_type = buf.pull_uint_var()
        else:
            frame_type = None
        reason_length = buf.pull_uint_var()
        try:
            reason_phrase = buf.pull_bytes(reason_length).decode("utf8")
        except UnicodeDecodeError:
            reason_phrase = ""

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_close_frame(
                    error_code=error_code,
                    frame_type=frame_type,
                    reason_phrase=reason_phrase,
                )
            )

        self._logger.info(
            "Connection close received (code 0x%X, reason %s)",
            error_code,
            reason_phrase,
        )
        if self._close_event is None:
            self._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._close_begin(is_initiator=False, now=context.time)

    def _handle_crypto_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CRYPTO frame.
        """
        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(offset=offset, data=buf.pull_bytes(length))

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_crypto_frame(frame)
            )

        stream = self._crypto_streams[context.epoch]
        event = stream.receiver.handle_frame(frame)
        self._logger.debug(f"event received from handle_frame length= {len(event.data) if event else None}")
        if event is not None:
            # pass data to TLS layer
            try:
                self.tls.handle_message(event.data, self._crypto_buffers)
                self._push_crypto_data()
            except tls.Alert as exc:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.CRYPTO_ERROR + int(exc.description),
                    frame_type=frame_type,
                    reason_phrase=str(exc),
                )

            # parse transport parameters
            if (
                not self._parameters_received
                and self.tls.received_extensions is not None
            ):
                for ext_type, ext_data in self.tls.received_extensions:
                    if ext_type == get_transport_parameters_extension(self._version):
                        self._parse_transport_parameters(ext_data)
                        self._parameters_received = True
                        break
                if not self._parameters_received:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.CRYPTO_ERROR
                        + tls.AlertDescription.missing_extension,
                        frame_type=frame_type,
                        reason_phrase="No QUIC transport parameters received",
                    )

            # update current epoch
            if not self._handshake_complete and self.tls.state in [
                tls.State.CLIENT_POST_HANDSHAKE,
                tls.State.SERVER_POST_HANDSHAKE,
            ]:
                self._handshake_complete = True

                # for servers, the handshake is now confirmed
                if not self._is_client:
                    self._discard_epoch(tls.Epoch.HANDSHAKE)
                    self._handshake_confirmed = True
                    self._handshake_done_pending = True

                self._replenish_connection_ids()
                self._events.append(
                    events.HandshakeCompleted(
                        alpn_protocol=self.tls.alpn_negotiated,
                        early_data_accepted=self.tls.early_data_accepted,
                        session_resumed=self.tls.session_resumed,
                    )
                )
                self._unblock_streams(is_unidirectional=False)
                self._unblock_streams(is_unidirectional=True)
                self._logger.info(
                    "ALPN negotiated protocol %s", self.tls.alpn_negotiated
                )
        else:
            self._logger.info(
                "Duplicate CRYPTO data received for epoch %s", context.epoch
            )

            # if a server receives duplicate CRYPTO in an INITIAL packet,
            # it can assume the client did not receive the server's CRYPTO
            if (
                not self._is_client
                and context.epoch == tls.Epoch.INITIAL
                and not self._crypto_retransmitted
            ):
                self._loss.reschedule_data(now=context.time)
                self._crypto_retransmitted = True

    def _handle_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATA_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_data_blocked_frame(limit=limit)
            )

    def _handle_datagram_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATAGRAM frame.
        """
        start = buf.tell()
        if frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - start
        data = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_datagram_frame(length=length)
            )

        # check frame is allowed
        if (
            self._configuration.max_datagram_frame_size is None
            or buf.tell() - start >= self._configuration.max_datagram_frame_size
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Unexpected DATAGRAM frame",
            )

        self._events.append(events.DatagramFrameReceived(data=data))

    def _handle_handshake_done_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a HANDSHAKE_DONE frame.
        """
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_handshake_done_frame()
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send HANDSHAKE_DONE frames",
            )

        # for clients, the handshake is now confirmed
        if not self._handshake_confirmed:
            self._discard_epoch(tls.Epoch.HANDSHAKE)
            self._handshake_confirmed = True
            self._loss.peer_completed_address_validation = True

    def _handle_max_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_DATA frame.

        This adjusts the total amount of we can send to the peer.
        """
        max_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_data
                )
            )

        if max_data > self._remote_max_data:
            self._logger.debug("Remote max_data raised to %d", max_data)
            self._remote_max_data = max_data

    def _handle_max_stream_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAM_DATA frame.

        This adjusts the amount of data we can send on a specific stream.
        """
        stream_id = buf.pull_uint_var()
        max_stream_data = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_max_stream_data_frame(
                    maximum=max_stream_data, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        stream = self._get_or_create_stream(frame_type, stream_id)
        if max_stream_data > stream.max_stream_data_remote:
            self._logger.debug(
                "Stream %d remote max_stream_data raised to %d",
                stream_id,
                max_stream_data,
            )
            stream.max_stream_data_remote = max_stream_data

    def _handle_max_streams_bidi_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_BIDI frame.

        This raises number of bidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_bidi:
            self._logger.debug("Remote max_streams_bidi raised to %d", max_streams)
            self._remote_max_streams_bidi = max_streams
            self._unblock_streams(is_unidirectional=False)

    def _handle_max_streams_uni_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_UNI frame.

        This raises number of unidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_connection_limit_frame(
                    frame_type=frame_type, maximum=max_streams
                )
            )

        if max_streams > self._remote_max_streams_uni:
            self._logger.debug("Remote max_streams_uni raised to %d", max_streams)
            self._remote_max_streams_uni = max_streams
            self._unblock_streams(is_unidirectional=True)

    def _handle_new_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(STATELESS_RESET_TOKEN_SIZE)
        if not connection_id or len(connection_id) > CONNECTION_ID_MAX_SIZE:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Length must be greater than 0 and less than 20",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_connection_id_frame(
                    connection_id=connection_id,
                    retire_prior_to=retire_prior_to,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )

        # sanity check
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Retire Prior To is greater than Sequence Number",
            )

        # determine which CIDs to retire
        change_cid = False
        retire = list(
            filter(
                lambda c: c.sequence_number < retire_prior_to, self._peer_cid_available
            )
        )
        if self._peer_cid.sequence_number < retire_prior_to:
            change_cid = True
            retire.insert(0, self._peer_cid)

        # update available CIDs
        self._peer_cid_available = list(
            filter(
                lambda c: c.sequence_number >= retire_prior_to, self._peer_cid_available
            )
        )
        if sequence_number not in self._peer_cid_sequence_numbers:
            self._peer_cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            self._peer_cid_sequence_numbers.add(sequence_number)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._retire_peer_cid(quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._consume_peer_cid()

        # check number of active connection IDs, including the selected one
        if 1 + len(self._peer_cid_available) > self._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many active connection IDs",
            )

    def _handle_new_token_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_TOKEN frame.
        """
        length = buf.pull_uint_var()
        token = buf.pull_bytes(length)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_new_token_frame(token=token)
            )

        if not self._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send NEW_TOKEN frames",
            )

    def _handle_padding_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_padding_frame())

    def _handle_path_challenge_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_CHALLENGE frame.
        """
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_challenge_frame(data=data)
            )

        context.network_path.remote_challenge = data

    def _handle_path_response_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_RESPONSE frame.
        """
        data = buf.pull_bytes(8)

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_path_response_frame(data=data)
            )

        if data != context.network_path.local_challenge:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Response does not match challenge",
            )
        self._logger.debug(
            "Network path %s validated by challenge", context.network_path.addr
        )
        context.network_path.is_validated = True

    def _handle_ping_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PING frame.
        """
        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(self._quic_logger.encode_ping_frame())

    def _handle_reset_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RESET_STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()
        final_size = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_reset_stream_frame(
                    error_code=error_code, final_size=final_size, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if final_size > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, final_size - stream.receiver.highest_offset)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process reset
        self._logger.info(
            "Stream %d reset by peer (error code %d, final size %d)",
            stream_id,
            error_code,
            final_size,
        )
        try:
            event = stream.receiver.handle_reset(
                error_code=error_code, final_size=final_size
            )
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received

    def _handle_retire_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RETIRE_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_retire_connection_id_frame(sequence_number)
            )

        if sequence_number >= self._host_cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        for index, connection_id in enumerate(self._host_cids):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Cannot retire current connection ID",
                    )
                self._logger.debug(
                    "Peer retiring CID %s (%d)",
                    dump_cid(connection_id.cid),
                    connection_id.sequence_number,
                )
                del self._host_cids[index]
                self._events.append(
                    events.ConnectionIdRetired(connection_id=connection_id.cid)
                )
                break

        # issue a new connection ID
        self._replenish_connection_ids()

    def _handle_stop_sending_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STOP_SENDING frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()  # application error code

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stop_sending_frame(
                    error_code=error_code, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_send(frame_type, stream_id)

        # reset the stream
        stream = self._get_or_create_stream(frame_type, stream_id)
        stream.sender.reset(error_code=QuicErrorCode.NO_ERROR)

    def _handle_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        if frame_type & 4:
            offset = buf.pull_uint_var()
        else:
            offset = 0
        if frame_type & 2:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - buf.tell()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        frame = QuicStreamFrame(
            offset=offset, data=buf.pull_bytes(length), fin=bool(frame_type & 1)
        )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_frame(frame, stream_id=stream_id)
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._get_or_create_stream(frame_type, stream_id)
        if offset + length > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, offset + length - stream.receiver.highest_offset)
        if self._local_max_data.used + newly_received > self._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process data
        try:
            event = stream.receiver.handle_frame(frame)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._events.append(event)
        self._local_max_data.used += newly_received

    def _handle_stream_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM_DATA_BLOCKED frame.
        """
        stream_id = buf.pull_uint_var()
        limit = buf.pull_uint_var()

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_stream_data_blocked_frame(
                    limit=limit, stream_id=stream_id
                )
            )

        # check stream direction
        self._assert_stream_can_receive(frame_type, stream_id)

        self._get_or_create_stream(frame_type, stream_id)

    def _handle_streams_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAMS_BLOCKED frame.
        """
        limit = buf.pull_uint_var()
        if limit > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        # log frame
        if self._quic_logger is not None:
            context.quic_logger_frames.append(
                self._quic_logger.encode_streams_blocked_frame(
                    is_unidirectional=frame_type == QuicFrameType.STREAMS_BLOCKED_UNI,
                    limit=limit,
                )
            )

    def _handle_reply_path_frame(self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        # update network path
        if self._logger: self._logger.debug("_handle_reply_path_frame")

        peer_reply_path = ReplyPathV2(buf, logger=self._logger)
        self._reply_path_receive = peer_reply_path
        if self._logger:self._logger.debug(f"_handle_reply_path: path: {peer_reply_path}")

        # find the existing default to update with this ReplyPathv2 frame (if it exists)
        idx = None
        old_path = None
        for i, path in enumerate(self._network_paths):
            if (
                path.addr == path.recv_from # isn't confidential (default)
                and [IPv6Address(path.addr[0]), path.addr[1], 0, 0] == [peer_reply_path.recv_from_addr, peer_reply_path.recv_from_port, 0, 0] # who we received from is who the client told us to receive from
                or
                path.addr != path.recv_from # is confidential
            ):
                idx = i
                old_path = path
        
        # update
        if idx is not None:
            if self._logger: self._logger.info(f"Updating NetworkPath: {old_path} from \nnew PeerReplyPath: {peer_reply_path}")
            peer_reply_path.update_QuicNetworkPath_from_ReplyPath( self._network_paths[idx] )
            if self._logger: self._logger.info(f"Updated to: {self._network_paths[idx]}")
        else: # add new
            if self._logger: self._logger.info(f"Appending new NetworkPath")
            # write in the self address from an existing network-path
            _self_addr = self._network_paths[0].self_addr
            new_path = peer_reply_path.to_QuicNetworkPath(_self_addr)
            self._network_paths.append(new_path)
            if self._logger: self._logger.info(f"New NetworkPath: {new_path}")

        # If we're the server then generate our own for sending to client.
        # All server needs to send is its selected connection ID. The client has chosen everything else
        if not self._is_client:
            r = ReplyPathV2(logger=self._logger)
            r.peer_real_connection_id = self.host_cid
            self._push_reply_path(reply_path=r)
        

    def _handle_client_key_frame(self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        pass

    def _log_key_retired(self, key_type: str, trigger: str) -> None:
        """
        Log a key retirement.
        """
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="security",
                event="key_retired",
                data={"key_type": key_type, "trigger": trigger},
            )

    def _log_key_updated(self, key_type: str, trigger: str) -> None:
        """
        Log a key update.
        """
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="security",
                event="key_updated",
                data={"key_type": key_type, "trigger": trigger},
            )

    def _on_ack_delivery(
        self, delivery: QuicDeliveryState, space: QuicPacketSpace, highest_acked: int
    ) -> None:
        """
        Callback when an ACK frame is acknowledged or lost.
        """
        if delivery == QuicDeliveryState.ACKED:
            space.ack_queue.subtract(0, highest_acked + 1)

    def _on_connection_limit_delivery(
        self, delivery: QuicDeliveryState, limit: Limit
    ) -> None:
        """
        Callback when a MAX_DATA or MAX_STREAMS frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            limit.sent = 0

    def _on_handshake_done_delivery(self, delivery: QuicDeliveryState) -> None:
        """
        Callback when a HANDSHAKE_DONE frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._handshake_done_pending = True

    def _on_max_stream_data_delivery(
        self, delivery: QuicDeliveryState, stream: QuicStream
    ) -> None:
        """
        Callback when a MAX_STREAM_DATA frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            stream.max_stream_data_local_sent = 0

    def _on_new_connection_id_delivery(
        self, delivery: QuicDeliveryState, connection_id: QuicConnectionId
    ) -> None:
        """
        Callback when a NEW_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            connection_id.was_sent = False

    def _on_ping_delivery(
        self, delivery: QuicDeliveryState, uids: Sequence[int]
    ) -> None:
        """
        Callback when a PING frame is acknowledged or lost.
        """
        if delivery == QuicDeliveryState.ACKED:
            self._logger.debug("Received PING%s response", "" if uids else " (probe)")
            for uid in uids:
                self._events.append(events.PingAcknowledged(uid=uid))
        else:
            self._ping_pending.extend(uids)

    def _on_retire_connection_id_delivery(
        self, delivery: QuicDeliveryState, sequence_number: int
    ) -> None:
        """
        Callback when a RETIRE_CONNECTION_ID frame is acknowledged or lost.
        """
        if delivery != QuicDeliveryState.ACKED:
            self._retire_connection_ids.append(sequence_number)

    def _payload_received(
        self, context: QuicReceiveContext, plain: bytes
    ) -> Tuple[bool, bool]:
        """
        Handle a QUIC packet payload.
        """
        self._logger.debug("connection::_payload_received")
        buf = Buffer(data=plain) # The whole packet, 

        frame_found = False
        is_ack_eliciting = False
        is_probing = None
        while not buf.eof():
            frame_type = buf.pull_uint_var()

            # check frame type is known
            try:
                frame_handler, frame_epochs = self.__frame_handlers[frame_type]
            except KeyError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unknown frame type",
                )

            # check frame is allowed for the epoch
            if context.epoch not in frame_epochs:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unexpected frame type",
                )

            # handle the frame
            try:
                self._logger.debug(f"Calling frame_handler for frame_type={frame_type}")
                frame_handler(context, frame_type, buf) # buf is the bytes contents of the whole packet, not individual frame bytes
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Failed to parse frame",
                )
            except StreamFinishedError:
                # we lack the state for the stream, ignore the frame
                pass

            # update ACK only / probing flags
            frame_found = True

            if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                is_ack_eliciting = True

            if frame_type not in PROBING_FRAME_TYPES:
                is_probing = False
            elif is_probing is None:
                is_probing = True

        if not frame_found:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=QuicFrameType.PADDING,
                reason_phrase="Packet contains no frames",
            )

        return is_ack_eliciting, bool(is_probing)

    def _replenish_connection_ids(self) -> None:
        """
        Generate new connection IDs.
        """
        while len(self._host_cids) < min(8, self._remote_active_connection_id_limit):
            self._host_cids.append(
                QuicConnectionId(
                    cid=os.urandom(self._configuration.connection_id_length),
                    sequence_number=self._host_cid_seq,
                    stateless_reset_token=os.urandom(16),
                )
            )
            self._host_cid_seq += 1

    def _retire_peer_cid(self, connection_id: QuicConnectionId) -> None:
        """
        Retire a destination connection ID.
        """
        self._logger.debug(
            "Retiring CID %s (%d)",
            dump_cid(connection_id.cid),
            connection_id.sequence_number,
        )
        self._retire_connection_ids.append(connection_id.sequence_number)

    def _push_crypto_data(self) -> None:
        for epoch, buf in self._crypto_buffers.items():
            self._crypto_streams[epoch].sender.write(buf.data)
            buf.seek(0)
    
    def _push_reply_path(self,
                         reply_path: Optional[ReplyPathV2] = None,
                         quic_network_path: Optional[QuicNetworkPath] = None
                        ):
        # Note we are sending this to the peer so the
        # peer real address from their perspective has to be our real address
        # likewise our recv_from must be their send_as
        self._logger.debug("_push_reply_path")
        if reply_path:
            self._reply_path_send = reply_path
        else:
            if quic_network_path is None:
                quic_network_path = self._network_paths[0]
            self._reply_path_send = ReplyPathV2().prep_to_send_from_QuicNetworkPath(qnp=quic_network_path, host_cid=self.host_cid)
        self._logger.debug(f"_reply_path_send: {self._reply_path_send}")
    
    def _push_client_key(self):
        self._client_key = None

    def _send_probe(self) -> None:
        self._probe_pending = True

    def _parse_transport_parameters(
        self, data: bytes, from_session_ticket: bool = False
    ) -> None:
        """
        Parse and apply remote transport parameters.

        `from_session_ticket` is `True` when restoring saved transport parameters,
        and `False` when handling received transport parameters.
        """

        try:
            quic_transport_parameters = pull_quic_transport_parameters(
                Buffer(data=data)
            )
        except ValueError:
            raise QuicConnectionError(
                error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                frame_type=QuicFrameType.CRYPTO,
                reason_phrase="Could not parse QUIC transport parameters",
            )

        # log event
        if self._quic_logger is not None and not from_session_ticket:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="remote", parameters=quic_transport_parameters
                ),
            )

        # validate remote parameters
        if not self._is_client:
            for attr in [
                "original_destination_connection_id",
                "preferred_address",
                "retry_source_connection_id",
                "stateless_reset_token",
            ]:
                if getattr(quic_transport_parameters, attr) is not None:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                        frame_type=QuicFrameType.CRYPTO,
                        reason_phrase="%s is not allowed for clients" % attr,
                    )

        if not from_session_ticket:
            if (
                quic_transport_parameters.initial_source_connection_id
                != self._remote_initial_source_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="initial_source_connection_id does not match",
                )
            if self._is_client and (
                quic_transport_parameters.original_destination_connection_id
                != self._original_destination_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="original_destination_connection_id does not match",
                )
            if self._is_client and (
                quic_transport_parameters.retry_source_connection_id
                != self._retry_source_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="retry_source_connection_id does not match",
                )
            if (
                quic_transport_parameters.active_connection_id_limit is not None
                and quic_transport_parameters.active_connection_id_limit < 2
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="active_connection_id_limit must be no less than 2",
                )
            if (
                quic_transport_parameters.ack_delay_exponent is not None
                and quic_transport_parameters.ack_delay_exponent > 20
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="ack_delay_exponent must be <= 20",
                )
            if (
                quic_transport_parameters.max_ack_delay is not None
                and quic_transport_parameters.max_ack_delay >= 2**14
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="max_ack_delay must be < 2^14",
                )
            if (
                quic_transport_parameters.max_udp_payload_size is not None
                and quic_transport_parameters.max_udp_payload_size < 1200
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="max_udp_payload_size must be >= 1200",
                )

        # store remote parameters
        if not from_session_ticket:
            if quic_transport_parameters.ack_delay_exponent is not None:
                self._remote_ack_delay_exponent = self._remote_ack_delay_exponent
            if quic_transport_parameters.max_ack_delay is not None:
                self._loss.max_ack_delay = (
                    quic_transport_parameters.max_ack_delay / 1000.0
                )
            if (
                self._is_client
                and self._peer_cid.sequence_number == 0
                and quic_transport_parameters.stateless_reset_token is not None
            ):
                self._peer_cid.stateless_reset_token = (
                    quic_transport_parameters.stateless_reset_token
                )

        if quic_transport_parameters.active_connection_id_limit is not None:
            self._remote_active_connection_id_limit = (
                quic_transport_parameters.active_connection_id_limit
            )
        if quic_transport_parameters.max_idle_timeout is not None:
            self._remote_max_idle_timeout = (
                quic_transport_parameters.max_idle_timeout / 1000.0
            )
        self._remote_max_datagram_frame_size = (
            quic_transport_parameters.max_datagram_frame_size
        )
        for param in [
            "max_data",
            "max_stream_data_bidi_local",
            "max_stream_data_bidi_remote",
            "max_stream_data_uni",
            "max_streams_bidi",
            "max_streams_uni",
        ]:
            value = getattr(quic_transport_parameters, "initial_" + param)
            if value is not None:
                setattr(self, "_remote_" + param, value)

    def _serialize_transport_parameters(self) -> bytes:
        quic_transport_parameters = QuicTransportParameters(
            ack_delay_exponent=self._local_ack_delay_exponent,
            active_connection_id_limit=self._local_active_connection_id_limit,
            max_idle_timeout=int(self._configuration.idle_timeout * 1000),
            initial_max_data=self._local_max_data.value,
            initial_max_stream_data_bidi_local=self._local_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote=self._local_max_stream_data_bidi_remote,
            initial_max_stream_data_uni=self._local_max_stream_data_uni,
            initial_max_streams_bidi=self._local_max_streams_bidi.value,
            initial_max_streams_uni=self._local_max_streams_uni.value,
            initial_source_connection_id=self._local_initial_source_connection_id,
            max_ack_delay=25,
            max_datagram_frame_size=self._configuration.max_datagram_frame_size,
            quantum_readiness=b"Q" * 1200
            if self._configuration.quantum_readiness_test
            else None,
            stateless_reset_token=self._host_cids[0].stateless_reset_token,
        )
        if not self._is_client:
            quic_transport_parameters.original_destination_connection_id = (
                self._original_destination_connection_id
            )
            quic_transport_parameters.retry_source_connection_id = (
                self._retry_source_connection_id
            )

        # log event
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="transport",
                event="parameters_set",
                data=self._quic_logger.encode_transport_parameters(
                    owner="local", parameters=quic_transport_parameters
                ),
            )

        buf = Buffer(capacity=3 * PACKET_MAX_SIZE)
        push_quic_transport_parameters(buf, quic_transport_parameters)
        return buf.data

    def _set_state(self, state: QuicConnectionState) -> None:
        self._logger.debug("%s -> %s", self._state, state)
        self._state = state

    def _stream_can_receive(self, stream_id: int) -> bool:
        return stream_is_client_initiated(
            stream_id
        ) != self._is_client or not stream_is_unidirectional(stream_id)

    def _stream_can_send(self, stream_id: int) -> bool:
        return stream_is_client_initiated(
            stream_id
        ) == self._is_client or not stream_is_unidirectional(stream_id)

    def _unblock_streams(self, is_unidirectional: bool) -> None:
        if is_unidirectional:
            max_stream_data_remote = self._remote_max_stream_data_uni
            max_streams = self._remote_max_streams_uni
            streams_blocked = self._streams_blocked_uni
        else:
            max_stream_data_remote = self._remote_max_stream_data_bidi_remote
            max_streams = self._remote_max_streams_bidi
            streams_blocked = self._streams_blocked_bidi

        while streams_blocked and streams_blocked[0].stream_id // 4 < max_streams:
            stream = streams_blocked.pop(0)
            stream.is_blocked = False
            stream.max_stream_data_remote = max_stream_data_remote

        if not self._streams_blocked_bidi and not self._streams_blocked_uni:
            self._streams_blocked_pending = False

    def _update_traffic_key(
        self,
        direction: tls.Direction,
        epoch: tls.Epoch,
        cipher_suite: tls.CipherSuite,
        secret: bytes,
    ) -> None:
        """
        Callback which is invoked by the TLS engine when new traffic keys are
        available.
        """
        secrets_log_file = self._configuration.secrets_log_file
        if secrets_log_file is not None:
            label_row = self._is_client == (direction == tls.Direction.DECRYPT)
            label = SECRETS_LABELS[label_row][epoch.value]
            secrets_log_file.write(
                "%s %s %s\n" % (label, self.tls.client_random.hex(), secret.hex())
            )
            secrets_log_file.flush()

        crypto = self._cryptos[epoch]
        if direction == tls.Direction.ENCRYPT:
            crypto.send.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._version
            )
        else:
            crypto.recv.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._version
            )

    def _write_application(
        self, builder: QuicPacketBuilder, network_path: QuicNetworkPath, now: float
    ) -> None:
        crypto_stream: Optional[QuicStream] = None
        if self._cryptos[tls.Epoch.ONE_RTT].send.is_valid():
            crypto = self._cryptos[tls.Epoch.ONE_RTT]
            crypto_stream = self._crypto_streams[tls.Epoch.ONE_RTT]
            packet_type = PACKET_TYPE_ONE_RTT
        elif self._cryptos[tls.Epoch.ZERO_RTT].send.is_valid():
            crypto = self._cryptos[tls.Epoch.ZERO_RTT]
            packet_type = PACKET_TYPE_ZERO_RTT
        else:
            return
        space = self._spaces[tls.Epoch.ONE_RTT]

        while True:
            # apply pacing, except if we have ACKs to send
            if space.ack_at is None or space.ack_at >= now:
                self._pacing_at = self._loss._pacer.next_send_time(now=now)
                if self._pacing_at is not None:
                    break
            builder.start_packet(packet_type, crypto)

            if self._handshake_complete:
                # ACK
                if space.ack_at is not None and space.ack_at <= now:
                    self._write_ack_frame(builder=builder, space=space, now=now)

                # HANDSHAKE_DONE
                if self._handshake_done_pending:
                    self._write_handshake_done_frame(builder=builder)
                    self._handshake_done_pending = False

                # PATH CHALLENGE
                if (
                    not network_path.is_validated
                    and network_path.local_challenge is None
                ):
                    challenge = os.urandom(8)
                    self._write_path_challenge_frame(
                        builder=builder, challenge=challenge
                    )
                    network_path.local_challenge = challenge

                # PATH RESPONSE
                if network_path.remote_challenge is not None:
                    self._write_path_response_frame(
                        builder=builder, challenge=network_path.remote_challenge
                    )
                    network_path.remote_challenge = None

                # NEW_CONNECTION_ID
                for connection_id in self._host_cids:
                    if not connection_id.was_sent:
                        self._write_new_connection_id_frame(
                            builder=builder, connection_id=connection_id
                        )

                # RETIRE_CONNECTION_ID
                for sequence_number in self._retire_connection_ids[:]:
                    self._write_retire_connection_id_frame(
                        builder=builder, sequence_number=sequence_number
                    )
                    self._retire_connection_ids.pop(0)

                # STREAMS_BLOCKED
                if self._streams_blocked_pending:
                    if self._streams_blocked_bidi:
                        self._write_streams_blocked_frame(
                            builder=builder,
                            frame_type=QuicFrameType.STREAMS_BLOCKED_BIDI,
                            limit=self._remote_max_streams_bidi,
                        )
                    if self._streams_blocked_uni:
                        self._write_streams_blocked_frame(
                            builder=builder,
                            frame_type=QuicFrameType.STREAMS_BLOCKED_UNI,
                            limit=self._remote_max_streams_uni,
                        )
                    self._streams_blocked_pending = False

                # MAX_DATA and MAX_STREAMS
                self._write_connection_limits(builder=builder, space=space)

            # stream-level limits
            for stream in self._streams.values():
                self._write_stream_limits(builder=builder, space=space, stream=stream)

            # PING (user-request)
            if self._ping_pending:
                self._write_ping_frame(builder, self._ping_pending)
                self._ping_pending.clear()

            # PING (probe)
            if self._probe_pending:
                self._write_ping_frame(builder, comment="probe")
                self._probe_pending = False

            # CRYPTO
            if crypto_stream is not None and not crypto_stream.sender.buffer_is_empty:
                self._write_crypto_frame(
                    builder=builder, space=space, stream=crypto_stream
                )

            # DATAGRAM
            while self._datagrams_pending:
                try:
                    self._write_datagram_frame(
                        builder=builder,
                        data=self._datagrams_pending[0],
                        frame_type=QuicFrameType.DATAGRAM_WITH_LENGTH,
                    )
                    self._datagrams_pending.popleft()
                except QuicPacketBuilderStop:
                    break

            for stream in list(self._streams.values()):
                # if the stream is finished, discard it
                if stream.is_finished:
                    self._logger.debug("Stream %d discarded", stream.stream_id)
                    self._streams.pop(stream.stream_id)
                    self._streams_finished.add(stream.stream_id)
                    continue

                if stream.receiver.stop_pending:
                    # STOP_SENDING
                    self._write_stop_sending_frame(builder=builder, stream=stream)

                if stream.sender.reset_pending:
                    # RESET_STREAM
                    self._write_reset_stream_frame(builder=builder, stream=stream)
                elif not stream.is_blocked and not stream.sender.buffer_is_empty:
                    # STREAM
                    self._remote_max_data_used += self._write_stream_frame(
                        builder=builder,
                        space=space,
                        stream=stream,
                        max_offset=min(
                            stream.sender.highest_offset
                            + self._remote_max_data
                            - self._remote_max_data_used,
                            stream.max_stream_data_remote,
                        ),
                    )

            if builder.packet_is_empty:
                break
            else:
                self._loss._pacer.update_after_send(now=now)

    def _write_handshake(
        self, builder: QuicPacketBuilder, epoch: tls.Epoch, now: float
    ) -> None:
        crypto = self._cryptos[epoch]
        if not crypto.send.is_valid():
            return

        crypto_stream = self._crypto_streams[epoch]
        space = self._spaces[epoch]
        reply_path_written: bool = False
        client_key_written: bool = False

        while True:
            if epoch == tls.Epoch.INITIAL:
                packet_type = PACKET_TYPE_INITIAL
            else:
                packet_type = PACKET_TYPE_HANDSHAKE
            builder.start_packet(packet_type,
                                 crypto,
                                 initial_assymetric_crypto=self._tls_cert_public_key,
                                 initial_asymmetric_padding=self._initial_asymmetric_padding
                                 ) # starts a new packet every iteration

            # ACK
            if space.ack_at is not None:
                self._write_ack_frame(builder=builder, space=space, now=now)

            # CRYPTO
            if not crypto_stream.sender.buffer_is_empty: # multiple frames to send in first crypto packet. Write them all
                if self._write_crypto_frame(
                    builder=builder, space=space, stream=crypto_stream
                ):
                    self._probe_pending = False

            # ReplyPath and ClientKey
            if (
                not self._handshake_complete
                and packet_type == PACKET_TYPE_INITIAL
            ):
                if not reply_path_written:
                    self._write_reply_path_frame( builder=builder, reply_path=self._reply_path_send )
                    reply_path_written = True
                if not client_key_written:
                    self._write_client_key_frame( builder=builder, client_key=self._client_key )
                    client_key_written = True

            # PING (probe)
            if (
                self._probe_pending
                and not self._handshake_complete
                and (
                    epoch == tls.Epoch.HANDSHAKE
                    or not self._cryptos[tls.Epoch.HANDSHAKE].send.is_valid()
                )
            ):
                self._write_ping_frame(builder, comment="probe")
                self._probe_pending = False

            if builder.packet_is_empty:
                break

    def _write_ack_frame(
        self, builder: QuicPacketBuilder, space: QuicPacketSpace, now: float
    ) -> None:
        # calculate ACK delay
        ack_delay = now - space.largest_received_time
        ack_delay_encoded = int(ack_delay * 1000000) >> self._local_ack_delay_exponent

        buf = builder.start_frame(
            QuicFrameType.ACK,
            capacity=ACK_FRAME_CAPACITY,
            handler=self._on_ack_delivery,
            handler_args=(space, space.largest_received_packet),
        )
        ranges = push_ack_frame(buf, space.ack_queue, ack_delay_encoded)
        space.ack_at = None

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_ack_frame(
                    ranges=space.ack_queue, delay=ack_delay
                )
            )

        # check if we need to trigger an ACK-of-ACK
        if ranges > 1 and builder.packet_number % 8 == 0:
            self._write_ping_frame(builder, comment="ACK-of-ACK trigger")

    def _write_connection_close_frame(
        self,
        builder: QuicPacketBuilder,
        epoch: tls.Epoch,
        error_code: int,
        frame_type: Optional[int],
        reason_phrase: str,
    ) -> None:
        # convert application-level close to transport-level close in early stages
        if frame_type is None and epoch in (tls.Epoch.INITIAL, tls.Epoch.HANDSHAKE):
            error_code = QuicErrorCode.APPLICATION_ERROR
            frame_type = QuicFrameType.PADDING
            reason_phrase = ""

        reason_bytes = reason_phrase.encode("utf8")
        reason_length = len(reason_bytes)

        if frame_type is None:
            buf = builder.start_frame(
                QuicFrameType.APPLICATION_CLOSE,
                capacity=APPLICATION_CLOSE_FRAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(error_code)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)
        else:
            buf = builder.start_frame(
                QuicFrameType.TRANSPORT_CLOSE,
                capacity=TRANSPORT_CLOSE_FRAME_CAPACITY + reason_length,
            )
            buf.push_uint_var(error_code)
            buf.push_uint_var(frame_type)
            buf.push_uint_var(reason_length)
            buf.push_bytes(reason_bytes)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_connection_close_frame(
                    error_code=error_code,
                    frame_type=frame_type,
                    reason_phrase=reason_phrase,
                )
            )

    def _write_connection_limits(
        self, builder: QuicPacketBuilder, space: QuicPacketSpace
    ) -> None:
        """
        Raise MAX_DATA or MAX_STREAMS if needed.
        """
        for limit in (
            self._local_max_data,
            self._local_max_streams_bidi,
            self._local_max_streams_uni,
        ):
            if limit.used * 2 > limit.value:
                limit.value *= 2
                self._logger.debug("Local %s raised to %d", limit.name, limit.value)
            if limit.value != limit.sent:
                buf = builder.start_frame(
                    limit.frame_type,
                    capacity=CONNECTION_LIMIT_FRAME_CAPACITY,
                    handler=self._on_connection_limit_delivery,
                    handler_args=(limit,),
                )
                buf.push_uint_var(limit.value)
                limit.sent = limit.value

                # log frame
                if self._quic_logger is not None:
                    builder.quic_logger_frames.append(
                        self._quic_logger.encode_connection_limit_frame(
                            frame_type=limit.frame_type,
                            maximum=limit.value,
                        )
                    )

    def _write_crypto_frame(
        self, builder: QuicPacketBuilder, space: QuicPacketSpace, stream: QuicStream
    ) -> bool:
        frame_overhead = 3 + size_uint_var(stream.sender.next_offset)
        frame = stream.sender.get_frame(builder.remaining_flight_space - frame_overhead)
        if frame is not None:
            buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=frame_overhead,
                handler=stream.sender.on_data_delivery,
                handler_args=(frame.offset, frame.offset + len(frame.data)),
            )
            buf.push_uint_var(frame.offset)
            buf.push_uint16(len(frame.data) | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            if self._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic_logger.encode_crypto_frame(frame)
                )
            return True

        return False

    def _write_datagram_frame(
        self, builder: QuicPacketBuilder, data: bytes, frame_type: QuicFrameType
    ) -> bool:
        """
        Write a DATAGRAM frame.

        Returns True if the frame was processed, False otherwise.
        """
        assert frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH
        length = len(data)
        frame_size = 1 + size_uint_var(length) + length

        buf = builder.start_frame(frame_type, capacity=frame_size)
        buf.push_uint_var(length)
        buf.push_bytes(data)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_datagram_frame(length=length)
            )

        return True

    def _write_handshake_done_frame(self, builder: QuicPacketBuilder) -> None:
        builder.start_frame(
            QuicFrameType.HANDSHAKE_DONE,
            capacity=HANDSHAKE_DONE_FRAME_CAPACITY,
            handler=self._on_handshake_done_delivery,
        )

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_handshake_done_frame()
            )

    def _write_new_connection_id_frame(
        self, builder: QuicPacketBuilder, connection_id: QuicConnectionId
    ) -> None:
        retire_prior_to = 0  # FIXME

        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY,
            handler=self._on_new_connection_id_delivery,
            handler_args=(connection_id,),
        )
        buf.push_uint_var(connection_id.sequence_number)
        buf.push_uint_var(retire_prior_to)
        buf.push_uint8(len(connection_id.cid))
        buf.push_bytes(connection_id.cid)
        buf.push_bytes(connection_id.stateless_reset_token)

        connection_id.was_sent = True
        self._events.append(events.ConnectionIdIssued(connection_id=connection_id.cid))

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_new_connection_id_frame(
                    connection_id=connection_id.cid,
                    retire_prior_to=retire_prior_to,
                    sequence_number=connection_id.sequence_number,
                    stateless_reset_token=connection_id.stateless_reset_token,
                )
            )

    def _write_path_challenge_frame(
        self, builder: QuicPacketBuilder, challenge: bytes
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.PATH_CHALLENGE, capacity=PATH_CHALLENGE_FRAME_CAPACITY
        )
        buf.push_bytes(challenge)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_path_challenge_frame(data=challenge)
            )

    def _write_path_response_frame(
        self, builder: QuicPacketBuilder, challenge: bytes
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.PATH_RESPONSE, capacity=PATH_RESPONSE_FRAME_CAPACITY
        )
        buf.push_bytes(challenge)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_path_response_frame(data=challenge)
            )

    def _write_ping_frame(
        self, builder: QuicPacketBuilder, uids: List[int] = [], comment=""
    ):
        builder.start_frame(
            QuicFrameType.PING,
            capacity=PING_FRAME_CAPACITY,
            handler=self._on_ping_delivery,
            handler_args=(tuple(uids),),
        )
        self._logger.debug(
            "Sending PING%s in packet %d",
            " (%s)" % comment if comment else "",
            builder.packet_number,
        )

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(self._quic_logger.encode_ping_frame())

    def _write_reset_stream_frame(
        self,
        builder: QuicPacketBuilder,
        stream: QuicStream,
    ) -> None:
        buf = builder.start_frame(
            frame_type=QuicFrameType.RESET_STREAM,
            capacity=RESET_STREAM_FRAME_CAPACITY,
            handler=stream.sender.on_reset_delivery,
        )
        frame = stream.sender.get_reset_frame()
        buf.push_uint_var(frame.stream_id)
        buf.push_uint_var(frame.error_code)
        buf.push_uint_var(frame.final_size)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_reset_stream_frame(
                    error_code=frame.error_code,
                    final_size=frame.final_size,
                    stream_id=frame.stream_id,
                )
            )

    def _write_retire_connection_id_frame(
        self, builder: QuicPacketBuilder, sequence_number: int
    ) -> None:
        buf = builder.start_frame(
            QuicFrameType.RETIRE_CONNECTION_ID,
            capacity=RETIRE_CONNECTION_ID_CAPACITY,
            handler=self._on_retire_connection_id_delivery,
            handler_args=(sequence_number,),
        )
        buf.push_uint_var(sequence_number)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_retire_connection_id_frame(sequence_number)
            )

    def _write_stop_sending_frame(
        self,
        builder: QuicPacketBuilder,
        stream: QuicStream,
    ) -> None:
        buf = builder.start_frame(
            frame_type=QuicFrameType.STOP_SENDING,
            capacity=STOP_SENDING_FRAME_CAPACITY,
            handler=stream.receiver.on_stop_sending_delivery,
        )
        frame = stream.receiver.get_stop_frame()
        buf.push_uint_var(frame.stream_id)
        buf.push_uint_var(frame.error_code)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_stop_sending_frame(
                    error_code=frame.error_code, stream_id=frame.stream_id
                )
            )

    def _write_stream_frame(
        self,
        builder: QuicPacketBuilder,
        space: QuicPacketSpace,
        stream: QuicStream,
        max_offset: int,
    ) -> int:
        # the frame data size is constrained by our peer's MAX_DATA and
        # the space available in the current packet
        frame_overhead = (
            3
            + size_uint_var(stream.stream_id)
            + (
                size_uint_var(stream.sender.next_offset)
                if stream.sender.next_offset
                else 0
            )
        )
        previous_send_highest = stream.sender.highest_offset
        frame = stream.sender.get_frame(
            builder.remaining_flight_space - frame_overhead, max_offset
        )

        if frame is not None:
            frame_type = QuicFrameType.STREAM_BASE | 2  # length
            if frame.offset:
                frame_type |= 4
            if frame.fin:
                frame_type |= 1
            buf = builder.start_frame(
                frame_type,
                capacity=frame_overhead,
                handler=stream.sender.on_data_delivery,
                handler_args=(frame.offset, frame.offset + len(frame.data)),
            )
            buf.push_uint_var(stream.stream_id)
            if frame.offset:
                buf.push_uint_var(frame.offset)
            buf.push_uint16(len(frame.data) | 0x4000)
            buf.push_bytes(frame.data)

            # log frame
            if self._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic_logger.encode_stream_frame(
                        frame, stream_id=stream.stream_id
                    )
                )

            return stream.sender.highest_offset - previous_send_highest
        else:
            return 0

    def _write_stream_limits(
        self, builder: QuicPacketBuilder, space: QuicPacketSpace, stream: QuicStream
    ) -> None:
        """
        Raise MAX_STREAM_DATA if needed.

        The only case where `stream.max_stream_data_local` is zero is for
        locally created unidirectional streams. We skip such streams to avoid
        spurious logging.
        """
        if (
            stream.max_stream_data_local
            and stream.receiver.highest_offset * 2 > stream.max_stream_data_local
        ):
            stream.max_stream_data_local *= 2
            self._logger.debug(
                "Stream %d local max_stream_data raised to %d",
                stream.stream_id,
                stream.max_stream_data_local,
            )
        if stream.max_stream_data_local_sent != stream.max_stream_data_local:
            buf = builder.start_frame(
                QuicFrameType.MAX_STREAM_DATA,
                capacity=MAX_STREAM_DATA_FRAME_CAPACITY,
                handler=self._on_max_stream_data_delivery,
                handler_args=(stream,),
            )
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(stream.max_stream_data_local)
            stream.max_stream_data_local_sent = stream.max_stream_data_local

            # log frame
            if self._quic_logger is not None:
                builder.quic_logger_frames.append(
                    self._quic_logger.encode_max_stream_data_frame(
                        maximum=stream.max_stream_data_local, stream_id=stream.stream_id
                    )
                )

    def _write_streams_blocked_frame(
        self, builder: QuicPacketBuilder, frame_type: QuicFrameType, limit: int
    ) -> None:
        buf = builder.start_frame(frame_type, capacity=STREAMS_BLOCKED_CAPACITY)
        buf.push_uint_var(limit)

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_streams_blocked_frame(
                    is_unidirectional=frame_type == QuicFrameType.STREAMS_BLOCKED_UNI,
                    limit=limit,
                )
            )

    
    # ConfidentialQUIC new
    def _write_reply_path_frame(
        self, builder: QuicPacketBuilder, reply_path: ReplyPathV2
    ) -> None:
        self._logger.debug(f"_write_reply_path_frame builder total bytes: {builder._total_bytes}")
        rp_bytes = reply_path.to_bytes()
        self._logger.debug(f"reply path: {reply_path}")
        self._logger.debug(f"reply path bytes\n length: {len(rp_bytes)}\n bytes: {rp_bytes}")
        buf = builder.start_frame(QuicFrameType.REPLY_PATH, capacity=len(rp_bytes))
        buf.push_bytes(rp_bytes)
    

    def _write_client_key_frame(
        self, builder: QuicPacketBuilder, client_key: ClientKey,
    ) -> None:
        pass

    def pull_reply_path(buf: Buffer) -> ReplyPathV2:
        # type
        #assert buf.pull_uint8() == HandshakeType.REPLY_PATH
        # length
        return ReplyPathV2(buf)
        

    def _client_send_reply_path(self, output_buf: Buffer, reply_path ) -> None:
        '''
        if self.__logger: self.__logger.debug("tls:_client_send_reply_path")
        
        # Fix circular imports
        #reply_path = cast(QuicNetworkPath, reply_path)
        
        path = ReplyPath(
                peer_real_addr=IPv6Address(reply_path.self_addr[0]),
                peer_real_port=reply_path.self_addr[1],
                send_as_addr=IPv6Address(reply_path.recv_from[0]),   # server sends as client's receive_from
                send_as_port=reply_path.recv_from[1],
                recv_from_addr=IPv6Address(reply_path.send_as[0]),   # server receives from client send_as
                recv_from_port=reply_path.send_as[1]
            )
        self.__logger.debug(f"tls:_client_send_reply_path: path: {path}")
        push_reply_path(output_buf, path)
        '''

    def _server_handle_reply_path(self, input_buf: Buffer, network_paths) -> None:
        '''
        if self.__logger: self.__logger.debug("tls:_server_handle_reply_path")

        # Fix circular imports
        from .quic.connection import QuicNetworkPath
        network_paths = cast(List[QuicNetworkPath], network_paths)

        peer_reply_path = pull_reply_path(input_buf)
        self.__logger.debug(f"_server_handle_reply_path: path: {peer_reply_path}")
        
        # convert to QuicNetworkPath
        new_path = QuicNetworkPath(
            addr = ( peer_reply_path.peer_real_addr.compressed, peer_reply_path.peer_real_port, 0, 0 ),
            send_as = ( peer_reply_path.send_as_addr.compressed, peer_reply_path.send_as_port, 0, 0),
            recv_from = ( peer_reply_path.recv_from_addr.compressed, peer_reply_path.recv_from_port, 0, 0)
        )

        # find the existing default path with confidential one
        idx = None
        old_path = None
        for i, path in enumerate(network_paths):
            if (
                path.addr == path.recv_from # isn't confidential (default)
                and path.addr == new_path.recv_from
            ):
                idx = i
                old_path = path
        
        # replace
        if idx is not None:
            self.__logger.info(f"Replacing NetworkPath: {old_path} wtih \nnew NetworkPath: {new_path}")
            network_paths[idx] = new_path
        else:
            self.__logger.info(f"Appending new NetworkPath: {new_path}")
            network_paths.append(new_path)
        '''