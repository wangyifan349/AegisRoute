#!/usr/bin/env python3
"""
windows_socks5_gateway.py

Windows-compatible proxy gateway using Python standard library only.

Purpose:
    This program provides a local proxy gateway and forwards all outbound traffic
    to one upstream SOCKS5 proxy.

Inbound protocols supported by this program:
    - HTTP forward proxy
    - HTTPS through HTTP CONNECT
    - SOCKS5 TCP CONNECT
    - SOCKS5 UDP ASSOCIATE

Outbound behavior:
    - HTTP traffic is forwarded through upstream SOCKS5 CONNECT.
    - HTTPS CONNECT tunnels are forwarded through upstream SOCKS5 CONNECT.
    - SOCKS5 TCP CONNECT is forwarded through upstream SOCKS5 CONNECT.
    - SOCKS5 UDP ASSOCIATE is forwarded through upstream SOCKS5 UDP ASSOCIATE.

Important limitations:
    - SOCKS5 UDP works only if the upstream SOCKS5 proxy supports UDP ASSOCIATE.
    - SOCKS5 BIND is not implemented.
    - HTTPS is tunneled only; TLS is not decrypted or inspected.
    - This is not a transparent proxy. Client software must explicitly use this proxy.
    - The default listener binds to 0.0.0.0 and ::. Use firewall rules if needed.

Requirements:
    - Windows
    - Python 3.10 or newer
    - No third-party Python packages are required.

Run:
    python windows_socks5_gateway.py

Configuration:
    Edit UPSTREAM_SOCKS5_HOST, UPSTREAM_SOCKS5_PORT, UPSTREAM_SOCKS5_USERNAME,
    and UPSTREAM_SOCKS5_PASSWORD near the top of this file.
"""

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_LISTEN_PORT = 8080
UPSTREAM_SOCKS5_HOST = "127.0.0.1"
UPSTREAM_SOCKS5_PORT = 1080
UPSTREAM_SOCKS5_USERNAME = ""
UPSTREAM_SOCKS5_PASSWORD = ""

BUFFER_SIZE = 64 * 1024
STREAM_LIMIT = 256 * 1024
HEADER_LIMIT = 64 * 1024
HANDSHAKE_TIMEOUT = 10
CONNECT_TIMEOUT = 15
IDLE_TIMEOUT = 900
MAX_CONCURRENT_CONNECTIONS = 30000
LISTEN_BACKLOG = 8192
TCP_KEEPALIVE_IDLE_MS = 60_000
TCP_KEEPALIVE_INTERVAL_MS = 20_000

SOCKS_VERSION = 0x05
SOCKS_METHOD_NO_AUTH = 0x00
SOCKS_METHOD_USERNAME_PASSWORD = 0x02
SOCKS_METHOD_NO_ACCEPTABLE = 0xFF
SOCKS_CMD_CONNECT = 0x01
SOCKS_CMD_BIND = 0x02
SOCKS_CMD_UDP_ASSOCIATE = 0x03
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04
SOCKS_REPLY_SUCCEEDED = 0x00
SOCKS_REPLY_GENERAL_FAILURE = 0x01
SOCKS_REPLY_HOST_UNREACHABLE = 0x04
SOCKS_REPLY_CONNECTION_REFUSED = 0x05
SOCKS_REPLY_COMMAND_NOT_SUPPORTED = 0x07

HTTP_HOP_BY_HOP_HEADERS = {
    b"connection", b"proxy-connection", b"keep-alive", b"proxy-authenticate",
    b"proxy-authorization", b"te", b"trailer", b"upgrade",
}

connection_semaphore: asyncio.Semaphore

@dataclass
class HttpHeaders:
    raw_lines: list[bytes]
    values: dict[bytes, list[bytes]]

@dataclass
class ServerConfig:
    listen_port: int
    max_connections: int = MAX_CONCURRENT_CONNECTIONS
    backlog: int = LISTEN_BACKLOG

@dataclass
class Socks5Reply:
    reply_code: int
    bind_host: str
    bind_port: int

def configure_tcp_socket(tcp_socket: socket.socket | None) -> None:
    """Enable TCP_NODELAY and TCP keepalive on Windows-supported sockets."""
    if tcp_socket is None:
        return
    tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        keepalive_values = struct.pack("III", 1, TCP_KEEPALIVE_IDLE_MS, TCP_KEEPALIVE_INTERVAL_MS)
        tcp_socket.ioctl(socket.SIO_KEEPALIVE_VALS, keepalive_values)

def create_listen_socket(address_family: int, host: str, port: int, backlog: int) -> socket.socket:
    """Create an IPv4 or IPv6 TCP listening socket."""
    listen_socket = socket.socket(address_family, socket.SOCK_STREAM)
    listen_socket.setblocking(False)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if address_family == socket.AF_INET6:
        listen_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listen_socket.bind((host, port))
    listen_socket.listen(backlog)
    return listen_socket

def split_host_port(authority: str, default_port: int) -> tuple[str, int]:
    """Parse host:port, [ipv6]:port, or plain host."""
    if authority.startswith("["):
        closing_bracket_index = authority.find("]")
        if closing_bracket_index < 0:
            raise ValueError("invalid IPv6 authority")
        host = authority[1:closing_bracket_index]
        suffix = authority[closing_bracket_index + 1:]
        port = int(suffix[1:]) if suffix.startswith(":") else default_port
        return host, port
    if authority.count(":") == 1:
        host, port_text = authority.rsplit(":", 1)
        return host, int(port_text)
    return authority, default_port

def encode_socks5_address(address: str, port: int) -> bytes:
    """Encode IPv4, IPv6, or domain name into SOCKS5 address format."""
    try:
        return bytes([SOCKS_ATYP_IPV4]) + socket.inet_pton(socket.AF_INET, address) + struct.pack("!H", port)
    except OSError:
        pass
    try:
        return bytes([SOCKS_ATYP_IPV6]) + socket.inet_pton(socket.AF_INET6, address) + struct.pack("!H", port)
    except OSError:
        encoded_domain = address.encode("idna")
        if len(encoded_domain) > 255:
            raise ValueError("domain name too long")
        return bytes([SOCKS_ATYP_DOMAIN]) + bytes([len(encoded_domain)]) + encoded_domain + struct.pack("!H", port)

async def read_socks5_address(reader: asyncio.StreamReader, address_type: int) -> tuple[str, int]:
    """Read a SOCKS5 address from a TCP stream."""
    if address_type == SOCKS_ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif address_type == SOCKS_ATYP_DOMAIN:
        domain_length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(domain_length)).decode("idna")
    elif address_type == SOCKS_ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ValueError("unsupported SOCKS5 address type")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return host, port

async def read_socks5_reply(reader: asyncio.StreamReader) -> Socks5Reply:
    """Read a SOCKS5 server reply."""
    version, reply_code, reserved, address_type = await reader.readexactly(4)
    if version != SOCKS_VERSION or reserved != 0x00:
        raise ConnectionError("invalid SOCKS5 reply header")
    bind_host, bind_port = await read_socks5_address(reader, address_type)
    return Socks5Reply(reply_code=reply_code, bind_host=bind_host, bind_port=bind_port)

def build_socks5_reply(reply_code: int, bind_host: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    """Build a SOCKS5 reply for inbound SOCKS5 clients."""
    return bytes([SOCKS_VERSION, reply_code, 0x00]) + encode_socks5_address(bind_host, bind_port)

def decode_socks5_udp_datagram(datagram: bytes) -> tuple[str, int, bytes] | None:
    """Validate and decode a SOCKS5 UDP datagram."""
    if len(datagram) < 4:
        return None
    reserved, fragment_number, address_type = struct.unpack("!HBB", datagram[:4])
    if reserved != 0 or fragment_number != 0:
        return None
    offset = 4
    if address_type == SOCKS_ATYP_IPV4:
        if len(datagram) < offset + 4 + 2:
            return None
        host = socket.inet_ntop(socket.AF_INET, datagram[offset:offset + 4])
        offset += 4
    elif address_type == SOCKS_ATYP_DOMAIN:
        if len(datagram) < offset + 1:
            return None
        domain_length = datagram[offset]
        offset += 1
        if len(datagram) < offset + domain_length + 2:
            return None
        host = datagram[offset:offset + domain_length].decode("idna")
        offset += domain_length
    elif address_type == SOCKS_ATYP_IPV6:
        if len(datagram) < offset + 16 + 2:
            return None
        host = socket.inet_ntop(socket.AF_INET6, datagram[offset:offset + 16])
        offset += 16
    else:
        return None
    port = struct.unpack("!H", datagram[offset:offset + 2])[0]
    offset += 2
    return host, port, datagram[offset:]

async def open_upstream_tcp_connection() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to the upstream SOCKS5 server and complete authentication."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(UPSTREAM_SOCKS5_HOST, UPSTREAM_SOCKS5_PORT, limit=STREAM_LIMIT),
        timeout=CONNECT_TIMEOUT,
    )
    configure_tcp_socket(writer.get_extra_info("socket"))
    methods = [SOCKS_METHOD_NO_AUTH]
    if UPSTREAM_SOCKS5_USERNAME or UPSTREAM_SOCKS5_PASSWORD:
        methods.append(SOCKS_METHOD_USERNAME_PASSWORD)
    writer.write(bytes([SOCKS_VERSION, len(methods)]) + bytes(methods))
    await writer.drain()
    version, selected_method = await reader.readexactly(2)
    if version != SOCKS_VERSION:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError("invalid upstream SOCKS5 version")
    if selected_method == SOCKS_METHOD_NO_AUTH:
        return reader, writer
    if selected_method == SOCKS_METHOD_USERNAME_PASSWORD:
        username = UPSTREAM_SOCKS5_USERNAME.encode("utf-8")
        password = UPSTREAM_SOCKS5_PASSWORD.encode("utf-8")
        if len(username) > 255 or len(password) > 255:
            writer.close()
            await writer.wait_closed()
            raise ValueError("SOCKS5 username/password too long")
        writer.write(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await writer.drain()
        auth_version, auth_status = await reader.readexactly(2)
        if auth_version != 0x01 or auth_status != 0x00:
            writer.close()
            await writer.wait_closed()
            raise ConnectionError("upstream SOCKS5 authentication failed")
        return reader, writer
    writer.close()
    await writer.wait_closed()
    raise ConnectionError("upstream SOCKS5 rejected all authentication methods")

async def connect_remote_via_upstream(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, Socks5Reply]:
    """Create a SOCKS5 CONNECT through the upstream SOCKS5 server."""
    reader, writer = await open_upstream_tcp_connection()
    writer.write(bytes([SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00]) + encode_socks5_address(host, port))
    await writer.drain()
    reply = await read_socks5_reply(reader)
    if reply.reply_code != SOCKS_REPLY_SUCCEEDED:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"upstream SOCKS5 CONNECT failed: {reply.reply_code}")
    return reader, writer, reply

async def create_upstream_udp_association() -> tuple[asyncio.StreamReader, asyncio.StreamWriter, tuple[str, int]]:
    """Create a SOCKS5 UDP ASSOCIATE session with the upstream SOCKS5 server."""
    reader, writer = await open_upstream_tcp_connection()
    writer.write(bytes([SOCKS_VERSION, SOCKS_CMD_UDP_ASSOCIATE, 0x00]) + encode_socks5_address("0.0.0.0", 0))
    await writer.drain()
    reply = await read_socks5_reply(reader)
    if reply.reply_code != SOCKS_REPLY_SUCCEEDED:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"upstream SOCKS5 UDP ASSOCIATE failed: {reply.reply_code}")
    upstream_udp_host = reply.bind_host
    if upstream_udp_host in ("0.0.0.0", "::"):
        upstream_udp_host = UPSTREAM_SOCKS5_HOST
    return reader, writer, (upstream_udp_host, reply.bind_port)

async def resolve_udp_endpoint(host: str, port: int) -> tuple[int, tuple]:
    """Resolve the upstream UDP relay endpoint."""
    loop = asyncio.get_running_loop()
    address_infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    family, _, _, _, socket_address = address_infos[0]
    return family, socket_address

async def relay_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes from one stream to another with backpressure."""
    try:
        while True:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        if writer.can_write_eof():
            try:
                writer.write_eof()
            except OSError:
                pass
        writer.close()

async def relay_tcp_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    """Bidirectional TCP relay for CONNECT-style traffic."""
    await asyncio.gather(
        relay_stream(client_reader, upstream_writer),
        relay_stream(upstream_reader, client_writer),
    )

def parse_http_headers(header_lines: list[bytes]) -> HttpHeaders:
    """Parse HTTP headers into raw and lookup forms."""
    values: dict[bytes, list[bytes]] = {}
    for line in header_lines:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        values.setdefault(name.strip().lower(), []).append(value.strip())
    return HttpHeaders(raw_lines=header_lines, values=values)

def get_http_header(headers: HttpHeaders, name: bytes) -> bytes | None:
    """Return the last value of an HTTP header."""
    values = headers.values.get(name.lower())
    return values[-1] if values else None

def is_chunked_transfer(headers: HttpHeaders) -> bool:
    """Return True when Transfer-Encoding contains chunked."""
    transfer_encoding = get_http_header(headers, b"transfer-encoding")
    if not transfer_encoding:
        return False
    tokens = [token.strip().lower() for token in transfer_encoding.split(b",")]
    return b"chunked" in tokens

def http_connection_should_close(version: str, headers: HttpHeaders) -> bool:
    """Decide whether a client-side HTTP connection should close."""
    connection = get_http_header(headers, b"connection")
    if connection:
        tokens = [token.strip().lower() for token in connection.split(b",")]
        if b"close" in tokens:
            return True
        if b"keep-alive" in tokens:
            return False
    return version.upper() == "HTTP/1.0"

async def read_http_header_block(reader: asyncio.StreamReader, first_line: bytes) -> tuple[bytes, HttpHeaders]:
    """Read an HTTP header block with a size limit."""
    header_lines: list[bytes] = []
    total_size = len(first_line)
    while True:
        line = await reader.readline()
        if not line:
            raise ConnectionError("client closed during HTTP header read")
        total_size += len(line)
        if total_size > HEADER_LIMIT:
            raise ValueError("HTTP header too large")
        if line in (b"\r\n", b"\n"):
            return first_line, parse_http_headers(header_lines)
        header_lines.append(line)

async def stream_exact_bytes(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, remaining: int) -> None:
    """Stream a fixed number of bytes."""
    while remaining > 0:
        data = await reader.read(min(BUFFER_SIZE, remaining))
        if not data:
            raise ConnectionError("unexpected EOF while streaming fixed body")
        remaining -= len(data)
        writer.write(data)
        await writer.drain()

async def stream_chunked_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Stream an HTTP chunked body."""
    while True:
        chunk_size_line = await reader.readline()
        if not chunk_size_line:
            raise ConnectionError("unexpected EOF while streaming chunked body")
        writer.write(chunk_size_line)
        await writer.drain()
        chunk_size_text = chunk_size_line.split(b";", 1)[0].strip()
        chunk_size = int(chunk_size_text, 16)
        if chunk_size == 0:
            while True:
                trailer_line = await reader.readline()
                if not trailer_line:
                    raise ConnectionError("unexpected EOF while streaming trailers")
                writer.write(trailer_line)
                await writer.drain()
                if trailer_line in (b"\r\n", b"\n"):
                    return
        await stream_exact_bytes(reader, writer, chunk_size + 2)

async def stream_http_request_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, headers: HttpHeaders) -> None:
    """Stream an HTTP request body if present."""
    if is_chunked_transfer(headers):
        await stream_chunked_body(reader, writer)
        return
    content_length = get_http_header(headers, b"content-length")
    if content_length is not None:
        await stream_exact_bytes(reader, writer, int(content_length))

async def stream_http_response_body(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    request_method: str,
    status_code: int,
    headers: HttpHeaders,
) -> bool:
    """Stream an HTTP response body and report whether it had a known end."""
    if request_method.upper() == "HEAD":
        return True
    if 100 <= status_code < 200 or status_code in (204, 304):
        return True
    if is_chunked_transfer(headers):
        await stream_chunked_body(reader, writer)
        return True
    content_length = get_http_header(headers, b"content-length")
    if content_length is not None:
        await stream_exact_bytes(reader, writer, int(content_length))
        return True
    await relay_stream(reader, writer)
    return False

def write_filtered_request_headers(upstream_writer: asyncio.StreamWriter, headers: HttpHeaders, destination_host: str) -> None:
    """Forward end-to-end request headers to the upstream connection."""
    has_host_header = False
    for line in headers.raw_lines:
        name = line.partition(b":")[0].strip().lower()
        if name in HTTP_HOP_BY_HOP_HEADERS:
            continue
        if name == b"host":
            has_host_header = True
        upstream_writer.write(line)
    if not has_host_header:
        upstream_writer.write(f"Host: {destination_host}\r\n".encode("latin-1"))
    upstream_writer.write(b"Connection: close\r\n\r\n")

def write_filtered_response_headers(
    client_writer: asyncio.StreamWriter,
    status_line: bytes,
    headers: HttpHeaders,
    client_keep_alive: bool,
) -> None:
    """Forward end-to-end response headers to the client."""
    client_writer.write(status_line)
    for line in headers.raw_lines:
        name = line.partition(b":")[0].strip().lower()
        if name in HTTP_HOP_BY_HOP_HEADERS:
            continue
        client_writer.write(line)
    client_writer.write(b"Connection: keep-alive\r\n" if client_keep_alive else b"Connection: close\r\n")
    client_writer.write(b"\r\n")

async def handle_http_client(first_byte: bytes, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    """Handle HTTP forward proxy and HTTPS CONNECT traffic."""
    current_first_byte = first_byte
    while True:
        request_line = current_first_byte + await client_reader.readline()
        if request_line in (b"", b"\r\n", b"\n"):
            return
        request_line, request_headers = await read_http_header_block(client_reader, request_line)
        request_parts = request_line.decode("latin-1", errors="replace").strip().split()
        if len(request_parts) != 3:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return
        method, request_target, http_version = request_parts
        upper_method = method.upper()
        client_keep_alive = not http_connection_should_close(http_version, request_headers)
        if upper_method == "CONNECT":
            destination_host, destination_port = split_host_port(request_target, 443)
            try:
                upstream_reader, upstream_writer, _ = await connect_remote_via_upstream(destination_host, destination_port)
            except Exception:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                await client_writer.drain()
                return
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: windows-socks5-gateway\r\n\r\n")
            await client_writer.drain()
            await relay_tcp_tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
            return
        parsed_url = urlsplit(request_target)
        if parsed_url.scheme and parsed_url.hostname:
            if parsed_url.scheme.lower() == "https":
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nHTTPS proxying must use CONNECT.\r\n")
                await client_writer.drain()
                return
            destination_host = parsed_url.hostname
            destination_port = parsed_url.port or 80
            origin_target = parsed_url.path or "/"
            if parsed_url.query:
                origin_target += "?" + parsed_url.query
        else:
            host_header = get_http_header(request_headers, b"host")
            if not host_header:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await client_writer.drain()
                return
            destination_host, destination_port = split_host_port(host_header.decode("latin-1"), 80)
            origin_target = request_target
        try:
            upstream_reader, upstream_writer, _ = await connect_remote_via_upstream(destination_host, destination_port)
        except Exception:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return
        upstream_writer.write(f"{method} {origin_target} {http_version}\r\n".encode("latin-1"))
        write_filtered_request_headers(upstream_writer, request_headers, destination_host)
        await upstream_writer.drain()
        await stream_http_request_body(client_reader, upstream_writer, request_headers)
        await upstream_writer.drain()
        response_status_line = await upstream_reader.readline()
        if not response_status_line:
            upstream_writer.close()
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return
        response_status_line, response_headers = await read_http_header_block(upstream_reader, response_status_line)
        response_parts = response_status_line.decode("latin-1", errors="replace").strip().split()
        status_code = int(response_parts[1]) if len(response_parts) >= 2 and response_parts[1].isdigit() else 502
        response_has_known_end = (
            upper_method == "HEAD"
            or 100 <= status_code < 200
            or status_code in (204, 304)
            or is_chunked_transfer(response_headers)
            or get_http_header(response_headers, b"content-length") is not None
        )
        keep_client_connection = client_keep_alive and response_has_known_end
        write_filtered_response_headers(client_writer, response_status_line, response_headers, keep_client_connection)
        await client_writer.drain()
        response_completed_without_close = await stream_http_response_body(upstream_reader, client_writer, method, status_code, response_headers)
        await client_writer.drain()
        upstream_writer.close()
        await upstream_writer.wait_closed()
        if not keep_client_connection or not response_completed_without_close:
            return
        try:
            current_first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=IDLE_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return

class Socks5UdpAssociation:
    """Map one inbound SOCKS5 UDP association to one upstream SOCKS5 UDP association."""
    def __init__(
        self,
        control_reader: asyncio.StreamReader,
        control_writer: asyncio.StreamWriter,
        client_declared_host: str,
        client_declared_port: int,
    ):
        self.control_reader = control_reader
        self.control_writer = control_writer
        self.client_declared_host = client_declared_host
        self.client_declared_port = client_declared_port
        self.loop = asyncio.get_running_loop()
        peername = control_writer.get_extra_info("peername")
        sockname = control_writer.get_extra_info("sockname")
        self.client_tcp_ip = peername[0]
        self.local_tcp_ip = sockname[0]
        self.client_udp_endpoint: tuple[str, int] | None = None
        self.client_udp_socket: socket.socket | None = None
        self.upstream_udp_socket: socket.socket | None = None
        self.upstream_control_reader: asyncio.StreamReader | None = None
        self.upstream_control_writer: asyncio.StreamWriter | None = None
        self.upstream_udp_endpoint: tuple | None = None

    async def start(self) -> None:
        try:
            await self.prepare_client_udp_socket()
            await self.prepare_upstream_udp_association()
        except Exception:
            self.control_writer.write(build_socks5_reply(SOCKS_REPLY_COMMAND_NOT_SUPPORTED))
            await self.control_writer.drain()
            return
        assert self.client_udp_socket is not None
        local_udp_port = self.client_udp_socket.getsockname()[1]
        reply_host = self.local_tcp_ip
        if reply_host in ("0.0.0.0", "::"):
            reply_host = "127.0.0.1" if ":" not in self.client_tcp_ip else "::1"
        self.control_writer.write(build_socks5_reply(SOCKS_REPLY_SUCCEEDED, reply_host, local_udp_port))
        await self.control_writer.drain()
        if self.client_declared_host not in ("0.0.0.0", "::") and self.client_declared_port != 0:
            self.client_udp_endpoint = (self.client_declared_host, self.client_declared_port)
        client_to_upstream_task = asyncio.create_task(self.client_to_upstream_loop())
        upstream_to_client_task = asyncio.create_task(self.upstream_to_client_loop())
        control_task = asyncio.create_task(self.control_reader.read())
        tasks = {client_to_upstream_task, upstream_to_client_task, control_task}
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.close_sockets()

    async def prepare_client_udp_socket(self) -> None:
        client_family = socket.AF_INET6 if ":" in self.client_tcp_ip else socket.AF_INET
        bind_host = "::" if client_family == socket.AF_INET6 else "0.0.0.0"
        self.client_udp_socket = socket.socket(client_family, socket.SOCK_DGRAM)
        self.client_udp_socket.setblocking(False)
        if client_family == socket.AF_INET6:
            self.client_udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.client_udp_socket.bind((bind_host, 0))

    async def prepare_upstream_udp_association(self) -> None:
        self.upstream_control_reader, self.upstream_control_writer, upstream_udp_endpoint = await create_upstream_udp_association()
        upstream_family, upstream_socket_address = await resolve_udp_endpoint(upstream_udp_endpoint[0], upstream_udp_endpoint[1])
        self.upstream_udp_endpoint = upstream_socket_address
        self.upstream_udp_socket = socket.socket(upstream_family, socket.SOCK_DGRAM)
        self.upstream_udp_socket.setblocking(False)
        if upstream_family == socket.AF_INET6:
            self.upstream_udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.upstream_udp_socket.bind(("::", 0))
        else:
            self.upstream_udp_socket.bind(("0.0.0.0", 0))

    async def client_to_upstream_loop(self) -> None:
        assert self.client_udp_socket is not None
        assert self.upstream_udp_socket is not None
        assert self.upstream_udp_endpoint is not None
        while True:
            datagram, source_endpoint = await self.loop.sock_recvfrom(self.client_udp_socket, 65535)
            source_ip, source_port = source_endpoint[:2]
            if source_ip != self.client_tcp_ip:
                continue
            if self.client_udp_endpoint is None:
                self.client_udp_endpoint = (source_ip, source_port)
            if (source_ip, source_port) != self.client_udp_endpoint:
                continue
            if decode_socks5_udp_datagram(datagram) is None:
                continue
            await self.loop.sock_sendto(self.upstream_udp_socket, datagram, self.upstream_udp_endpoint)

    async def upstream_to_client_loop(self) -> None:
        assert self.client_udp_socket is not None
        assert self.upstream_udp_socket is not None
        while True:
            datagram, _ = await self.loop.sock_recvfrom(self.upstream_udp_socket, 65535)
            if self.client_udp_endpoint is None:
                continue
            await self.loop.sock_sendto(self.client_udp_socket, datagram, self.client_udp_endpoint)

    def close_sockets(self) -> None:
        if self.client_udp_socket is not None:
            self.client_udp_socket.close()
        if self.upstream_udp_socket is not None:
            self.upstream_udp_socket.close()
        if self.upstream_control_writer is not None:
            self.upstream_control_writer.close()

async def handle_socks5_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    """Handle inbound SOCKS5 TCP CONNECT and UDP ASSOCIATE."""
    method_count = (await client_reader.readexactly(1))[0]
    methods = await client_reader.readexactly(method_count)
    if SOCKS_METHOD_NO_AUTH not in methods:
        client_writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NO_ACCEPTABLE]))
        await client_writer.drain()
        return
    client_writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]))
    await client_writer.drain()
    version, command, reserved, address_type = await client_reader.readexactly(4)
    if version != SOCKS_VERSION or reserved != 0x00:
        return
    destination_host, destination_port = await read_socks5_address(client_reader, address_type)
    if command == SOCKS_CMD_CONNECT:
        try:
            upstream_reader, upstream_writer, upstream_reply = await connect_remote_via_upstream(destination_host, destination_port)
        except asyncio.TimeoutError:
            client_writer.write(build_socks5_reply(SOCKS_REPLY_HOST_UNREACHABLE))
            await client_writer.drain()
            return
        except OSError:
            client_writer.write(build_socks5_reply(SOCKS_REPLY_CONNECTION_REFUSED))
            await client_writer.drain()
            return
        except Exception:
            client_writer.write(build_socks5_reply(SOCKS_REPLY_GENERAL_FAILURE))
            await client_writer.drain()
            return
        client_writer.write(build_socks5_reply(SOCKS_REPLY_SUCCEEDED, upstream_reply.bind_host, upstream_reply.bind_port))
        await client_writer.drain()
        await relay_tcp_tunnel(client_reader, client_writer, upstream_reader, upstream_writer)
        return
    if command == SOCKS_CMD_UDP_ASSOCIATE:
        association = Socks5UdpAssociation(client_reader, client_writer, destination_host, destination_port)
        await association.start()
        return
    client_writer.write(build_socks5_reply(SOCKS_REPLY_COMMAND_NOT_SUPPORTED))
    await client_writer.drain()

async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    """Detect inbound protocol and dispatch to HTTP or SOCKS5 handler."""
    acquired_connection_slot = False
    try:
        await connection_semaphore.acquire()
        acquired_connection_slot = True
        configure_tcp_socket(client_writer.get_extra_info("socket"))
        first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT)
        if first_byte == bytes([SOCKS_VERSION]):
            await handle_socks5_client(client_reader, client_writer)
        else:
            await handle_http_client(first_byte, client_reader, client_writer)
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError, ValueError) as error:
        logging.debug("client closed or protocol error: %s", error)
    finally:
        if acquired_connection_slot:
            connection_semaphore.release()
        client_writer.close()
        try:
            await client_writer.wait_closed()
        except Exception:
            pass

async def run_server(config: ServerConfig) -> None:
    """Start IPv4 and IPv6 listeners."""
    global connection_semaphore
    connection_semaphore = asyncio.Semaphore(config.max_connections)
    servers = []
    ipv4_socket = create_listen_socket(socket.AF_INET, "0.0.0.0", config.listen_port, config.backlog)
    ipv4_server = await asyncio.start_server(handle_client, sock=ipv4_socket, limit=STREAM_LIMIT, start_serving=True)
    servers.append(ipv4_server)
    try:
        ipv6_socket = create_listen_socket(socket.AF_INET6, "::", config.listen_port, config.backlog)
        ipv6_server = await asyncio.start_server(handle_client, sock=ipv6_socket, limit=STREAM_LIMIT, start_serving=True)
        servers.append(ipv6_server)
        logging.info("listening on 0.0.0.0:%s and [::]:%s", config.listen_port, config.listen_port)
    except OSError as error:
        logging.warning("IPv6 listener disabled: %s", error)
        logging.info("listening on 0.0.0.0:%s", config.listen_port)
    logging.info("upstream SOCKS5 = %s:%s, max_connections=%s", UPSTREAM_SOCKS5_HOST, UPSTREAM_SOCKS5_PORT, config.max_connections)
    await asyncio.gather(*(server.serve_forever() for server in servers))

def ask_listen_port() -> int:
    """Ask for local listen port."""
    raw_value = input(f"Enter local listen port [{DEFAULT_LISTEN_PORT}]: ").strip()
    if not raw_value:
        return DEFAULT_LISTEN_PORT
    port = int(raw_value)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port

def main() -> None:
    """Program entry point."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    listen_port = ask_listen_port()
    logging.info("starting Windows SOCKS5 gateway")
    logging.info("inbound: HTTP, HTTPS CONNECT, SOCKS5 TCP, SOCKS5 UDP")
    logging.info("outbound: upstream SOCKS5 only")
    config = ServerConfig(listen_port=listen_port)
    asyncio.run(run_server(config))

if __name__ == "__main__":
    main()
