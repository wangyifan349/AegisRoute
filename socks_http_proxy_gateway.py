#!/usr/bin/env python3
import asyncio
import logging
import multiprocessing
import os
import resource
import socket
import struct
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
import uvloop
# ============================================================
# Global performance defaults
# ============================================================
BUFFER_SIZE = 64 * 1024
STREAM_LIMIT = 256 * 1024
HEADER_LIMIT = 64 * 1024
HANDSHAKE_TIMEOUT = 10
CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 600
MAX_CONCURRENT_CONNECTIONS = 50000
LISTEN_BACKLOG = 8192
NOFILE_LIMIT = 1048576
UDP_DNS_CACHE_TTL = 60
# ============================================================
# SOCKS5 constants from RFC 1928
# ============================================================
SOCKS_VERSION = 0x05
SOCKS_METHOD_NO_AUTH = 0x00
SOCKS_METHOD_NO_ACCEPTABLE = 0xFF
SOCKS_CMD_CONNECT = 0x01
SOCKS_CMD_BIND = 0x02
SOCKS_CMD_UDP_ASSOCIATE = 0x03
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04
# ============================================================
# HTTP hop-by-hop headers should not be forwarded by proxies
# ============================================================
HTTP_HOP_BY_HOP_HEADERS = {
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"upgrade",
}
# ============================================================
# Runtime globals initialized inside each worker
# ============================================================
connection_semaphore: asyncio.Semaphore
@dataclass
class HttpHeaders:
    raw_lines: list[bytes]
    values: dict[bytes, list[bytes]]
@dataclass
class ServerConfig:
    port: int
    workers: int
    max_connections: int = MAX_CONCURRENT_CONNECTIONS
    backlog: int = LISTEN_BACKLOG
    nofile: int = NOFILE_LIMIT
# ============================================================
# System tuning helpers
# ============================================================
def raise_file_descriptor_limit(target_limit: int) -> None:
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    new_soft_limit = min(max(soft_limit, target_limit), hard_limit)
    resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft_limit, hard_limit))
def configure_tcp_socket(tcp_socket: socket.socket) -> None:
    tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
    tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
    tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
def create_listen_socket(address_family: int, host: str, port: int, backlog: int, reuse_port: bool) -> socket.socket:
    listen_socket = socket.socket(address_family, socket.SOCK_STREAM)
    listen_socket.setblocking(False)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuse_port:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if address_family == socket.AF_INET6:
        listen_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listen_socket.bind((host, port))
    listen_socket.listen(backlog)
    return listen_socket
# ============================================================
# Generic network helpers
# ============================================================
def split_host_port(authority: str, default_port: int) -> tuple[str, int]:
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
async def connect_remote(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(asyncio.open_connection(host, port, limit=STREAM_LIMIT), timeout=CONNECT_TIMEOUT)
async def relay_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
async def relay_tcp_tunnel(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter) -> None:
    configure_tcp_socket(remote_writer.get_extra_info("socket"))
    await asyncio.gather(relay_stream(client_reader, remote_writer), relay_stream(remote_reader, client_writer))
# ============================================================
# SOCKS5 address helpers
# ============================================================
def encode_socks5_address(address: str, port: int) -> bytes:
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
def socks5_reply(reply_code: int, bind_host: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    return bytes([SOCKS_VERSION, reply_code, 0x00]) + encode_socks5_address(bind_host, bind_port)
async def read_socks5_address(reader: asyncio.StreamReader, address_type: int) -> tuple[str, int]:
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
def decode_socks5_udp_datagram(datagram: bytes):
    if len(datagram) < 4:
        return None
    reserved, fragment_number, address_type = struct.unpack("!HBB", datagram[:4])
    if reserved != 0 or fragment_number != 0:
        return None
    offset = 4
    if address_type == SOCKS_ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, datagram[offset:offset + 4])
        offset += 4
    elif address_type == SOCKS_ATYP_DOMAIN:
        domain_length = datagram[offset]
        offset += 1
        host = datagram[offset:offset + domain_length].decode("idna")
        offset += domain_length
    elif address_type == SOCKS_ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, datagram[offset:offset + 16])
        offset += 16
    else:
        return None
    port = struct.unpack("!H", datagram[offset:offset + 2])[0]
    offset += 2
    return host, port, datagram[offset:]
# ============================================================
# HTTP parsing helpers
# ============================================================
def parse_http_headers(header_lines: list[bytes]) -> HttpHeaders:
    values: dict[bytes, list[bytes]] = {}
    for line in header_lines:
        if line in (b"\r\n", b"\n"):
            continue
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        normalized_name = name.strip().lower()
        values.setdefault(normalized_name, []).append(value.strip())
    return HttpHeaders(raw_lines=header_lines, values=values)
def get_http_header(headers: HttpHeaders, name: bytes) -> bytes | None:
    values = headers.values.get(name.lower())
    if not values:
        return None
    return values[-1]
def is_chunked_transfer(headers: HttpHeaders) -> bool:
    transfer_encoding = get_http_header(headers, b"transfer-encoding")
    if not transfer_encoding:
        return False
    tokens = [token.strip().lower() for token in transfer_encoding.split(b",")]
    return b"chunked" in tokens
def http_connection_should_close(version: str, headers: HttpHeaders) -> bool:
    connection = get_http_header(headers, b"connection")
    if connection:
        tokens = [token.strip().lower() for token in connection.split(b",")]
        if b"close" in tokens:
            return True
        if b"keep-alive" in tokens:
            return False
    return version.upper() == "HTTP/1.0"
async def read_http_header_block(reader: asyncio.StreamReader, first_line: bytes) -> tuple[bytes, HttpHeaders]:
    header_lines: list[bytes] = []
    total_size = len(first_line)
    while True:
        line = await reader.readline()
        if not line:
            raise ConnectionError()
        total_size += len(line)
        if total_size > HEADER_LIMIT:
            raise ValueError()
        if line in (b"\r\n", b"\n"):
            return first_line, parse_http_headers(header_lines)
        header_lines.append(line)
async def stream_exact_bytes(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, remaining: int) -> None:
    while remaining > 0:
        data = await reader.read(min(BUFFER_SIZE, remaining))
        if not data:
            raise ConnectionError()
        remaining -= len(data)
        writer.write(data)
        await writer.drain()
async def stream_chunked_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        chunk_size_line = await reader.readline()
        if not chunk_size_line:
            raise ConnectionError()
        writer.write(chunk_size_line)
        await writer.drain()
        chunk_size_text = chunk_size_line.split(b";", 1)[0].strip()
        chunk_size = int(chunk_size_text, 16)
        if chunk_size == 0:
            while True:
                trailer_line = await reader.readline()
                if not trailer_line:
                    raise ConnectionError()
                writer.write(trailer_line)
                await writer.drain()
                if trailer_line in (b"\r\n", b"\n"):
                    return
        await stream_exact_bytes(reader, writer, chunk_size + 2)
async def stream_http_request_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, headers: HttpHeaders) -> None:
    if is_chunked_transfer(headers):
        await stream_chunked_body(reader, writer)
        return
    content_length = get_http_header(headers, b"content-length")
    if content_length is not None:
        await stream_exact_bytes(reader, writer, int(content_length))
async def stream_http_response_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, request_method: str, status_code: int, headers: HttpHeaders) -> bool:
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
def write_filtered_request_headers(remote_writer: asyncio.StreamWriter, headers: HttpHeaders, destination_host: str) -> None:
    has_host_header = False
    for line in headers.raw_lines:
        name = line.partition(b":")[0].strip().lower()
        if name in HTTP_HOP_BY_HOP_HEADERS:
            continue
        if name == b"host":
            has_host_header = True
        remote_writer.write(line)
    if not has_host_header:
        remote_writer.write(f"Host: {destination_host}\r\n".encode("latin-1"))
    remote_writer.write(b"Connection: close\r\n")
    remote_writer.write(b"\r\n")
def write_filtered_response_headers(client_writer: asyncio.StreamWriter, status_line: bytes, headers: HttpHeaders, client_keep_alive: bool) -> None:
    client_writer.write(status_line)
    for line in headers.raw_lines:
        name = line.partition(b":")[0].strip().lower()
        if name in HTTP_HOP_BY_HOP_HEADERS:
            continue
        client_writer.write(line)
    client_writer.write(b"Connection: keep-alive\r\n" if client_keep_alive else b"Connection: close\r\n")
    client_writer.write(b"\r\n")
# ============================================================
# HTTP / HTTPS CONNECT handler
# ============================================================
async def handle_http_client(first_byte, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
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
        client_keep_alive = not http_connection_should_close(http_version, request_headers)
        if method.upper() == "CONNECT":
            destination_host, destination_port = split_host_port(request_target, 443)
            try:
                remote_reader, remote_writer = await connect_remote(destination_host, destination_port)
            except Exception:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                await client_writer.drain()
                return
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: py-proxy-gateway\r\n\r\n")
            await client_writer.drain()
            await relay_tcp_tunnel(client_reader, client_writer, remote_reader, remote_writer)
            return
        parsed_url = urlsplit(request_target)
        if parsed_url.scheme and parsed_url.hostname:
            destination_host = parsed_url.hostname
            destination_port = parsed_url.port or (443 if parsed_url.scheme.lower() == "https" else 80)
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
            remote_reader, remote_writer = await connect_remote(destination_host, destination_port)
        except Exception:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return
        configure_tcp_socket(remote_writer.get_extra_info("socket"))
        remote_writer.write(f"{method} {origin_target} {http_version}\r\n".encode("latin-1"))
        write_filtered_request_headers(remote_writer, request_headers, destination_host)
        await remote_writer.drain()
        await stream_http_request_body(client_reader, remote_writer, request_headers)
        await remote_writer.drain()
        response_status_line = await remote_reader.readline()
        if not response_status_line:
            remote_writer.close()
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return
        response_status_line, response_headers = await read_http_header_block(remote_reader, response_status_line)
        response_parts = response_status_line.decode("latin-1", errors="replace").strip().split()
        status_code = int(response_parts[1]) if len(response_parts) >= 2 and response_parts[1].isdigit() else 502
        response_has_known_end = (method.upper() == "HEAD" or 100 <= status_code < 200 or status_code in (204, 304) or is_chunked_transfer(response_headers) or get_http_header(response_headers, b"content-length") is not None)
        keep_client_connection = client_keep_alive and response_has_known_end
        write_filtered_response_headers(client_writer, response_status_line, response_headers, keep_client_connection)
        await client_writer.drain()
        response_completed_without_close = await stream_http_response_body(remote_reader, client_writer, method, status_code, response_headers)
        await client_writer.drain()
        remote_writer.close()
        await remote_writer.wait_closed()
        if not keep_client_connection or not response_completed_without_close:
            return
        try:
            current_first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=IDLE_TIMEOUT)
        except Exception:
            return
# ============================================================
# SOCKS5 UDP ASSOCIATE handler
# ============================================================
class UdpAssociation:
    def __init__(self, control_reader, control_writer, client_declared_host, client_declared_port):
        self.control_reader = control_reader
        self.control_writer = control_writer
        self.client_declared_host = client_declared_host
        self.client_declared_port = client_declared_port
        self.loop = asyncio.get_running_loop()
        self.client_endpoint = None
        self.client_tcp_ip = control_writer.get_extra_info("peername")[0]
        self.local_tcp_ip = control_writer.get_extra_info("sockname")[0]
        self.client_udp_socket = None
        self.outbound_ipv4_socket = None
        self.outbound_ipv6_socket = None
        self.dns_cache = {}
    async def start(self):
        client_family = socket.AF_INET6 if ":" in self.client_tcp_ip else socket.AF_INET
        client_bind_host = "::" if client_family == socket.AF_INET6 else "0.0.0.0"
        self.client_udp_socket = socket.socket(client_family, socket.SOCK_DGRAM)
        self.client_udp_socket.setblocking(False)
        self.client_udp_socket.bind((client_bind_host, 0))
        udp_port = self.client_udp_socket.getsockname()[1]
        reply_host = self.local_tcp_ip
        if reply_host in ("0.0.0.0", "::"):
            reply_host = client_bind_host
        self.control_writer.write(socks5_reply(0x00, reply_host, udp_port))
        await self.control_writer.drain()
        self.outbound_ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.outbound_ipv4_socket.setblocking(False)
        self.outbound_ipv4_socket.bind(("0.0.0.0", 0))
        self.outbound_ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.outbound_ipv6_socket.setblocking(False)
        self.outbound_ipv6_socket.bind(("::", 0))
        await asyncio.wait({asyncio.create_task(self.client_udp_loop()), asyncio.create_task(self.outbound_udp_loop(self.outbound_ipv4_socket)), asyncio.create_task(self.outbound_udp_loop(self.outbound_ipv6_socket)), asyncio.create_task(self.control_reader.read())}, return_when=asyncio.FIRST_COMPLETED)
        self.client_udp_socket.close()
        self.outbound_ipv4_socket.close()
        self.outbound_ipv6_socket.close()
    async def resolve_udp_destination(self, host, port):
        cache_key = (host, port)
        now = time.monotonic()
        cached = self.dns_cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        try:
            socket.inet_pton(socket.AF_INET, host)
            return (socket.AF_INET, host)
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return (socket.AF_INET6, host)
        except OSError:
            pass
        infos = await self.loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        family, _, _, _, addr = infos[0]
        return (family, addr[0])
    async def client_udp_loop(self):
        while True:
            datagram, source_endpoint = await self.loop.sock_recvfrom(self.client_udp_socket, 65535)
            source_ip, source_port = source_endpoint[:2]
            if source_ip != self.client_tcp_ip:
                continue
            decoded = decode_socks5_udp_datagram(datagram)
            if not decoded:
                continue
            host, port, payload = decoded
            family, resolved = await self.resolve_udp_destination(host, port)
            sock = self.outbound_ipv4_socket if family == socket.AF_INET else self.outbound_ipv6_socket
            await self.loop.sock_sendto(sock, payload, (resolved, port))
    async def outbound_udp_loop(self, outbound_socket):
        while True:
            datagram, source_endpoint = await self.loop.sock_recvfrom(outbound_socket, 65535)
            if not self.client_endpoint:
                continue
            response = b"\x00\x00\x00" + encode_socks5_address(source_endpoint[0], source_endpoint[1]) + datagram
            await self.loop.sock_sendto(self.client_udp_socket, response, self.client_endpoint)
# ============================================================
# SOCKS5 TCP / UDP handler
# ============================================================
async def handle_socks5_client(client_reader, client_writer):
    method_count = (await client_reader.readexactly(1))[0]
    methods = await client_reader.readexactly(method_count)
    if SOCKS_METHOD_NO_AUTH not in methods:
        client_writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NO_ACCEPTABLE]))
        await client_writer.drain()
        return
    client_writer.write(bytes([SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]))
    await client_writer.drain()
    version, command, _, address_type = await client_reader.readexactly(4)
    destination_host, destination_port = await read_socks5_address(client_reader, address_type)
    if command == SOCKS_CMD_CONNECT:
        try:
            remote_reader, remote_writer = await connect_remote(destination_host, destination_port)
        except Exception:
            client_writer.write(socks5_reply(0x05))
            await client_writer.drain()
            return
        client_writer.write(socks5_reply(0x00))
        await client_writer.drain()
        await relay_tcp_tunnel(client_reader, client_writer, remote_reader, remote_writer)
        return
    if command == SOCKS_CMD_UDP_ASSOCIATE:
        assoc = UdpAssociation(client_reader, client_writer, destination_host, destination_port)
        await assoc.start()
        return
    client_writer.write(socks5_reply(0x07))
    await client_writer.drain()
# ============================================================
# Unified entry
# ============================================================
async def handle_client(client_reader, client_writer):
    acquired = False
    try:
        await connection_semaphore.acquire()
        acquired = True
        first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT)
        if first_byte == b"\x05":
            await handle_socks5_client(client_reader, client_writer)
        else:
            await handle_http_client(first_byte, client_reader, client_writer)
    finally:
        if acquired:
            connection_semaphore.release()
        client_writer.close()
# ============================================================
# Server startup
# ============================================================
async def run_server(config):
    global connection_semaphore
    connection_semaphore = asyncio.Semaphore(config.max_connections)
    ipv4_socket = create_listen_socket(socket.AF_INET, "0.0.0.0", config.port, config.backlog, True)
    ipv6_socket = create_listen_socket(socket.AF_INET6, "::", config.port, config.backlog, True)
    ipv4_server = await asyncio.start_server(handle_client, sock=ipv4_socket)
    ipv6_server = await asyncio.start_server(handle_client, sock=ipv6_socket)
    async with ipv4_server, ipv6_server:
        await asyncio.gather(ipv4_server.serve_forever(), ipv6_server.serve_forever())
def main():
    port = 1080
    workers = 1
    config = ServerConfig(port=port, workers=workers)
    if workers <= 1:
        asyncio.run(run_server(config))
if __name__ == "__main__":
    main()
