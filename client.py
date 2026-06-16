#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
"""
AegisRoute Client
Copyright (C) 2026  WangYiFan
This file is part of AegisRoute.
AegisRoute is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3 as published by the
Free Software Foundation.
AegisRoute is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License v3.0 for more details.
Project:
    https://github.com/wangyifan349/AegisRoute
Install dependency:
    pip install cryptography
Run:
    python client.py
"""
import asyncio
import functools
import getpass
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, TextIO, Tuple
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HTTP_PROXY_HOST = "127.0.0.1"               # Local HTTP proxy listen host
HTTP_PROXY_PORT = 8080                      # Local HTTP proxy listen port
HTTPS_PROXY_HOST = "127.0.0.1"              # Local HTTPS CONNECT proxy listen host
HTTPS_PROXY_PORT = 8081                     # Local HTTPS CONNECT proxy listen port
SOCKS5_HOST = "127.0.0.1"                   # Local SOCKS5 TCP and UDP listen host
SOCKS5_PORT = 1080                          # Local SOCKS5 TCP and UDP listen port
CLIENT_LOG_FILE = "client.log"              # Client log file name

TCP_MAGIC = b"PYPX-TCP-1"                  # TCP protocol marker
UDP_MAGIC = b"PYPX-UDP-1"                  # UDP protocol marker
TCP_AAD = b"pyproxy-tcp-aead-v1"           # AEAD associated data for TCP
UDP_AAD = b"pyproxy-udp-aead-v1"           # AEAD associated data for UDP

FRAME_CONNECT = 1                           # Client requests target connection
FRAME_OK = 2                                # Server accepts target connection
FRAME_ERR = 3                               # Server returns a short error
FRAME_DATA = 4                              # Encrypted stream data frame
FRAME_EOF = 5                               # Stream close frame
FRAME_PING = 6                              # Keep-alive ping frame
FRAME_PONG = 7                              # Keep-alive pong frame

MAX_FRAME_SIZE = 1024 * 1024                # Maximum encrypted TCP frame size
TCP_CHUNK_SIZE = 64 * 1024                  # Stream read chunk size
UDP_SESSION_TTL = 120                       # UDP session idle timeout in seconds
KEEPALIVE_SECONDS = 25                      # TCP keep-alive interval in seconds


class EventLogger:
    def __init__(self, enabled: bool, file_path: str):
        self.enabled = enabled              # True means log records are kept
        self.file_path = file_path          # Log file path
        self.lock = threading.Lock()        # File write lock across threads
        self.file_handle: Optional[TextIO] = None  # Open file handle

        if self.enabled:
            self.file_handle = open(self.file_path, "a", encoding="utf-8")  # Append mode

    def log(self, message: str) -> None:
        if not self.enabled:
            return

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")  # Local timestamp
        line = f"[{timestamp}] {message}\n"            # One log line

        with self.lock:
            if self.file_handle is None:
                return
            self.file_handle.write(line)
            self.file_handle.flush()

    def close(self) -> None:
        if self.file_handle is None:
            return

        with self.lock:
            self.file_handle.close()
            self.file_handle = None


def derive_tcp_key(password: str, salt: bytes) -> bytes:
    base_key = hashlib.sha256(password.encode("utf-8")).digest()  # Stable password hash
    key_deriver = HKDF(                                            # HKDF session key derivation
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"pyproxy-tcp-key-v1",
    )
    return key_deriver.derive(base_key)


def derive_udp_key(password: str) -> bytes:
    key_text = "pyproxy-udp-key-v1:" + password      # Domain-separated UDP key text
    return hashlib.sha256(key_text.encode("utf-8")).digest()


class SecureChannel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, key: bytes, is_client: bool):
        self.reader = reader                         # Encrypted TCP reader
        self.writer = writer                         # Encrypted TCP writer
        self.aead = ChaCha20Poly1305(key)            # AEAD cipher instance
        self.send_counter = 0                        # Outbound nonce counter
        self.recv_counter = 0                        # Inbound nonce counter
        self.write_lock = asyncio.Lock()             # Serialize frame writes

        if is_client:
            self.send_prefix = b"C2S0"               # Client-to-server nonce prefix
            self.recv_prefix = b"S2C0"               # Server-to-client nonce prefix
        else:
            self.send_prefix = b"S2C0"               # Server-to-client nonce prefix
            self.recv_prefix = b"C2S0"               # Client-to-server nonce prefix

    def build_nonce(self, prefix: bytes, counter: int) -> bytes:
        return prefix + counter.to_bytes(8, "big")   # 12-byte ChaCha20-Poly1305 nonce

    async def send(self, frame_type: int, payload: bytes = b"") -> None:
        plain_frame = bytes([frame_type]) + payload   # Frame type plus payload

        async with self.write_lock:
            nonce = self.build_nonce(self.send_prefix, self.send_counter)  # Unique nonce
            self.send_counter += 1
            encrypted_frame = self.aead.encrypt(nonce, plain_frame, TCP_AAD)  # AEAD encrypt
            frame_size = struct.pack("!I", len(encrypted_frame))             # Network order size
            self.writer.write(frame_size + encrypted_frame)
            await self.writer.drain()

    async def recv(self) -> Tuple[Optional[int], bytes]:
        raw_size = await self.reader.read(4)          # Read encrypted frame size
        if not raw_size:
            return None, b""
        if len(raw_size) != 4:
            raise ConnectionError("broken frame header")

        frame_size = struct.unpack("!I", raw_size)[0]  # Decode frame size
        if frame_size <= 0 or frame_size > MAX_FRAME_SIZE:
            raise ConnectionError("invalid frame size")

        encrypted_frame = await self.reader.readexactly(frame_size)  # Read encrypted frame
        nonce = self.build_nonce(self.recv_prefix, self.recv_counter)  # Expected nonce
        self.recv_counter += 1
        plain_frame = self.aead.decrypt(nonce, encrypted_frame, TCP_AAD)  # AEAD decrypt
        return plain_frame[0], plain_frame[1:]


async def client_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, password: str) -> SecureChannel:
    salt = os.urandom(16)                              # Random session salt
    writer.write(TCP_MAGIC + salt)
    await writer.drain()
    key = derive_tcp_key(password, salt)               # Per-connection TCP key
    return SecureChannel(reader, writer, key, is_client=True)


async def open_secure_channel(config: dict) -> SecureChannel:
    server_host = str(config["server_host"])            # Remote server host
    server_port = int(config["server_port"])            # Remote server port
    reader, writer = await asyncio.open_connection(server_host, server_port)
    tune_tcp_writer(writer)
    return await client_handshake(reader, writer, str(config["password"]))


async def send_connect(channel: SecureChannel, host: str, port: int) -> None:
    request = {"host": host, "port": int(port)}        # Target connect request
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    await channel.send(FRAME_CONNECT, payload)

    while True:
        frame_type, data = await channel.recv()          # Wait for server connect result
        if frame_type == FRAME_OK:
            return
        if frame_type == FRAME_ERR:
            raise ConnectionError(data.decode("utf-8", "replace"))
        if frame_type == FRAME_PING:
            await channel.send(FRAME_PONG)
            continue
        if frame_type is None:
            raise ConnectionError("server closed connection")


def udp_encrypt(key: bytes, header: dict, payload: bytes) -> bytes:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")  # Compact JSON header
    plain_packet = struct.pack("!H", len(header_bytes)) + header_bytes + payload  # Header length + data
    nonce = os.urandom(12)                                    # Random AEAD nonce for UDP
    encrypted_packet = ChaCha20Poly1305(key).encrypt(nonce, plain_packet, UDP_AAD)  # AEAD encrypt
    return UDP_MAGIC + nonce + encrypted_packet


def udp_decrypt(key: bytes, packet: bytes) -> Tuple[dict, bytes]:
    if not packet.startswith(UDP_MAGIC):
        raise ValueError("bad udp protocol magic")

    nonce_start = len(UDP_MAGIC)                              # Nonce offset
    nonce_end = nonce_start + 12                              # Nonce end offset
    nonce = packet[nonce_start:nonce_end]                     # UDP AEAD nonce
    encrypted_packet = packet[nonce_end:]                     # UDP encrypted body
    plain_packet = ChaCha20Poly1305(key).decrypt(nonce, encrypted_packet, UDP_AAD)  # AEAD decrypt
    header_size = struct.unpack("!H", plain_packet[:2])[0]    # JSON header length
    header_start = 2                                          # Header data start
    header_end = header_start + header_size                   # Header data end
    header = json.loads(plain_packet[header_start:header_end].decode("utf-8"))  # Decode JSON header
    payload = plain_packet[header_end:]                       # Remaining UDP payload
    return header, payload


def tune_tcp_writer(writer: asyncio.StreamWriter) -> None:
    socket_object = writer.get_extra_info("socket")           # Raw socket from stream writer
    if socket_object is None:
        return

    socket_object.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Reduce latency
    socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # Enable TCP keepalive


async def close_writer(writer: asyncio.StreamWriter) -> None:
    if writer.is_closing():
        return

    writer.close()                                            # Start stream close
    await writer.wait_closed()                                # Wait until closed


async def keepalive(channel: SecureChannel) -> None:
    while True:
        await asyncio.sleep(KEEPALIVE_SECONDS)
        await channel.send(FRAME_PING)


async def local_to_channel(local_reader: asyncio.StreamReader, channel: SecureChannel) -> None:
    while True:
        data = await local_reader.read(TCP_CHUNK_SIZE)         # Read from local app
        if not data:
            await channel.send(FRAME_EOF)
            return
        await channel.send(FRAME_DATA, data)


async def channel_to_local(channel: SecureChannel, local_writer: asyncio.StreamWriter) -> None:
    while True:
        frame_type, data = await channel.recv()                # Read encrypted server frame
        if frame_type is None:
            return
        if frame_type == FRAME_EOF:
            return
        if frame_type == FRAME_DATA:
            local_writer.write(data)
            await local_writer.drain()
            continue
        if frame_type == FRAME_PING:
            await channel.send(FRAME_PONG)
            continue
        if frame_type == FRAME_PONG:
            continue
        if frame_type == FRAME_ERR:
            raise ConnectionError(data.decode("utf-8", "replace"))
        return


async def run_tunnel(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    channel: SecureChannel,
    first_payload: bytes = b"",
) -> None:
    if first_payload:
        await channel.send(FRAME_DATA, first_payload)

    keep_task = asyncio.create_task(keepalive(channel))        # Periodic keep-alive task
    upload_task = asyncio.create_task(local_to_channel(local_reader, channel))  # Local to server
    download_task = asyncio.create_task(channel_to_local(channel, local_writer))  # Server to local
    relay_tasks = [upload_task, download_task]                 # TCP relay task list

    await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)

    keep_task.cancel()                                        # Stop keep-alive task
    upload_task.cancel()                                      # Stop upload task if alive
    download_task.cancel()                                    # Stop download task if alive
    await asyncio.gather(keep_task, upload_task, download_task, return_exceptions=True)


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    host_port_text = value.strip()                            # Raw host:port text

    if host_port_text.startswith("["):
        closing_index = host_port_text.index("]")             # IPv6 closing bracket
        host = host_port_text[1:closing_index]
        rest_text = host_port_text[closing_index + 1:]
        if rest_text.startswith(":"):
            port = int(rest_text[1:])
        else:
            port = default_port
        return host, port

    if ":" in host_port_text:
        host, port_text = host_port_text.rsplit(":", 1)
        return host, int(port_text)

    return host_port_text, default_port


def build_http_error(status: str, message: str) -> bytes:
    body = (message + "\n").encode("utf-8")                  # HTTP error body
    header_text = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    )
    return header_text.encode("latin1") + body


async def handle_http_proxy(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: dict,
    event_logger: EventLogger,
) -> None:
    tune_tcp_writer(writer)
    channel: Optional[SecureChannel] = None                    # Secure server channel
    client_addr = writer.get_extra_info("peername")           # Local app address

    try:
        header = await reader.readuntil(b"\r\n\r\n")          # HTTP proxy request header
        header_text = header.decode("latin1")
        header_lines = header_text.split("\r\n")
        request_line = header_lines[0]
        method, target, version = request_line.split(" ", 2)
        method_upper = method.upper()

        normal_headers = []                                   # Headers forwarded to target
        host_header: Optional[str] = None                      # HTTP Host header value

        for line in header_lines[1:]:
            if not line:
                continue

            if ":" not in line:
                continue

            header_name, header_value = line.split(":", 1)
            lower_name = header_name.lower()

            if lower_name == "host":
                host_header = header_value.strip()

            if lower_name != "proxy-connection":
                normal_headers.append(line)

        if method_upper == "CONNECT":
            target_host, target_port = parse_host_port(target, 443)
            first_payload = b""
            success_response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        else:
            parsed_url = urlsplit(target)
            if parsed_url.scheme and parsed_url.netloc:
                if parsed_url.scheme.lower() == "https":
                    default_port = 443
                else:
                    default_port = 80

                target_host, target_port = parse_host_port(parsed_url.netloc, default_port)
                target_path = parsed_url.path or "/"
                if parsed_url.query:
                    target_path = target_path + "?" + parsed_url.query

                rewritten_header = f"{method} {target_path} {version}\r\n"
                for header_line in normal_headers:
                    rewritten_header = rewritten_header + header_line + "\r\n"
                rewritten_header = rewritten_header + "\r\n"
                first_payload = rewritten_header.encode("latin1")
            else:
                if host_header is None:
                    writer.write(build_http_error("400 Bad Request", "missing Host header"))
                    await writer.drain()
                    return

                target_host, target_port = parse_host_port(host_header, 80)
                first_payload = header

            success_response = b""

        event_logger.log(f"http client={client_addr} target={target_host}:{target_port} method={method_upper}")
        channel = await open_secure_channel(config)
        await send_connect(channel, target_host, target_port)

        if success_response:
            writer.write(success_response)
            await writer.drain()

        await run_tunnel(reader, writer, channel, first_payload)

    except Exception as error:
        event_logger.log(f"http error client={client_addr} error={error}")
        if not writer.is_closing():
            writer.write(build_http_error("502 Bad Gateway", f"proxy error: {error}"))
            await writer.drain()
    finally:
        await close_writer(writer)


async def run_http_proxy(
    config: dict,
    event_logger: EventLogger,
    listen_host: str,
    listen_port: int,
    display_name: str,
) -> None:
    http_handler = functools.partial(handle_http_proxy, config=config, event_logger=event_logger)  # Handler with state
    http_server = await asyncio.start_server(
        http_handler,
        host=listen_host,
        port=listen_port,
        backlog=65535,
        start_serving=True,
    )

    print(f"[{display_name}] {listen_host}:{listen_port}")
    async with http_server:
        await http_server.serve_forever()


async def read_socks5_address(reader: asyncio.StreamReader, address_type: int) -> str:
    if address_type == 1:
        ipv4_bytes = await reader.readexactly(4)               # IPv4 address bytes
        return socket.inet_ntoa(ipv4_bytes)

    if address_type == 3:
        domain_size = await reader.readexactly(1)              # Domain length byte
        domain_bytes = await reader.readexactly(domain_size[0])
        return domain_bytes.decode("utf-8")

    if address_type == 4:
        ipv6_bytes = await reader.readexactly(16)              # IPv6 address bytes
        return socket.inet_ntop(socket.AF_INET6, ipv6_bytes)

    raise ConnectionError("unsupported socks5 address type")


def socks5_reply(reply_code: int, bind_host: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    bind_ip = ipaddress.ip_address(bind_host)                  # Bind address object

    if bind_ip.version == 4:
        return b"\x05" + bytes([reply_code]) + b"\x00\x01" + bind_ip.packed + struct.pack("!H", bind_port)

    return b"\x05" + bytes([reply_code]) + b"\x00\x04" + bind_ip.packed + struct.pack("!H", bind_port)


async def handle_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: dict,
    event_logger: EventLogger,
) -> None:
    tune_tcp_writer(writer)
    client_addr = writer.get_extra_info("peername")           # Local app address

    try:
        version = await reader.readexactly(1)                  # SOCKS version byte
        if version != b"\x05":
            return

        method_count_byte = await reader.readexactly(1)        # Auth method count byte
        method_count = method_count_byte[0]
        await reader.readexactly(method_count)
        writer.write(b"\x05\x00")                            # No-auth method selected
        await writer.drain()

        request_header = await reader.readexactly(4)           # SOCKS request header
        socks_version = request_header[0]
        command = request_header[1]
        address_type = request_header[3]

        if socks_version != 5:
            return

        target_host = await read_socks5_address(reader, address_type)
        target_port_bytes = await reader.readexactly(2)
        target_port = struct.unpack("!H", target_port_bytes)[0]

        if command == 1:
            event_logger.log(f"socks5 tcp client={client_addr} target={target_host}:{target_port}")
            channel = await open_secure_channel(config)
            await send_connect(channel, target_host, target_port)
            writer.write(socks5_reply(0, "127.0.0.1", 0))
            await writer.drain()
            await run_tunnel(reader, writer, channel)
            return

        if command == 3:
            event_logger.log(f"socks5 udp-associate client={client_addr}")
            writer.write(socks5_reply(0, SOCKS5_HOST, SOCKS5_PORT))
            await writer.drain()
            while True:
                keep_data = await reader.read(1024)            # Keep TCP control connection open
                if not keep_data:
                    return

        writer.write(socks5_reply(7, "127.0.0.1", 0))
        await writer.drain()

    except Exception as error:
        event_logger.log(f"socks5 error client={client_addr} error={error}")
        if not writer.is_closing():
            writer.write(socks5_reply(1, "127.0.0.1", 0))
            await writer.drain()
    finally:
        await close_writer(writer)


async def run_socks5_server(config: dict, event_logger: EventLogger) -> None:
    socks_handler = functools.partial(handle_socks5, config=config, event_logger=event_logger)  # Handler with state
    socks_server = await asyncio.start_server(
        socks_handler,
        host=SOCKS5_HOST,
        port=SOCKS5_PORT,
        backlog=65535,
        start_serving=True,
    )

    print(f"[SOCKS5 TCP] {SOCKS5_HOST}:{SOCKS5_PORT}")
    async with socks_server:
        await socks_server.serve_forever()


@dataclass
class UdpClientSession:
    client_addr: Tuple[str, int]                               # Local app UDP address
    session_id: str                                            # Client-generated session id
    last_seen: float                                           # Last activity timestamp


def parse_socks5_udp_packet(packet: bytes) -> Tuple[str, int, bytes]:
    if len(packet) < 10:
        raise ValueError("short socks5 udp packet")
    if packet[0:2] != b"\x00\x00":
        raise ValueError("bad socks5 udp reserved field")
    if packet[2] != 0:
        raise ValueError("socks5 udp fragmentation is not supported")

    address_type = packet[3]                                  # SOCKS5 address type
    position = 4                                               # Address field position

    if address_type == 1:
        target_host = socket.inet_ntoa(packet[position:position + 4])
        position += 4
    elif address_type == 3:
        domain_size = packet[position]
        position += 1
        target_host = packet[position:position + domain_size].decode("utf-8")
        position += domain_size
    elif address_type == 4:
        target_host = socket.inet_ntop(socket.AF_INET6, packet[position:position + 16])
        position += 16
    else:
        raise ValueError("unsupported socks5 udp address type")

    target_port = struct.unpack("!H", packet[position:position + 2])[0]
    payload = packet[position + 2:]
    return target_host, target_port, payload


def build_socks5_udp_packet(host: str, port: int, payload: bytes) -> bytes:
    try:
        address_ip = ipaddress.ip_address(host)                # Try IP address first
    except ValueError:
        host_bytes = host.encode("utf-8")                      # Domain name bytes
        if len(host_bytes) > 255:
            raise ValueError("domain too long")
        address_part = b"\x03" + bytes([len(host_bytes)]) + host_bytes
    else:
        if address_ip.version == 4:
            address_part = b"\x01" + address_ip.packed
        else:
            address_part = b"\x04" + address_ip.packed

    return b"\x00\x00\x00" + address_part + struct.pack("!H", port) + payload


class ClientUdpRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, config: dict, event_logger: EventLogger):
        self.config = config                                   # Client configuration
        self.event_logger = event_logger                       # Optional event logger
        self.key = derive_udp_key(str(config["password"]))     # Long-lived UDP AEAD key
        self.server_addr = (str(config["server_host"]), int(config["server_port"]))  # Remote server UDP addr
        self.transport: Optional[asyncio.DatagramTransport] = None  # Local UDP transport
        self.by_client: Dict[Tuple[str, int], UdpClientSession] = {}  # Client address map
        self.by_session: Dict[str, UdpClientSession] = {}      # Session id map
        self.loop: Optional[asyncio.AbstractEventLoop] = None  # Current event loop

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport                             # Store local UDP transport
        self.loop = asyncio.get_running_loop()                 # Store loop for tasks
        self.loop.create_task(self.cleanup_loop())

    def datagram_received(self, data: bytes, addr) -> None:
        if data.startswith(UDP_MAGIC):
            self.handle_server_response(data)
            return
        self.handle_local_request(data, addr)

    def handle_local_request(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        target_host, target_port, payload = parse_socks5_udp_packet(data)  # Parse SOCKS5 UDP packet
        session = self.by_client.get(client_addr)             # Existing local client session

        if session is None:
            session = UdpClientSession(
                client_addr=client_addr,
                session_id=secrets.token_hex(8),
                last_seen=time.time(),
            )
            self.by_client[client_addr] = session
            self.by_session[session.session_id] = session
            self.event_logger.log(f"udp local-session client={client_addr}")

        session.last_seen = time.time()
        request_header = {                                    # Encrypted UDP request metadata
            "type": "udp_request",
            "sid": session.session_id,
            "host": target_host,
            "port": target_port,
        }
        encrypted_packet = udp_encrypt(self.key, request_header, payload)
        self.event_logger.log(f"udp request client={client_addr} target={target_host}:{target_port} bytes={len(payload)}")
        self.transport.sendto(encrypted_packet, self.server_addr)

    def handle_server_response(self, data: bytes) -> None:
        header, payload = udp_decrypt(self.key, data)          # Decrypt server UDP packet
        packet_type = header.get("type")                       # Packet type field
        if packet_type != "udp_response":
            return

        session_id = str(header["sid"])                        # Original session id
        session = self.by_session.get(session_id)
        if session is None:
            return

        session.last_seen = time.time()
        target_host = str(header["host"])
        target_port = int(header["port"])
        response_packet = build_socks5_udp_packet(target_host, target_port, payload)
        self.transport.sendto(response_packet, session.client_addr)

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            current_time = time.time()                         # Current cleanup time
            expired_sessions = []                              # Session ids selected for cleanup

            for session_id, session in self.by_session.items():
                idle_seconds = current_time - session.last_seen
                if idle_seconds > UDP_SESSION_TTL:
                    expired_sessions.append(session_id)

            for session_id in expired_sessions:
                session = self.by_session.pop(session_id)
                self.by_client.pop(session.client_addr, None)
                self.event_logger.log(f"udp expired client={session.client_addr}")


async def run_udp_relay(config: dict, event_logger: EventLogger) -> None:
    event_loop = asyncio.get_running_loop()                    # UDP relay event loop
    protocol_factory = functools.partial(ClientUdpRelayProtocol, config, event_logger)  # Relay protocol factory
    await event_loop.create_datagram_endpoint(
        protocol_factory,
        local_addr=(SOCKS5_HOST, SOCKS5_PORT),
    )

    print(f"[SOCKS5 UDP] {SOCKS5_HOST}:{SOCKS5_PORT}")
    while True:
        await asyncio.sleep(3600)


def read_runtime_config() -> dict:
    print("Enter server information. This client does not store the server address, port, or password locally.")

    server_host = input("Server IP or domain: ").strip()          # Remote server host
    server_port_text = input("Server port: ").strip()           # Remote server port text
    password = getpass.getpass("Password: ").strip()           # Hidden password input

    if not server_host:
        raise SystemExit("Server address cannot be empty.")
    if not server_port_text:
        raise SystemExit("Server port cannot be empty.")
    if not password:
        raise SystemExit("Password cannot be empty.")

    config = {}                                                # Runtime-only client configuration
    config["server_host"] = server_host                       # Remote server host in memory only
    config["server_port"] = int(server_port_text)             # Remote server port in memory only
    config["password"] = password                             # Password in memory only
    return config


def ask_yes_no(prompt_text: str, default_value: bool = False) -> bool:
    default_text = "yes" if default_value else "no"           # Display default answer

    while True:
        answer = input(f"{prompt_text} yes/no [{default_text}]：").strip().lower()  # User yes/no input
        if not answer:
            return default_value
        if answer == "yes" or answer == "y":
            return True
        if answer == "no" or answer == "n":
            return False
        print("Please enter yes or no.")

def thread_entry(coroutine) -> None:
    asyncio.run(coroutine)                                     # Run one event loop per thread

def run_asyncio_thread(name: str, coroutine) -> threading.Thread:
    thread = threading.Thread(target=thread_entry, args=(coroutine,), name=name, daemon=True)  # Worker thread
    thread.start()
    return thread

def main() -> None:
    print("AegisRoute Client")
    config = read_runtime_config()                              # Read runtime-only server configuration
    save_records = ask_yes_no("Keep client records in client.log?", False)  # Log option
    event_logger = EventLogger(save_records, CLIENT_LOG_FILE)  # Optional file logger

    event_logger.log("client start without saved secrets")
    http_thread = run_asyncio_thread(
        "aegisroute-http-proxy",
        run_http_proxy(config, event_logger, HTTP_PROXY_HOST, HTTP_PROXY_PORT, "HTTP"),
    )                                                           # HTTP worker
    https_thread = run_asyncio_thread(
        "aegisroute-https-proxy",
        run_http_proxy(config, event_logger, HTTPS_PROXY_HOST, HTTPS_PROXY_PORT, "HTTPS CONNECT"),
    )                                                           # HTTPS CONNECT worker
    socks_thread = run_asyncio_thread("aegisroute-socks5-server", run_socks5_server(config, event_logger))  # SOCKS TCP worker
    udp_thread = run_asyncio_thread("aegisroute-udp-relay", run_udp_relay(config, event_logger))  # SOCKS UDP worker
    print("\nClient started. Proxy endpoints:")
    print(f"  HTTP Proxy  : {HTTP_PROXY_HOST}:{HTTP_PROXY_PORT}")
    print(f"  HTTPS Proxy : {HTTPS_PROXY_HOST}:{HTTPS_PROXY_PORT}  CONNECT is supported")
    print(f"  SOCKS5 TCP：{SOCKS5_HOST}:{SOCKS5_PORT}")
    print(f"  SOCKS5 UDP：{SOCKS5_HOST}:{SOCKS5_PORT}")
    print(f"  Records     : {'client.log' if save_records else 'not kept'}")
    print("  Secrets     : server address, server port, and password are not stored")
    print("\nRecommended browser or system proxy settings:")
    print(f"  HTTP proxy  = {HTTP_PROXY_HOST}:{HTTP_PROXY_PORT}")
    print(f"  HTTPS proxy = {HTTPS_PROXY_HOST}:{HTTPS_PROXY_PORT}")
    print(f"  SOCKS5      = {SOCKS5_HOST}:{SOCKS5_PORT}")
    print("\nKeep this window open. Press Ctrl+C to stop.")
    try:
        while http_thread.is_alive() and https_thread.is_alive() and socks_thread.is_alive() and udp_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nClient is shutting down.")
    finally:
        event_logger.log("client stop")
        event_logger.close()
if __name__ == "__main__":
    main()
