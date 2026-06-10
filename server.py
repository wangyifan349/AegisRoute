#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0
"""
server.py
AegisRoute interactive encrypted proxy server.
Install dependency:
    pip install cryptography
Run:
    python server.py
"""
import asyncio
import functools
import getpass
import hashlib
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, TextIO, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
SERVER_LOG_FILE = "server.log"              # Server log file name


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


async def server_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, password: str) -> SecureChannel:
    magic_value = await reader.readexactly(len(TCP_MAGIC))  # Read protocol marker
    if magic_value != TCP_MAGIC:
        raise ConnectionError("bad tcp protocol magic")

    salt = await reader.readexactly(16)                     # Read client random salt
    key = derive_tcp_key(password, salt)                    # Build session key
    return SecureChannel(reader, writer, key, is_client=False)


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


async def target_to_channel(target_reader: asyncio.StreamReader, channel: SecureChannel) -> None:
    while True:
        data = await target_reader.read(TCP_CHUNK_SIZE)        # Read from remote target
        if not data:
            await channel.send(FRAME_EOF)
            return
        await channel.send(FRAME_DATA, data)

async def channel_to_target(channel: SecureChannel, target_writer: asyncio.StreamWriter) -> None:
    while True:
        frame_type, payload = await channel.recv()             # Read encrypted client frame
        if frame_type is None:
            return
        if frame_type == FRAME_EOF:
            return
        if frame_type == FRAME_DATA:
            target_writer.write(payload)
            await target_writer.drain()
            continue
        if frame_type == FRAME_PING:
            await channel.send(FRAME_PONG)
            continue
        if frame_type == FRAME_PONG:
            continue
        return


async def relay_tcp(channel: SecureChannel, target_reader: asyncio.StreamReader, target_writer: asyncio.StreamWriter) -> None:
    keep_task = asyncio.create_task(keepalive(channel))        # Periodic keep-alive task
    upload_task = asyncio.create_task(channel_to_target(channel, target_writer))  # Client to target
    download_task = asyncio.create_task(target_to_channel(target_reader, channel))  # Target to client
    relay_tasks = [upload_task, download_task]                 # TCP relay task list

    await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)

    keep_task.cancel()                                        # Stop keep-alive task
    upload_task.cancel()                                      # Stop upload task if alive
    download_task.cancel()                                    # Stop download task if alive
    await asyncio.gather(keep_task, upload_task, download_task, return_exceptions=True)


async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    password: str,
    event_logger: EventLogger,
) -> None:
    channel: Optional[SecureChannel] = None                    # Secure channel after handshake
    target_writer: Optional[asyncio.StreamWriter] = None       # Target stream writer
    client_addr = writer.get_extra_info("peername")           # Client socket address
    tune_tcp_writer(writer)
    try:
        channel = await server_handshake(reader, writer, password)
        frame_type, payload = await channel.recv()
        if frame_type != FRAME_CONNECT:
            await channel.send(FRAME_ERR, b"expected CONNECT frame")
            return
        request = json.loads(payload.decode("utf-8"))          # Target request JSON
        target_host = str(request["host"])                     # Target host name
        target_port = int(request["port"])                     # Target port number
        event_logger.log(f"tcp connect client={client_addr} target={target_host}:{target_port}")
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        tune_tcp_writer(target_writer)
        await channel.send(FRAME_OK)
        await relay_tcp(channel, target_reader, target_writer)
    except Exception as error:
        event_logger.log(f"tcp error client={client_addr} error={error}")
        if channel is not None:
            await channel.send(FRAME_ERR, str(error).encode("utf-8", "replace"))
    finally:
        if target_writer is not None:
            await close_writer(target_writer)
        await close_writer(writer)


async def run_tcp_server(port: int, password: str, event_logger: EventLogger) -> None:
    tcp_handler = functools.partial(handle_tcp_client, password=password, event_logger=event_logger)  # Handler with state
    tcp_server = await asyncio.start_server(
        tcp_handler,
        host="0.0.0.0",
        port=port,
        backlog=65535,
        start_serving=True,
    )

    print(f"[TCP] listening on 0.0.0.0:{port}")
    async with tcp_server:
        await tcp_server.serve_forever()


@dataclass
class UdpTargetSession:
    client_addr: Tuple[str, int]                               # Original client UDP address
    session_id: str                                            # Client session id
    target_host: str                                           # Target host name
    target_port: int                                           # Target port number
    transport: asyncio.DatagramTransport                       # UDP socket to target
    last_seen: float                                           # Last activity timestamp


class TargetUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server_protocol: "ServerUdpProtocol", session_key: tuple):
        self.server_protocol = server_protocol                 # Parent UDP server protocol
        self.session_key = session_key                         # Lookup key for session map
        self.transport: Optional[asyncio.DatagramTransport] = None  # Target UDP transport

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport                             # Store target transport

    def datagram_received(self, data: bytes, addr) -> None:
        session = self.server_protocol.sessions.get(self.session_key)  # Find related session
        if session is None:
            return

        response_header = {                                    # Encrypted response metadata
            "type": "udp_response",
            "sid": session.session_id,
            "host": session.target_host,
            "port": session.target_port,
        }
        response_packet = udp_encrypt(self.server_protocol.key, response_header, data)
        self.server_protocol.transport.sendto(response_packet, session.client_addr)


class ServerUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, password: str, event_logger: EventLogger):
        self.key = derive_udp_key(password)                    # Long-lived UDP AEAD key
        self.event_logger = event_logger                       # Optional event logger
        self.transport: Optional[asyncio.DatagramTransport] = None  # Server UDP transport
        self.sessions: Dict[tuple, UdpTargetSession] = {}      # Active UDP target sessions
        self.loop: Optional[asyncio.AbstractEventLoop] = None  # Current event loop

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport                             # Store server transport
        self.loop = asyncio.get_running_loop()                 # Store loop for tasks
        self.loop.create_task(self.cleanup_loop())

    def datagram_received(self, data: bytes, addr) -> None:
        if self.loop is None:
            return
        self.loop.create_task(self.handle_datagram(data, addr))

    async def handle_datagram(self, data: bytes, client_addr: Tuple[str, int]) -> None:
        header, payload = udp_decrypt(self.key, data)          # Decrypt client UDP packet
        packet_type = header.get("type")                       # Packet type field
        if packet_type != "udp_request":
            return

        session_id = str(header["sid"])                        # Client UDP session id
        target_host = str(header["host"])                      # Target host name
        target_port = int(header["port"])                      # Target port number
        session_key = (client_addr, session_id, target_host, target_port)  # Unique session key
        session = self.sessions.get(session_key)               # Existing target socket
        if session is None:
            protocol_factory = functools.partial(TargetUdpProtocol, self, session_key)  # Target protocol factory
            target_transport, _ = await self.loop.create_datagram_endpoint(
                protocol_factory,
                remote_addr=(target_host, target_port),
            )
            session = UdpTargetSession(
                client_addr=client_addr,
                session_id=session_id,
                target_host=target_host,
                target_port=target_port,
                transport=target_transport,
                last_seen=time.time(),
            )
            self.sessions[session_key] = session
            self.event_logger.log(f"udp session client={client_addr} target={target_host}:{target_port}")

        session.last_seen = time.time()
        session.transport.sendto(payload)

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            current_time = time.time()                         # Current cleanup time
            expired_keys = []                                  # Keys selected for cleanup
            for session_key, session in self.sessions.items():
                idle_seconds = current_time - session.last_seen
                if idle_seconds > UDP_SESSION_TTL:
                    expired_keys.append(session_key)
            for session_key in expired_keys:
                session = self.sessions.pop(session_key)
                session.transport.close()
                self.event_logger.log(f"udp expired client={session.client_addr} target={session.target_host}:{session.target_port}")
async def run_udp_server(port: int, password: str, event_logger: EventLogger) -> None:
    event_loop = asyncio.get_running_loop()                    # UDP event loop
    protocol_factory = functools.partial(ServerUdpProtocol, password, event_logger)  # Server protocol factory
    await event_loop.create_datagram_endpoint(
        protocol_factory,
        local_addr=("0.0.0.0", port),
    )

    print(f"[UDP] listening on 0.0.0.0:{port}")
    while True:
        await asyncio.sleep(3600)


def thread_entry(coroutine) -> None:
    asyncio.run(coroutine)                                     # Run one event loop per thread


def run_asyncio_thread(name: str, coroutine) -> threading.Thread:
    thread = threading.Thread(target=thread_entry, args=(coroutine,), name=name, daemon=True)  # Worker thread
    thread.start()
    return thread


def ask_port() -> int:
    port_text = input("Server listen port, for example 8443: ").strip()  # User port input
    if not port_text:
        port_text = "8443"
    return int(port_text)
def ask_password() -> str:
    password = getpass.getpass("Communication password; a random string of at least 32 characters is recommended: ").strip()  # Hidden password input
    if not password:
        raise SystemExit("Password cannot be empty")
    return password
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
def main() -> None:
    print("AegisRoute Server")
    print("The listen address is fixed at 0.0.0.0, and TCP and UDP use the same port.")
    port = ask_port()                                         # Server listen port
    password = ask_password()                                 # Shared password
    save_records = ask_yes_no("Keep server logs in server.log?", False)  # Log option
    event_logger = EventLogger(save_records, SERVER_LOG_FILE) # Optional file logger
    event_logger.log(f"server start port={port}")
    tcp_thread = run_asyncio_thread("aegisroute-tcp-server", run_tcp_server(port, password, event_logger))  # TCP worker
    udp_thread = run_asyncio_thread("aegisroute-udp-server", run_udp_server(port, password, event_logger))  # UDP worker
    print("\nServer started:")
    print(f"  TCP: 0.0.0.0:{port}")
    print(f"  UDP: 0.0.0.0:{port}")
    print(f"  Logs: {'server.log' if save_records else 'not kept'}")
    print("\nKeep this window open. Press Ctrl+C to stop.")
    try:
        while tcp_thread.is_alive() and udp_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        event_logger.log("server stop")
        event_logger.close()
if __name__ == "__main__":
    main()
