# 🛡️ AegisRoute

**AegisRoute** is a lightweight, two-file Python proxy tunnel built around an interactive client and server design. It provides local HTTP, HTTPS, and SOCKS5 proxy endpoints on the client side, then forwards traffic to a remote AegisRoute server through encrypted TCP and UDP transport paths.

The project is designed to be easy to read, easy to run, and easy to modify. The server is contained in `server.py`, the client is contained in `client.py`, and both programs ask for their runtime settings interactively. The client does **not** save the server address, server port, or shared password to a local configuration file.

AegisRoute is licensed under the **GNU Affero General Public License v3.0 only (AGPL-3.0-only)**..

SPDX-License-Identifier: AGPL-3.0-only
---

## ✨ Highlights

- 🧩 Two-file structure: `server.py` and `client.py`.
- 🖥️ Interactive startup with no command-line arguments required.
- 🌐 Local HTTP proxy support.
- 🔒 Local HTTPS proxy support through the HTTP `CONNECT` method.
- 🧦 SOCKS5 TCP `CONNECT` support for general TCP-based applications.
- 📡 SOCKS5 UDP `UDP ASSOCIATE` support for UDP-capable clients.
- 🔁 SOCKS5 TCP and SOCKS5 UDP use the same local port number.
- 🚇 TCP traffic is transported through an encrypted TCP tunnel.
- ⚡ UDP traffic is transported through encrypted UDP datagrams.
- 🛡️ Client/server communication uses ChaCha20-Poly1305 authenticated encryption.
- 🔑 TCP session keys are derived with HKDF-SHA256 and a random per-connection salt.
- 💓 TCP keep-alive frames are included in the tunnel protocol.
- 🧵 Multi-threaded service layout with separate `asyncio` event loops.
- 📝 Optional client-side and server-side event logging.
- 🚫 Client does not store the server IP, server port, or shared password on disk.

---

## 📦 Project Files

```text
server.py   # Interactive encrypted proxy server
client.py   # Interactive encrypted proxy client
README.md   # Project documentation
LICENSE     # GNU GPLv3 license text
```

---

## 🧠 Proxy Concepts

AegisRoute exposes several common proxy interfaces locally. Each proxy type solves a slightly different problem.

### 🌐 HTTP Proxy

An HTTP proxy is commonly used by browsers and applications for normal HTTP traffic. Instead of connecting directly to the target web server, the application sends an HTTP request to the proxy. The proxy reads the requested destination, opens a connection to that destination, and forwards the request and response.

For plain HTTP, the proxy can see the HTTP request line and headers because HTTP itself is not encrypted. AegisRoute does not store raw proxied traffic content in its logs.

Default local endpoint:

```text
127.0.0.1:8080
```

### 🔒 HTTPS Proxy with CONNECT

HTTPS proxying normally uses the HTTP `CONNECT` method. The browser asks the proxy to create a TCP tunnel to a target host and port, usually port `443`. After the tunnel is established, the browser and the website perform their normal TLS handshake through that tunnel.

AegisRoute does **not** decrypt HTTPS traffic. It only transports the encrypted TLS stream between the local client and the remote destination through the AegisRoute server.

Default local endpoint:

```text
127.0.0.1:8081
```

### 🧦 SOCKS5 TCP Proxy

SOCKS5 is a general-purpose proxy protocol. Unlike an HTTP proxy, it is not limited to browser-style HTTP requests. SOCKS5 TCP `CONNECT` can carry many TCP-based protocols, including web browsing, API clients, package managers, SSH clients, database clients, and other applications that support SOCKS5.

Default local endpoint:

```text
127.0.0.1:1080
```

### 📡 SOCKS5 UDP Proxy

SOCKS5 also defines `UDP ASSOCIATE`, which allows UDP packets to be relayed through a SOCKS5 proxy. UDP is used by many latency-sensitive and datagram-oriented protocols, including DNS, some game traffic, voice/video flows, and QUIC/HTTP/3-style traffic when the application supports SOCKS5 UDP correctly.

AegisRoute keeps UDP traffic on an encrypted UDP path instead of forcing UDP payloads through a TCP stream. This is important because TCP is ordered and reliable, while UDP is datagram-based and latency-sensitive.

Default local endpoint:

```text
127.0.0.1:1080
```

SOCKS5 TCP and SOCKS5 UDP can use the same numeric port because TCP and UDP are separate transport protocols.

---

## 🔁 TCP and UDP Transport Model

AegisRoute separates TCP and UDP forwarding paths.

### TCP Path

For local HTTP, HTTPS `CONNECT`, and SOCKS5 TCP traffic:

```text
Local Application
    -> AegisRoute Client TCP Proxy
    -> Encrypted TCP Tunnel
    -> AegisRoute Server
    -> Target Website or Service
```

The client opens a secure TCP channel to the server, sends the requested target host and port, and then both sides exchange encrypted data frames until the connection closes.

### UDP Path

For SOCKS5 UDP traffic:

```text
Local Application
    -> AegisRoute Client UDP Relay
    -> Encrypted UDP Datagram
    -> AegisRoute Server UDP Relay
    -> Target UDP Service
```

Each UDP packet is protected as an encrypted datagram. This keeps the UDP behavior closer to native UDP and avoids TCP head-of-line blocking.

---

## 🛡️ Encryption

AegisRoute uses **ChaCha20-Poly1305** for authenticated encryption between the client and the server. ChaCha20 provides fast stream encryption, while Poly1305 provides message authentication so modified ciphertext is rejected.

### TCP Encryption Flow

1. The client generates a random 16-byte salt for each TCP tunnel.
2. The shared password is hashed with SHA-256.
3. HKDF-SHA256 derives a 32-byte session key.
4. Each tunnel frame is encrypted and authenticated with ChaCha20-Poly1305.
5. Separate nonce prefixes are used for client-to-server and server-to-client frames.

### UDP Encryption Flow

1. A UDP encryption key is derived from the shared password.
2. Each UDP datagram uses a random nonce.
3. UDP metadata and payload are encrypted and authenticated together.
4. The server decrypts, validates, forwards, and returns encrypted UDP responses.

Use a long random shared password. The password should be unique to the deployment.

---

## 🔌 Default Client Ports

After the client starts, configure your browser, operating system, or application proxy settings with these local endpoints:

| Proxy Type | Local Address | Description |
| --- | --- | --- |
| HTTP | `127.0.0.1:8080` | Plain HTTP proxy endpoint. |
| HTTPS | `127.0.0.1:8081` | HTTP `CONNECT` endpoint for HTTPS tunneling. |
| SOCKS5 TCP | `127.0.0.1:1080` | General TCP proxy endpoint. |
| SOCKS5 UDP | `127.0.0.1:1080` | UDP relay through SOCKS5 `UDP ASSOCIATE`. |

The server listens on one user-selected port for both TCP and UDP:

```text
TCP: 0.0.0.0:<server-port>
UDP: 0.0.0.0:<server-port>
```

---

## 🧰 Requirements

- Python 3.9 or newer is recommended.
- The `cryptography` Python package is required.
- The server firewall or cloud security group must allow both TCP and UDP on the selected server port.

Install the Python dependency:

```bash
python -m pip install cryptography
```

On some Linux systems, use:

```bash
python3 -m pip install cryptography
```

---

## 🚀 Deployment from GitHub

Repository:

```text
https://github.com/wangyifan349/AegisRoute
```

Clone the project:

```bash
git clone https://github.com/wangyifan349/AegisRoute.git
cd AegisRoute
```

Install the dependency:

```bash
python -m pip install cryptography
```

Run the server on your remote machine:

```bash
python server.py
```

Run the client on your local machine:

```bash
python client.py
```

---

## 🖥️ Server Deployment

On the server machine, install Python, Git, and the required dependency.

### Ubuntu or Debian Example

```bash
sudo apt update
sudo apt install -y python3 python3-pip git

git clone https://github.com/wangyifan349/AegisRoute.git
cd AegisRoute

python3 -m pip install cryptography
python3 server.py
```

When `server.py` starts, it asks for:

```text
Server listen port
Shared password
Whether to keep server records in server.log
```

The server always binds to:

```text
0.0.0.0
```

Open the selected server port for both TCP and UDP.

### UFW Example

Replace `8443` with your selected server port:

```bash
sudo ufw allow 8443/tcp
sudo ufw allow 8443/udp
```

### Cloud Firewall Example

In your cloud provider security group or firewall panel, allow:

```text
Inbound TCP: <server-port>
Inbound UDP: <server-port>
```

To keep an interactive server session running, you can use `tmux` or `screen`:

```bash
tmux new -s aegisroute
python3 server.py
```

Detach from `tmux` with `Ctrl+B`, then `D`.

---

## 💻 Client Setup

On the client machine:

```bash
git clone https://github.com/wangyifan349/AegisRoute.git
cd AegisRoute
python -m pip install cryptography
python client.py
```

When `client.py` starts, it asks for:

```text
Server IP address or domain name
Server port
Shared password
Whether to keep client records in client.log
```

The client keeps the server address, port, and password in memory only for the current process. It does not write them to a configuration file.

After startup, set your browser or application proxy settings to:

```text
HTTP proxy:  127.0.0.1:8080
HTTPS proxy: 127.0.0.1:8081
SOCKS5:      127.0.0.1:1080
```

Applications that support SOCKS5 UDP can use the same SOCKS5 endpoint:

```text
SOCKS5 UDP: 127.0.0.1:1080
```

---

## 🪟 Windows Quick Start

Install Python from the official Python distribution, then open PowerShell in the project directory.

```powershell
py -m pip install cryptography
py client.py
```

For a Windows server machine:

```powershell
py -m pip install cryptography
py server.py
```

Allow the selected server port for both TCP and UDP in Windows Firewall if the machine is receiving inbound connections.

---

## 🐧 Linux Quick Start

```bash
python3 -m pip install cryptography
python3 server.py
```

For the client:

```bash
python3 -m pip install cryptography
python3 client.py
```

---

## 📝 Logging

Both programs ask whether records should be kept.

If enabled:

- The server writes `server.log`.
- The client writes `client.log`.

Logs are designed for operational visibility. They can include connection events, target hosts, target ports, UDP session lifecycle messages, and error messages.

Logs do not intentionally store:

- Shared passwords.
- Raw HTTP bodies.
- Raw HTTPS contents.
- Raw SOCKS5 payload contents.
- Full proxied traffic data.
- Client-side saved server configuration.

If you do not want local records, answer `no` when prompted.

---

## 🧵 Runtime Architecture

AegisRoute uses multiple threads and separate `asyncio` event loops so each service path is easier to understand and maintain.

Typical worker layout:

```text
Server TCP worker thread
Server UDP worker thread
Client HTTP worker thread
Client HTTPS CONNECT worker thread
Client SOCKS5 TCP worker thread
Client SOCKS5 UDP relay worker thread
```

This layout separates proxy responsibilities while still using asynchronous network I/O inside each worker.

---

## 🔐 Security Practices

- Use a strong random shared password.
- Use a unique password for each deployment.
- Keep Python and `cryptography` updated.
- Keep server firewall rules narrow and intentional.
- Review logs before sharing them.
- Use this software only on systems and networks where you have permission.

---
## ☕ Support AegisRoute

If **AegisRoute** has been useful to you, please consider supporting the project.

Building and maintaining networking software requires a significant amount of time, research, testing, debugging, and long-term maintenance. Features such as HTTP, HTTPS CONNECT, SOCKS5, TCP/UDP forwarding, encryption, protocol compatibility, and cross-platform support all require continuous development and refinement.

AegisRoute is developed as an open-source project, and every contribution helps support future improvements, new features, bug fixes, documentation, testing, and ongoing maintenance.

If you would like to support the project, even the equivalent of a coffee is sincerely appreciated. ☕❤️

---

### ⚡ Bitcoin (BTC)

```text
bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p
```

### 🌞 Solana (SOL)

```text
B7N4e3KG9zWQBwMrtydS1B9wVBp2w62fAdryZdxAMBiz
```

### 💎 Ethereum (ETH)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### 🟡 BNB Smart Chain (BNB)

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

### 💵 USDT

```text
0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b
```

---

⭐ If you enjoy the project, please consider giving the repository a star and sharing it with others.

🙏 Your support, encouragement, and contributions are greatly appreciated and help keep AegisRoute active and evolving.

Thank you for supporting open-source software.


## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).

See the `LICENSE` file for the full license text.

```text
SPDX-License-Identifier: AGPL-3.0-only
