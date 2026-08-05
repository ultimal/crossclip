# crossclip

A cross-platform clipboard sync tool for Windows and Linux. Run a relay `server`
on one machine and a `client` on every machine you want kept in sync. Whenever
you copy something (Ctrl+C) on a machine running the client, the change is
pushed to the server and rebroadcast to every other connected client, which
then updates its local clipboard.

Supports:
- Plain text
- Images (re-encoded as PNG in transit)
- Single files (dragged/copied as a file, not a folder)

## Architecture

```
client A ──┐                  ┌── client B
           ├── TCP ── server ─┤
client C ──┘   (relay only)   └── client D
```

- `server` never touches the clipboard. It just authenticates clients with a
  shared pre-key (PSK) and relays encrypted, length-prefixed packets between
  them. It has no GUI and can run headless.
- `client` watches the local system clipboard via Qt's `QClipboard`, and on
  change, serializes the payload (`protocol.h`), encrypts it (`crypto.cpp`,
  AES-256-CBC, key = SHA-256 of the PSK), and sends it to the server. Incoming
  packets are decrypted and applied to the local clipboard.

## Requirements

- CMake 3.16+
- A C++17 compiler
- Qt 6.5+ (`Core`, `Gui`, `Network` components) — for the client on Windows,
  install Qt via the official [Qt Online Installer](https://www.qt.io/download-qt-installer);
  on Linux, distro packages or the same installer both work.
- OpenSSL (`libssl-dev` on Debian/Ubuntu, or via `vcpkg`/the OpenSSL installer
  on Windows)

## Building

```bash
cmake -B build -S .
cmake --build build
```

This produces two executables: `server` and `client`.

## Usage

On the machine that will act as the relay:

```bash
./server <psk> <port>
# e.g. ./server "correct horse battery staple" 5900
```

On every machine you want synced:

```bash
./client <server-ip> <port> <psk>
# e.g. ./client 192.168.1.10 5900 "correct horse battery staple"
```

All clients must use the same PSK and point at the same server/port. Copying
something on one client updates the clipboard on every other connected
client. If a client loses its connection, it automatically retries every 3
seconds until the server is reachable again.

## Security

Payloads are encrypted with AES-256-GCM (key = SHA-256 of the PSK), which
provides both confidentiality and integrity — tampered or corrupted packets
are rejected rather than silently decrypted into garbage. That said, the PSK
itself is exchanged in the clear as a raw key check on connect, so this is
suitable for trusted networks, not as a substitute for TLS/mutual auth
against an active on-path attacker.

## Known limitations

- **Folders are not supported.** Copying a directory is explicitly rejected
  client-side; only single files work.
- **Only the first file in a multi-file selection is sent.** Selecting and
  copying several files at once will sync just one of them.
- Whole files/images are buffered in memory and sent as a single message, so
  very large files will use a correspondingly large amount of RAM on both
  ends.
