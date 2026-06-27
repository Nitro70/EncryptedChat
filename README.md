# Encrypted Chat

A small, self-hostable encrypted chat app. A cross-platform desktop **client**
(Avalonia, runs on Windows, Linux and macOS) talks to a lightweight Python
**server** over a secure WebSocket. Messages are end-to-end encrypted with a key
that you choose and share out-of-band — the server only ever relays ciphertext.

There is **no built-in central server**: you point the client at any address
running the server script. Nothing — no server, no key, no password — is
hardcoded.

## Features

- 🔐 AES-256-CBC encryption (key derived from a shared passphrase)
- 🌐 Connect to any server by address + port, or 🏠 discover servers on your LAN
- 🚪 One server can host multiple isolated **rooms**, each with its own key
- ✏️ Edit / 🗑️ delete messages · 😊 emoji reactions · 💬 replies
- 📎 Image sharing · ⌨️ typing indicators · 👥 live user list · 📜 history on join
- 👑 Optional admin panel (kick / ban / broadcast / stats / clear)
- 🎨 Dark, Discord-style UI

## Repository layout

```
client/   Avalonia desktop client (.NET 8)
server/   Python WebSocket server (config-driven)
```

## Running the client

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
cd client
dotnet run
```

To produce a standalone build for your platform:

```bash
# Windows
dotnet publish -c Release -r win-x64 --self-contained
# Linux
dotnet publish -c Release -r linux-x64 --self-contained
# macOS (Apple Silicon)
dotnet publish -c Release -r osx-arm64 --self-contained
```

Pick **Connect to Server** and enter the address, port, a username, and the
encryption key. Or pick **LAN Mode** to discover/connect to servers on your
local network. The last-used connection is remembered locally (never shared).

## Hosting a server

Requires Python 3.9+.

```bash
cd server
pip install -r requirements.txt
python server.py
```

On the **first run** the server writes a `config.json` and exits. Open it and
set your own values, then run `python server.py` again:

```json
{
  "host": "0.0.0.0",
  "port": 8443,
  "adminPassword": "set-your-own",
  "rooms": [
    { "name": "General", "key": "set-a-unique-key" },
    { "name": "Private", "key": "set-another-unique-key" }
  ],
  "certFile": "server.crt",
  "keyFile": "server.key"
}
```

### Rooms (multiple keyed sessions)

One server hosts as many **rooms** as you list — each with its own **unique
key**. A client lands in whichever room's key it connects with, and rooms are
fully isolated (separate users, history and reactions). To invite someone to a
room, share that room's key. Add or remove rooms by editing the list and
restarting.

- **room `key`** — the shared secret for that room; clients enter it to join.
  Every room's key must be unique (and never a placeholder).
- **`adminPassword`** — required to use the admin panel; admin actions apply to
  the admin's own room. The server refuses to start until the admin password and
  every room key are set (no defaults are shipped — **nothing is hardcoded**).
- A self-signed TLS certificate is generated automatically on first run.

The server keeps recent messages in memory only (capped, cleared on restart) —
it does not persist chat history to disk.

### Connecting clients to your server

Clients connect with `wss://<your-host>:<port>`. If your host runs another
service on 443 (e.g. a website behind nginx), either run the chat server on a
free port like `8443` and connect to that directly, or put a WebSocket reverse
proxy in front of it.

## Security notes

- Encryption is only as strong as your shared key — use a long, random one.
- The server uses a self-signed certificate, so the client does not verify the
  certificate chain. This protects against passive eavesdropping but not an
  active man-in-the-middle who can present their own cert. For stronger
  guarantees, front the server with a proxy using a CA-issued certificate.
- This is a hobby project, not an audited secure-messaging product.

## License

[MIT](LICENSE)
