# Encrypted Chat

A small, self-hostable encrypted chat app. A cross-platform desktop **client**
(Avalonia, runs on Windows, Linux and macOS) talks to a lightweight Python
**server** over a secure WebSocket. Messages are AES-256-CBC encrypted with a key
you choose and share out-of-band.

There is **no built-in central server** — you point the client at any address
running the server script. The server itself **stores no keys and no rooms**:
clients create rooms on demand, rooms live only in memory while in use, and an
idle room is automatically removed. Nothing is hardcoded.

## Features

- 🔐 AES-256-CBC encryption (key derived from a shared passphrase)
- 🌐 Connect to any server by address + port, or 🏠 discover servers on your LAN
- 🚪 **Create rooms on demand** on a central server — each room has its own key,
  lives only while it's in use, and is auto-removed once empty
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

- **Create a Room** — make a new room on a central server (name + key + optional
  admin password) and get dropped straight into it. Share the key to invite people.
- **Connect to Server** — join an existing room with its address, port, and key.
- **LAN Mode** — discover/connect to servers on your local network.

The last-used connection is remembered locally (never shared).

## Hosting a server

Requires Python 3.9+.

```bash
cd server
pip install -r requirements.txt
python server.py
```

The server just runs — there are no secrets to set. On first run it writes a
`config.json` with sensible defaults and starts:

```json
{
  "host": "0.0.0.0",
  "port": 8443,
  "certFile": "server.crt",
  "keyFile": "server.key",
  "roomIdleTimeoutSeconds": 600,
  "maxRooms": 500
}
```

A self-signed TLS certificate is generated automatically on first run.

### Rooms (created on demand, no keys on the server)

The server holds **no keys and no rooms** on disk. Rooms are created at runtime
**from the app**: in the client, pick **Create a Room**, give it a name, a key,
and (optionally) an admin password for that room. Share the room's **key** with
whoever you want to join (they use **Connect to Server** with that key).

- Each room lives **only in memory** while it's in use.
- When a room has been empty for `roomIdleTimeoutSeconds` (default 10 minutes),
  it is **automatically removed** — so an idle server uses no resources.
- `maxRooms` caps how many rooms can exist at once.
- Anyone who can reach the server can create a room, but a room can only be
  joined by someone who has its key. Nothing is hardcoded — **the server never
  stores a key**.

Recent messages are kept in memory only (capped) and are gone when the room is
removed or the server restarts.

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
