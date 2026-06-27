"""
Encrypted Chat Server (multi-room)
Serves the EncryptedChat clients over WSS (secure WebSocket).

One server process can host several independent rooms ("sessions"), each with its
own encryption key. A client lands in whichever room's key it connects with;
rooms are fully isolated (separate users, history, reactions). All settings live
in config.json (created on first run) — NO key is hardcoded.
"""

import asyncio
import ssl
import json
import uuid
import time
import hashlib
import base64
import os
import sys
from datetime import datetime

# ============================================================
# SERVER CONFIGURATION (loaded from config.json — never hardcoded)
# ============================================================
CONFIG_FILE = "config.json"
PLACEHOLDER = "CHANGE_ME"
CONFIG_TEMPLATE = {
    "host": "0.0.0.0",
    "port": 8443,
    "adminPassword": PLACEHOLDER,        # set your own — required for the admin panel
    "rooms": [                            # one entry per room; each key must be unique
        {"name": "General", "key": "CHANGE_ME_pick_a_unique_key"},
        {"name": "Private", "key": "CHANGE_ME_pick_another_key"}
    ],
    "certFile": "server.crt",
    "keyFile": "server.key",
}

# Fixed limits (keep in sync with the client)
MAX_MESSAGE_HISTORY = 500
MAX_IMAGE_SIZE = 5 * 1024 * 1024


def load_config():
    """Load config.json. On first run, write a template and exit so the host can
    set their own admin password and room keys. Refuses to start otherwise."""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(CONFIG_TEMPLATE, f, indent=2)
        print(f"[!] Created {CONFIG_FILE}.")
        print(f"[!] Set 'adminPassword' and a unique 'key' for each room, then run again.")
        sys.exit(1)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = {**CONFIG_TEMPLATE, **json.load(f)}
    except Exception as e:
        print(f"[!] Could not read {CONFIG_FILE}: {e}")
        sys.exit(1)

    admin = str(cfg.get("adminPassword", "")).strip()
    if not admin or admin == PLACEHOLDER:
        print(f"[!] Set a real 'adminPassword' in {CONFIG_FILE} (not empty, not '{PLACEHOLDER}').")
        sys.exit(1)

    rooms = cfg.get("rooms")
    if not isinstance(rooms, list) or not rooms:
        print(f"[!] {CONFIG_FILE} needs a non-empty 'rooms' list (each with a 'name' and 'key').")
        sys.exit(1)

    seen_keys = set()
    for i, r in enumerate(rooms):
        if not isinstance(r, dict) or "name" not in r or "key" not in r:
            print(f"[!] rooms[{i}] must have both 'name' and 'key'.")
            sys.exit(1)
        key = str(r["key"]).strip()
        if not key or key.startswith(PLACEHOLDER):
            print(f"[!] Set a real 'key' for room '{r.get('name')}' (not empty, not a '{PLACEHOLDER}' placeholder).")
            sys.exit(1)
        if key in seen_keys:
            print(f"[!] Two rooms share the same key — every room must have a UNIQUE key.")
            sys.exit(1)
        seen_keys.add(key)

    return cfg


_cfg = load_config()
SERVER_HOST = _cfg["host"]
SERVER_PORT = int(_cfg["port"])
SSL_CERT_FILE = _cfg["certFile"]
SSL_KEY_FILE = _cfg["keyFile"]
ADMIN_PASSWORD = _cfg["adminPassword"]
ROOMS_CONFIG = _cfg["rooms"]
# ============================================================

# Install dependencies
try:
    import websockets
    from websockets.server import serve
except ImportError:
    print("Installing websockets library...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
    import websockets
    from websockets.server import serve

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding, hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import ipaddress
except ImportError:
    print("Installing cryptography library...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding, hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import ipaddress


def generate_self_signed_cert():
    """Generate self-signed SSL certificate if not exists"""
    if os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE):
        return

    print("[*] Generating self-signed SSL certificate...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EncryptedChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow().replace(year=datetime.utcnow().year + 10)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    with open(SSL_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(SSL_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] SSL certificate generated successfully")


class AESCipher:
    """AES-256-CBC encryption"""

    def __init__(self, password: str):
        self.key = hashlib.sha256(password.encode('utf-8')).digest()
        self.backend = default_backend()

    def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, encoded_ciphertext: str) -> str:
        try:
            data = base64.b64decode(encoded_ciphertext)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception:
            return None


class Message:
    """Represents a chat message"""
    def __init__(self, msg_id: str, username: str, content: str, msg_type: str = "text",
                 reply_to: str = None, image_data: str = None, timestamp: float = None):
        self.id = msg_id
        self.username = username
        self.content = content
        self.msg_type = msg_type
        self.reply_to = reply_to
        self.image_data = image_data
        self.reactions = {}
        self.edited = False
        self.edited_by = None
        self.deleted = False
        self.timestamp = timestamp or time.time()

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'content': self.content,
            'msg_type': self.msg_type,
            'reply_to': self.reply_to,
            'image_data': self.image_data,
            'reactions': self.reactions,
            'edited': self.edited,
            'edited_by': self.edited_by,
            'deleted': self.deleted,
            'timestamp': self.timestamp
        }


class Room:
    """One isolated chat room, identified by its own encryption key."""
    def __init__(self, name: str, key: str):
        self.name = name
        self.cipher = AESCipher(key)
        self.clients = {}        # websocket -> {"username", "is_admin", "typing"}
        self.messages = []
        self.typing_users = set()
        self.banned_users = set()


class ChatServer:
    """Multi-room WSS chat server."""

    def __init__(self):
        self.rooms = [Room(r["name"], r["key"]) for r in ROOMS_CONFIG]
        self.start_time = time.time()

    def log(self, message: str, msg_type: str = "info"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = {
            "info": "[INFO]", "join": "[+]", "leave": "[-]", "msg": "[MSG]",
            "error": "[ERROR]", "system": "[SYS]", "admin": "[ADMIN]", "wss": "[WSS]"
        }.get(msg_type, "[INFO]")
        print(f"{timestamp} {prefix} {message}")

    # ---- per-room send / broadcast ----------------------------------------

    async def send_encrypted(self, room: Room, websocket, data: dict):
        try:
            encrypted = room.cipher.encrypt(json.dumps(data))
            await websocket.send(encrypted)
        except Exception:
            pass

    async def broadcast(self, room: Room, data: dict, exclude=None):
        for ws in list(room.clients.keys()):
            if ws != exclude:
                await self.send_encrypted(room, ws, data)

    async def broadcast_system(self, room: Room, message: str, exclude=None):
        await self.broadcast(room, {'type': 'system', 'message': message, 'timestamp': time.time()}, exclude)

    async def broadcast_user_list(self, room: Room):
        online_users = [c["username"] for c in room.clients.values()]
        admins = [c["username"] for c in room.clients.values() if c["is_admin"]]
        await self.broadcast(room, {'type': 'user_list', 'users': online_users, 'admins': admins})

    async def broadcast_typing_status(self, room: Room):
        await self.broadcast(room, {'type': 'typing_status', 'users': list(room.typing_users)})

    # ---- connection lifecycle ---------------------------------------------

    async def handle_client(self, websocket):
        username = None
        room = None
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"

        try:
            self.log(f"WSS connection from {client_ip}", "wss")

            # First message must be a 'join'. Find the room by trying each room's key:
            # only the correct key decrypts to valid JSON with type == 'join'.
            raw_data = await asyncio.wait_for(websocket.recv(), timeout=30)
            decrypted = None
            for r in self.rooms:
                d = r.cipher.decrypt(raw_data)
                if not d:
                    continue
                try:
                    m = json.loads(d)
                except (json.JSONDecodeError, ValueError):
                    continue
                if m.get('type') == 'join':
                    room, decrypted = r, d
                    break

            if room is None:
                await websocket.close()
                return

            msg = json.loads(decrypted)
            username = msg.get('username', f'User_{client_ip}')

            if username.lower() in room.banned_users:
                await self.send_encrypted(room, websocket, {'type': 'kicked', 'message': 'You are banned from this room'})
                await websocket.close()
                self.log(f"Banned user {username} tried to join room '{room.name}'", "admin")
                return

            room.clients[websocket] = {"username": username, "is_admin": False, "typing": False}
            self.log(f"{username} joined room '{room.name}' from {client_ip}", "join")
            await self.broadcast_system(room, f"{username} joined the chat", exclude=websocket)

            welcome = {
                'type': 'welcome',
                'room': room.name,
                'message': f"Connected to '{room.name}'! {len(room.clients)} user(s) online.",
                'online_users': [c["username"] for c in room.clients.values()],
                'message_history': [m.to_dict() for m in room.messages[-50:]]
            }
            await self.send_encrypted(room, websocket, welcome)
            await self.broadcast_user_list(room)

            async for raw_data in websocket:
                try:
                    d = room.cipher.decrypt(raw_data)
                    if not d:
                        continue
                    await self.handle_message(room, websocket, username, json.loads(d))
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    self.log(f"Message error: {e}", "error")

        except websockets.exceptions.ConnectionClosed:
            pass
        except asyncio.TimeoutError:
            self.log(f"Connection timeout from {client_ip}", "error")
        except Exception as e:
            self.log(f"Client error: {e}", "error")
        finally:
            if room is not None and websocket in room.clients:
                del room.clients[websocket]
            if room is not None and username:
                room.typing_users.discard(username)
                self.log(f"{username} left room '{room.name}'", "leave")
                await self.broadcast_system(room, f"{username} left the chat")
                await self.broadcast_user_list(room)
                await self.broadcast_typing_status(room)

    # ---- message handling (scoped to a room) ------------------------------

    async def handle_message(self, room: Room, websocket, username: str, msg: dict):
        msg_type = msg.get('type', 'message')

        if msg_type == 'message':
            content = msg.get('content', '')
            reply_to = msg.get('reply_to')
            image_data = msg.get('image_data')

            if image_data and len(image_data) > MAX_IMAGE_SIZE:
                await self.send_encrypted(room, websocket, {'type': 'error', 'message': 'Image too large'})
                return

            message = Message(
                msg_id=str(uuid.uuid4()), username=username, content=content,
                msg_type='image' if image_data else 'text', reply_to=reply_to, image_data=image_data
            )
            room.messages.append(message)
            if len(room.messages) > MAX_MESSAGE_HISTORY:
                room.messages = room.messages[-MAX_MESSAGE_HISTORY:]

            self.log(f"[{room.name}] {username}: {content[:50]}{'...' if len(content) > 50 else ''}", "msg")
            await self.broadcast(room, {'type': 'message', 'message': message.to_dict()})

        elif msg_type == 'edit_message':
            is_admin = room.clients.get(websocket, {}).get("is_admin", False)
            await self.edit_message(room, msg.get('message_id'), msg.get('content', ''), username, is_admin)

        elif msg_type == 'delete_message':
            is_admin = room.clients.get(websocket, {}).get("is_admin", False)
            await self.delete_message(room, msg.get('message_id'), username, is_admin)

        elif msg_type == 'reaction':
            await self.toggle_reaction(room, msg.get('message_id'), username, msg.get('emoji', ''))

        elif msg_type == 'typing':
            is_typing = msg.get('typing', False)
            if websocket in room.clients:
                room.clients[websocket]["typing"] = is_typing
                if is_typing:
                    room.typing_users.add(username)
                else:
                    room.typing_users.discard(username)
            await self.broadcast_typing_status(room)

        elif msg_type == 'admin_auth':
            if msg.get('password', '') == ADMIN_PASSWORD:
                room.clients[websocket]["is_admin"] = True
                await self.send_encrypted(room, websocket, {'type': 'admin_auth_result', 'success': True})
                self.log(f"[{room.name}] {username} authenticated as admin", "admin")
            else:
                await self.send_encrypted(room, websocket, {'type': 'admin_auth_result', 'success': False})
                self.log(f"[{room.name}] {username} failed admin auth", "admin")

        elif msg_type == 'admin_command':
            if not room.clients.get(websocket, {}).get("is_admin", False):
                return
            await self.handle_admin_command(room, websocket, username, msg.get('command', ''))

    async def edit_message(self, room, msg_id, new_content, editor, is_admin):
        for message in room.messages:
            if message.id == msg_id and not message.deleted:
                if message.username == editor or is_admin:
                    message.content = new_content
                    message.edited = True
                    message.edited_by = editor if editor != message.username else None
                    await self.broadcast(room, {'type': 'message_edited', 'message': message.to_dict()})
                    return

    async def delete_message(self, room, msg_id, deleter, is_admin):
        for message in room.messages:
            if message.id == msg_id and not message.deleted:
                if message.username == deleter or is_admin:
                    message.deleted = True
                    message.content = "[Message deleted]"
                    message.image_data = None
                    await self.broadcast(room, {'type': 'message_deleted', 'message_id': msg_id})
                    return

    async def toggle_reaction(self, room, msg_id, username, emoji):
        for message in room.messages:
            if message.id == msg_id:
                if emoji not in message.reactions:
                    message.reactions[emoji] = []
                if username in message.reactions[emoji]:
                    message.reactions[emoji].remove(username)
                    if not message.reactions[emoji]:
                        del message.reactions[emoji]
                else:
                    message.reactions[emoji].append(username)
                await self.broadcast(room, {'type': 'reaction_update', 'message_id': msg_id, 'reactions': message.reactions})
                return

    async def handle_admin_command(self, room, websocket, admin_name, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        async def reply(success, message):
            await self.send_encrypted(room, websocket, {'type': 'admin_result', 'success': success, 'message': message})

        if cmd == 'users':
            users = [f"{c['username']}{'*' if c['is_admin'] else ''}" for c in room.clients.values()]
            await reply(True, f"Online in '{room.name}' ({len(users)}): {', '.join(users)}")

        elif cmd == 'kick' and len(parts) >= 2:
            target = parts[1]
            for ws, info in list(room.clients.items()):
                if info["username"].lower() == target.lower():
                    await self.send_encrypted(room, ws, {'type': 'kicked', 'message': 'You have been kicked'})
                    await ws.close()
                    self.log(f"[{room.name}] {admin_name} kicked {target}", "admin")
                    await self.broadcast_system(room, f"{target} was kicked")
                    await reply(True, f'Kicked {target}')
                    return
            await reply(False, 'User not found in this room')

        elif cmd == 'broadcast' and len(parts) >= 2:
            text = ' '.join(parts[1:])
            m = Message(str(uuid.uuid4()), '[ADMIN]', text)
            room.messages.append(m)
            await self.broadcast(room, {'type': 'message', 'message': m.to_dict()})
            self.log(f"[{room.name}] [ADMIN] {admin_name}: {text}", "admin")
            await reply(True, 'Broadcast sent')

        elif cmd == 'announce' and len(parts) >= 2:
            await self.broadcast_system(room, f"[ANNOUNCEMENT] {' '.join(parts[1:])}")
            await reply(True, 'Announcement sent')

        elif cmd == 'clear':
            room.messages.clear()
            await self.broadcast(room, {'type': 'clear_chat'})
            self.log(f"[{room.name}] {admin_name} cleared chat", "admin")
            await reply(True, 'Chat cleared')

        elif cmd == 'ban' and len(parts) >= 2:
            target = parts[1]
            room.banned_users.add(target.lower())
            for ws, info in list(room.clients.items()):
                if info["username"].lower() == target.lower():
                    await self.send_encrypted(room, ws, {'type': 'kicked', 'message': 'You have been banned'})
                    await ws.close()
                    await self.broadcast_system(room, f"{target} was banned")
            self.log(f"[{room.name}] {admin_name} banned {target}", "admin")
            await reply(True, f'Banned {target}')

        elif cmd == 'unban' and len(parts) >= 2:
            target = parts[1]
            if target.lower() in room.banned_users:
                room.banned_users.discard(target.lower())
                await reply(True, f'Unbanned {target}')
            else:
                await reply(False, f'{target} is not banned')

        elif cmd == 'bans':
            banned = list(room.banned_users)
            await reply(True, f"Banned in '{room.name}' ({len(banned)}): {', '.join(banned)}" if banned else "No banned users")

        elif cmd == 'stats':
            uptime = int(time.time() - self.start_time)
            await reply(True, (f"Server Stats:\n"
                               f"Uptime: {uptime // 3600}h {(uptime % 3600) // 60}m {uptime % 60}s\n"
                               f"Room: {room.name}\n"
                               f"Messages: {len(room.messages)}\n"
                               f"Online here: {len(room.clients)}\n"
                               f"Rooms on server: {len(self.rooms)}"))

        elif cmd == 'export':
            export_data = {
                'server_name': 'EncryptedChat', 'room': room.name,
                'export_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'message_count': len(room.messages),
                'messages': [m.to_dict() for m in room.messages]
            }
            await self.send_encrypted(room, websocket, {
                'type': 'admin_result', 'success': True,
                'message': 'Chat exported (check message)', 'export_data': export_data
            })

    # ---- server console ---------------------------------------------------

    async def console_handler(self):
        loop = asyncio.get_event_loop()
        while True:
            try:
                user_input = (await loop.run_in_executor(None, input)).strip()
                if not user_input:
                    continue

                if user_input.lower() == '/quit':
                    self.log("Shutting down...", "system")
                    for room in self.rooms:
                        for ws in list(room.clients.keys()):
                            await ws.close()
                    return

                elif user_input.lower() == '/rooms':
                    for room in self.rooms:
                        self.log(f"  '{room.name}': {len(room.clients)} online, {len(room.messages)} msgs", "info")

                elif user_input.lower() == '/users':
                    for room in self.rooms:
                        users = [c['username'] for c in room.clients.values()]
                        self.log(f"  '{room.name}': {', '.join(users) if users else '(empty)'}", "info")

                elif user_input.lower() == '/help':
                    print("\nServer Commands:")
                    print("  /rooms  - list rooms with online/message counts")
                    print("  /users  - list users per room")
                    print("  /quit   - shut the server down\n")

                else:
                    print("Unknown command. Type /help.")

            except EOFError:
                self.log("Running in background mode (no console)", "system")
                await asyncio.sleep(float('inf'))
            except Exception as e:
                self.log(f"Console error: {e}", "error")

    async def run(self):
        generate_self_signed_cert()

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)

        print("\n" + "=" * 50)
        print("  ENCRYPTED CHAT SERVER (WSS, multi-room)")
        print("=" * 50)
        print(f"  Protocol: wss:// (secure WebSocket)")
        print(f"  Listening: {SERVER_HOST}:{SERVER_PORT}")
        print(f"  Rooms: {', '.join(r.name for r in self.rooms)}")
        print(f"  Admin password: set ({len(ADMIN_PASSWORD)} chars)")
        print("=" * 50)
        print("\nType /help for commands\n")

        async with serve(self.handle_client, SERVER_HOST, SERVER_PORT,
                         ssl=ssl_context, ping_interval=30, ping_timeout=10):
            self.log(f"WSS server running on wss://{SERVER_HOST}:{SERVER_PORT} with {len(self.rooms)} room(s)", "wss")
            self.log("Waiting for connections...", "system")
            await self.console_handler()


def main():
    server = ChatServer()
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    main()
