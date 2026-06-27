using System;
using System.IO;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace EncryptedChat
{
    /// <summary>
    /// WebSocket client that connects to a user-specified chat server over secure WebSocket (WSS).
    /// </summary>
    public class CentralClient : IDisposable
    {
        private ClientWebSocket? _webSocket;
        private AESCipher? _cipher;
        private CancellationTokenSource? _cancellationTokenSource;
        private bool _isConnected;

        public event Action<string, string>? OnMessage;
        public event Action<string>? OnStatus;
        public event Action? OnDisconnected;

        public bool IsConnected => _isConnected;

        public async Task<bool> ConnectAsync(string username, string encryptionKey, string host, int port)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(host) || port <= 0)
                {
                    OnStatus?.Invoke("Server address and port are required.");
                    return false;
                }

                _cipher = new AESCipher(encryptionKey);
                _webSocket = new ClientWebSocket();
                _cancellationTokenSource = new CancellationTokenSource();

                // Accept self-signed certificates. The server ships with a generated
                // self-signed cert by default, so the client must not reject it.
                _webSocket.Options.RemoteCertificateValidationCallback =
                    (sender, certificate, chain, sslPolicyErrors) => true;

                // Protocol-level WebSocket keepalive. The server pings periodically and
                // ClientWebSocket auto-replies with pong while ReceiveAsync is pending;
                // this also makes the client ping the server periodically.
                _webSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);

                string serverUrl = $"wss://{host}:{port}";
                OnStatus?.Invoke($"Connecting to {serverUrl}...");

                await _webSocket.ConnectAsync(new Uri(serverUrl), _cancellationTokenSource.Token);

                // Mark connected BEFORE sending join. SendEncryptedAsync drops messages
                // while _isConnected is false; previously that meant the join handshake
                // was never sent and the server closed us after its 30s join timeout.
                _isConnected = true;

                // Send join message — the server requires this as the very first message.
                var joinMsg = new
                {
                    type = "join",
                    username = username
                };
                await SendEncryptedAsync(joinMsg);

                OnStatus?.Invoke("Connected!");

                // Start receive loop
                _ = Task.Run(() => ReceiveLoop(_cancellationTokenSource.Token));

                return true;
            }
            catch (Exception ex)
            {
                OnStatus?.Invoke($"Connection failed: {ex.Message}");
                _isConnected = false;
                return false;
            }
        }

        private async Task ReceiveLoop(CancellationToken cancellationToken)
        {
            var buffer = new byte[64 * 1024]; // 64KB read chunk

            try
            {
                while (_isConnected && _webSocket != null && _webSocket.State == WebSocketState.Open)
                {
                    // A single logical message may span multiple WebSocket frames; accumulate
                    // until EndOfMessage before decrypting. Welcome history and image payloads
                    // routinely exceed one frame, so the previous single-read code truncated
                    // (and silently dropped) them.
                    using var ms = new MemoryStream();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await _webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);

                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            _isConnected = false;
                            OnDisconnected?.Invoke();
                            return;
                        }

                        ms.Write(buffer, 0, result.Count);
                    }
                    while (!result.EndOfMessage);

                    if (result.MessageType != WebSocketMessageType.Text || ms.Length == 0)
                        continue;

                    string encrypted = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                    string? decrypted = _cipher?.Decrypt(encrypted);

                    if (decrypted != null)
                    {
                        try
                        {
                            var jsonDoc = JsonDocument.Parse(decrypted);
                            var type = jsonDoc.RootElement.TryGetProperty("type", out var t)
                                ? (t.GetString() ?? "message")
                                : "message";
                            OnMessage?.Invoke(type, decrypted);
                        }
                        catch
                        {
                            // Invalid JSON, ignore
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal cancellation
            }
            catch (Exception ex)
            {
                OnStatus?.Invoke($"Receive error: {ex.Message}");
                _isConnected = false;
                OnDisconnected?.Invoke();
            }
        }

        public async Task SendEncryptedAsync(object data)
        {
            if (_webSocket == null || _cipher == null || !_isConnected)
                return;

            try
            {
                string json = JsonSerializer.Serialize(data);
                string encrypted = _cipher.Encrypt(json);
                byte[] buffer = Encoding.UTF8.GetBytes(encrypted);

                await _webSocket.SendAsync(new ArraySegment<byte>(buffer),
                    WebSocketMessageType.Text, true, _cancellationTokenSource?.Token ?? CancellationToken.None);
            }
            catch (Exception ex)
            {
                OnStatus?.Invoke($"Send error: {ex.Message}");
            }
        }

        public async Task SendMessageAsync(string content, string? replyTo = null, string? imageData = null)
        {
            var msg = new
            {
                type = "message",
                content = content,
                reply_to = replyTo,
                image_data = imageData
            };
            await SendEncryptedAsync(msg);
        }

        public async Task SendTypingAsync(bool isTyping)
        {
            var msg = new { type = "typing", typing = isTyping };
            await SendEncryptedAsync(msg);
        }

        public async Task EditMessageAsync(string messageId, string newContent)
        {
            var msg = new { type = "edit_message", message_id = messageId, content = newContent };
            await SendEncryptedAsync(msg);
        }

        public async Task DeleteMessageAsync(string messageId)
        {
            var msg = new { type = "delete_message", message_id = messageId };
            await SendEncryptedAsync(msg);
        }

        public async Task SendReactionAsync(string messageId, string emoji)
        {
            var msg = new { type = "reaction", message_id = messageId, emoji = emoji };
            await SendEncryptedAsync(msg);
        }

        public async Task AuthenticateAdminAsync(string password)
        {
            var msg = new { type = "admin_auth", password = password };
            await SendEncryptedAsync(msg);
        }

        public async Task SendAdminCommandAsync(string command)
        {
            var msg = new { type = "admin_command", command = command };
            await SendEncryptedAsync(msg);
        }

        /// <summary>
        /// Ask a central server to create a new room. This is a one-shot plaintext control
        /// message (sent over the TLS/WSS connection before any room key is established).
        /// Returns (success, message). After success, connect normally with the key to join.
        /// </summary>
        public static async Task<(bool ok, string message)> CreateRoomAsync(
            string host, int port, string name, string key, string adminPassword)
        {
            if (string.IsNullOrWhiteSpace(host) || port <= 0)
                return (false, "Server address and port are required.");

            using var ws = new ClientWebSocket();
            ws.Options.RemoteCertificateValidationCallback = (s, c, ch, e) => true;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                await ws.ConnectAsync(new Uri($"wss://{host}:{port}"), cts.Token);

                string req = JsonSerializer.Serialize(new
                {
                    type = "create_room",
                    name = name,
                    key = key,
                    adminPassword = adminPassword
                });
                await ws.SendAsync(Encoding.UTF8.GetBytes(req), WebSocketMessageType.Text, true, cts.Token);

                var buffer = new byte[64 * 1024];
                var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cts.Token);
                string respText = Encoding.UTF8.GetString(buffer, 0, result.Count);

                try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None); } catch { }

                using var doc = JsonDocument.Parse(respText);
                var root = doc.RootElement;
                bool success = root.TryGetProperty("success", out var s2) && s2.GetBoolean();
                string msg = root.TryGetProperty("message", out var m) ? (m.GetString() ?? "") : "";
                return (success, msg);
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        public async Task DisconnectAsync()
        {
            _isConnected = false;
            _cancellationTokenSource?.Cancel();

            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                try
                {
                    await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client disconnecting",
                        CancellationToken.None);
                }
                catch { }
            }
        }

        public void Dispose()
        {
            // Non-blocking: never .Wait() on the UI thread. DisconnectAsync is awaited
            // by the window's Closed handler before Dispose is called.
            _isConnected = false;
            try { _cancellationTokenSource?.Cancel(); } catch { }
            _webSocket?.Dispose();
            _cancellationTokenSource?.Dispose();
        }
    }
}
