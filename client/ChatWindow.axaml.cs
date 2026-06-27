using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace EncryptedChat
{
    public partial class ChatWindow : Window
    {
        public enum ConnectionMode { Central, Lan }

        private readonly string _username;
        private readonly string _encryptionKey;
        private readonly ConnectionMode _mode;
        private readonly string? _host;
        private readonly int _port;

        private CentralClient? _centralClient;
        private LanClient? _lanClient;

        private readonly List<Message> _messages = new();
        private readonly List<string> _onlineUsers = new();
        private readonly Dictionary<string, Bitmap> _imageCache = new();
        private string? _replyToMessageId;
        private bool _isAdmin;
        private DispatcherTimer? _typingTimer;
        private bool _isTyping;

        public ChatWindow(string username, string encryptionKey, ConnectionMode mode,
                          string? host = null, int port = 0)
        {
            InitializeComponent();

            _username = username;
            _encryptionKey = encryptionKey;
            _mode = mode;
            _host = host;
            _port = port;

            Title = $"Encrypted Chat - {username}";

            _typingTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _typingTimer.Tick += (_, _) =>
            {
                if (_isTyping)
                {
                    _isTyping = false;
                    SendTypingIndicator(false);
                }
            };

            Closed += ChatWindow_Closed;
        }

        public async Task<bool> ConnectAsync()
        {
            try
            {
                if (_mode == ConnectionMode.Central)
                {
                    _centralClient = new CentralClient();
                    _centralClient.OnMessage += OnMessageReceived;
                    _centralClient.OnStatus += OnStatusReceived;
                    _centralClient.OnDisconnected += OnDisconnected;
                    return await _centralClient.ConnectAsync(_username, _encryptionKey, _host ?? string.Empty, _port);
                }
                else
                {
                    _lanClient = new LanClient();
                    _lanClient.OnMessage += OnMessageReceived;
                    _lanClient.OnStatus += OnStatusReceived;
                    _lanClient.OnDisconnected += OnDisconnected;
                    return await _lanClient.ConnectAsync(_host!, _port, _username, _encryptionKey);
                }
            }
            catch (Exception ex)
            {
                await Dialogs.Error(this, $"Connection error: {ex.Message}");
                return false;
            }
        }

        // ---- incoming messages -------------------------------------------------

        private void OnMessageReceived(string type, string json)
        {
            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    switch (type)
                    {
                        case "welcome": HandleWelcome(root); break;
                        case "message": HandleMessage(root); break;
                        case "system": HandleSystemMessage(root); break;
                        case "user_list": HandleUserList(root); break;
                        case "typing_status": HandleTypingStatus(root); break;
                        case "message_edited": HandleMessageEdited(root); break;
                        case "message_deleted": HandleMessageDeleted(root); break;
                        case "reaction_update": HandleReactionUpdate(root); break;
                        case "admin_auth_result": HandleAdminAuthResult(root); break;
                        case "admin_result": HandleAdminResult(root); break;
                        case "kicked": HandleKicked(root); break;
                        case "error": HandleError(root); break;
                        case "clear_chat":
                            _messages.Clear();
                            _imageCache.Clear();
                            RefreshMessageList();
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling message: {ex.Message}");
                }
            });
        }

        private void HandleWelcome(JsonElement root)
        {
            if (root.TryGetProperty("room", out var roomName) && roomName.ValueKind == JsonValueKind.String)
                ServerNameText.Text = $"# {roomName.GetString()}";

            if (root.TryGetProperty("message", out var msg))
                AddSystemMessage(msg.GetString() ?? "Connected");

            if (root.TryGetProperty("online_users", out var users))
            {
                _onlineUsers.Clear();
                foreach (var u in users.EnumerateArray())
                    _onlineUsers.Add(u.GetString() ?? "Unknown");
                UpdateUserList();
            }

            if (root.TryGetProperty("message_history", out var history))
            {
                foreach (var m in history.EnumerateArray())
                {
                    var message = JsonSerializer.Deserialize<Message>(m.GetRawText());
                    if (message != null) _messages.Add(message);
                }
                RefreshMessageList();
            }
        }

        private void HandleMessage(JsonElement root)
        {
            if (root.TryGetProperty("message", out var msgElement))
            {
                var message = JsonSerializer.Deserialize<Message>(msgElement.GetRawText());
                if (message != null)
                {
                    _messages.Add(message);
                    AddMessageToUI(message);
                }
            }
        }

        private void HandleSystemMessage(JsonElement root)
        {
            if (root.TryGetProperty("message", out var msg))
                AddSystemMessage(msg.GetString() ?? "");
        }

        private void HandleUserList(JsonElement root)
        {
            if (root.TryGetProperty("users", out var users))
            {
                _onlineUsers.Clear();
                foreach (var u in users.EnumerateArray())
                    _onlineUsers.Add(u.GetString() ?? "Unknown");
                UpdateUserList();
            }

            if (root.TryGetProperty("admins", out var admins))
            {
                foreach (var a in admins.EnumerateArray())
                {
                    if (a.GetString() == _username)
                    {
                        _isAdmin = true;
                        AdminButton.IsVisible = true;
                    }
                }
            }
        }

        private void HandleTypingStatus(JsonElement root)
        {
            if (!root.TryGetProperty("users", out var users)) return;
            var typing = users.EnumerateArray()
                .Select(u => u.GetString())
                .Where(u => u != _username && !string.IsNullOrEmpty(u))
                .ToList();
            TypingIndicatorText.Text = typing.Count switch
            {
                0 => "",
                1 => $"{typing[0]} is typing…",
                _ => $"{string.Join(", ", typing.Take(3))} are typing…"
            };
        }

        private void HandleMessageEdited(JsonElement root)
        {
            if (!root.TryGetProperty("message", out var msgElement)) return;
            var updated = JsonSerializer.Deserialize<Message>(msgElement.GetRawText());
            if (updated == null) return;
            var existing = _messages.FirstOrDefault(m => m.Id == updated.Id);
            if (existing != null)
            {
                existing.Content = updated.Content;
                existing.Edited = updated.Edited;
                existing.EditedBy = updated.EditedBy;
                RefreshMessageList();
            }
        }

        private void HandleMessageDeleted(JsonElement root)
        {
            if (!root.TryGetProperty("message_id", out var msgId)) return;
            var message = _messages.FirstOrDefault(m => m.Id == msgId.GetString());
            if (message != null)
            {
                message.Deleted = true;
                message.Content = "[Message deleted]";
                message.ImageData = null;
                RefreshMessageList();
            }
        }

        private void HandleReactionUpdate(JsonElement root)
        {
            if (root.TryGetProperty("message_id", out var msgId) &&
                root.TryGetProperty("reactions", out var reactions))
            {
                var message = _messages.FirstOrDefault(m => m.Id == msgId.GetString());
                if (message != null)
                {
                    message.Reactions = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(reactions.GetRawText())
                        ?? new Dictionary<string, List<string>>();
                    RefreshMessageList();
                }
            }
        }

        private void HandleAdminAuthResult(JsonElement root)
        {
            if (root.TryGetProperty("success", out var success) && success.GetBoolean())
            {
                _isAdmin = true;
                AdminButton.IsVisible = true;
                _ = Dialogs.Info(this, "Admin authenticated!", "Success");
            }
            else
            {
                _ = Dialogs.Error(this, "Admin authentication failed");
            }
        }

        private void HandleAdminResult(JsonElement root)
        {
            if (root.TryGetProperty("message", out var msg))
                _ = Dialogs.Info(this, msg.GetString() ?? "", "Admin");
        }

        private void HandleKicked(JsonElement root)
        {
            string reason = "You have been kicked";
            if (root.TryGetProperty("message", out var msg))
                reason = msg.GetString() ?? reason;
            Dispatcher.UIThread.Post(async () =>
            {
                await Dialogs.Info(this, reason, "Kicked");
                Close();
            });
        }

        private void HandleError(JsonElement root)
        {
            string message = "An error occurred";
            if (root.TryGetProperty("message", out var msg))
                message = msg.GetString() ?? message;
            _ = Dialogs.Error(this, message, "Server Error");
        }

        private void OnStatusReceived(string status) => Console.WriteLine($"Status: {status}");

        private void OnDisconnected()
        {
            Dispatcher.UIThread.Post(async () =>
            {
                await Dialogs.Info(this, "Disconnected from server", "Disconnected");
                Close();
            });
        }

        // ---- building the message list ----------------------------------------

        private static string Truncate(string? text, int max)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return text.Length <= max ? text : text.Substring(0, max) + "…";
        }

        private void AddSystemMessage(string content)
        {
            var border = new Border
            {
                Background = AppPalette.B(AppPalette.SysBg),
                CornerRadius = new CornerRadius(5),
                Padding = new Thickness(10, 5),
                Margin = new Thickness(0, 2),
                HorizontalAlignment = HorizontalAlignment.Center,
                Child = new TextBlock
                {
                    Text = content,
                    Foreground = AppPalette.B(AppPalette.SysText),
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap
                }
            };
            MessagesPanel.Items.Add(border);
            ScrollToBottom();
        }

        private void AddMessageToUI(Message message)
        {
            MessagesPanel.Items.Add(CreateMessagePanel(message));
            ScrollToBottom();
        }

        private Control CreateMessagePanel(Message message)
        {
            var mainBorder = new Border
            {
                Background = message.Deleted ? AppPalette.B(Color.FromRgb(40, 40, 40)) : Brushes.Transparent,
                Padding = new Thickness(10, 5),
                Margin = new Thickness(0, 2),
                Tag = message.Id
            };

            var stack = new StackPanel();

            // header
            var header = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            header.Children.Add(new TextBlock
            {
                Text = message.Username,
                FontWeight = FontWeight.Bold,
                Foreground = AppPalette.GreenBrush,
                FontSize = 14
            });
            header.Children.Add(new TextBlock
            {
                Text = message.GetDateTime().ToString("HH:mm"),
                Foreground = AppPalette.MutedBrush,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center
            });
            if (message.Edited)
                header.Children.Add(new TextBlock
                {
                    Text = "(edited)",
                    Foreground = AppPalette.MutedBrush,
                    FontSize = 10,
                    FontStyle = FontStyle.Italic,
                    VerticalAlignment = VerticalAlignment.Center
                });
            stack.Children.Add(header);

            // reply context
            if (!string.IsNullOrEmpty(message.ReplyTo))
            {
                var repliedTo = _messages.FirstOrDefault(m => m.Id == message.ReplyTo);
                string snippet = repliedTo != null
                    ? $"↩ {repliedTo.Username}: {Truncate(repliedTo.Content, 60)}"
                    : "↩ replying to a message";
                stack.Children.Add(new TextBlock
                {
                    Text = snippet,
                    Foreground = AppPalette.MutedBrush,
                    FontSize = 11,
                    FontStyle = FontStyle.Italic,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Margin = new Thickness(0, 2)
                });
            }

            // content
            stack.Children.Add(new TextBlock
            {
                Text = message.Content,
                Foreground = message.Deleted ? AppPalette.MutedBrush : AppPalette.TextBrush,
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
                FontStyle = message.Deleted ? FontStyle.Italic : FontStyle.Normal,
                Margin = new Thickness(0, 2, 0, 5)
            });

            // image
            if (!string.IsNullOrEmpty(message.ImageData) && !message.Deleted)
            {
                try
                {
                    if (string.IsNullOrEmpty(message.Id) || !_imageCache.TryGetValue(message.Id, out var bitmap))
                    {
                        var bytes = Convert.FromBase64String(message.ImageData);
                        using var ms = new MemoryStream(bytes);
                        bitmap = new Bitmap(ms);
                        if (!string.IsNullOrEmpty(message.Id))
                            _imageCache[message.Id] = bitmap;
                    }
                    stack.Children.Add(new Image
                    {
                        Source = bitmap,
                        MaxWidth = 400,
                        MaxHeight = 300,
                        Margin = new Thickness(0, 5),
                        Stretch = Stretch.Uniform,
                        HorizontalAlignment = HorizontalAlignment.Left
                    });
                }
                catch { /* unreadable image */ }
            }

            // reactions
            if (message.Reactions.Count > 0)
            {
                var wrap = new WrapPanel { Margin = new Thickness(0, 5, 0, 0) };
                foreach (var reaction in message.Reactions)
                {
                    bool mine = reaction.Value.Contains(_username);
                    var btn = new Button
                    {
                        Content = $"{reaction.Key} {reaction.Value.Count}",
                        Background = mine ? AppPalette.EdgeBrush : AppPalette.PanelBrush,
                        Foreground = AppPalette.TextBrush,
                        BorderBrush = mine ? AppPalette.GreenBrush : AppPalette.EdgeBrush,
                        BorderThickness = new Thickness(1),
                        Padding = new Thickness(6, 2),
                        Margin = new Thickness(0, 0, 5, 0),
                        FontSize = 11,
                        Cursor = new Cursor(StandardCursorType.Hand),
                        Tag = (message.Id, reaction.Key)
                    };
                    btn.Click += ReactionButton_Click;
                    wrap.Children.Add(btn);
                }
                stack.Children.Add(wrap);
            }

            // actions
            if (!message.Deleted)
            {
                var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 5, Margin = new Thickness(0, 5, 0, 0) };

                var reply = ActionButton("Reply", message.Id, AppPalette.MutedBrush);
                reply.Click += ReplyButton_Click;
                actions.Children.Add(reply);

                if (message.Username == _username || _isAdmin)
                {
                    var edit = ActionButton("Edit", message.Id, AppPalette.MutedBrush);
                    edit.Click += EditButton_Click;
                    actions.Children.Add(edit);

                    var del = ActionButton("Delete", message.Id, AppPalette.B(AppPalette.Danger));
                    del.Click += DeleteButton_Click;
                    actions.Children.Add(del);
                }

                var react = ActionButton("😊", message.Id, AppPalette.MutedBrush);
                react.Click += AddReactionButton_Click;
                actions.Children.Add(react);

                stack.Children.Add(actions);
            }

            mainBorder.Child = stack;
            return mainBorder;
        }

        private static Button ActionButton(string content, string? tag, IBrush foreground) => new Button
        {
            Content = content,
            FontSize = 10,
            Padding = new Thickness(5, 2),
            Background = Brushes.Transparent,
            Foreground = foreground,
            BorderThickness = new Thickness(0),
            Cursor = new Cursor(StandardCursorType.Hand),
            Tag = tag
        };

        private void RefreshMessageList()
        {
            MessagesPanel.Items.Clear();
            foreach (var message in _messages)
                AddMessageToUI(message);
        }

        private void UpdateUserList()
        {
            UserListBox.Items.Clear();
            foreach (var user in _onlineUsers.OrderBy(u => u))
                UserListBox.Items.Add(user);
            OnlineCountText.Text = $"ONLINE — {_onlineUsers.Count}";
        }

        private void ScrollToBottom()
        {
            Dispatcher.UIThread.Post(() =>
            {
                MessageScrollViewer.Offset = new Vector(MessageScrollViewer.Offset.X, MessageScrollViewer.Extent.Height);
            }, DispatcherPriority.Background);
        }

        // ---- sending ----------------------------------------------------------

        private async void SendMessage_Click(object? sender, RoutedEventArgs e) => await SendCurrentMessage();

        private async void MessageInput_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && !e.KeyModifiers.HasFlag(KeyModifiers.Shift))
            {
                e.Handled = true;
                await SendCurrentMessage();
            }
        }

        private void MessageInput_TextChanged(object? sender, TextChangedEventArgs e)
        {
            if (!_isTyping && !string.IsNullOrWhiteSpace(MessageInput.Text))
            {
                _isTyping = true;
                SendTypingIndicator(true);
            }
            _typingTimer?.Stop();
            _typingTimer?.Start();
        }

        private async Task SendCurrentMessage()
        {
            string content = (MessageInput.Text ?? string.Empty).Trim();
            if (string.IsNullOrEmpty(content)) return;
            if (_centralClient is null && _lanClient is null) return;

            try
            {
                if (_mode == ConnectionMode.Central) await _centralClient!.SendMessageAsync(content, _replyToMessageId);
                else await _lanClient!.SendMessageAsync(content, _replyToMessageId);

                MessageInput.Text = string.Empty;
                _replyToMessageId = null;
                ReplyPreviewPanel.IsVisible = false;
                _isTyping = false;
                SendTypingIndicator(false);
            }
            catch (Exception ex)
            {
                await Dialogs.Error(this, $"Failed to send message: {ex.Message}");
            }
        }

        private async void SendTypingIndicator(bool isTyping)
        {
            if (_centralClient is null && _lanClient is null) return;
            try
            {
                if (_mode == ConnectionMode.Central) await _centralClient!.SendTypingAsync(isTyping);
                else await _lanClient!.SendTypingAsync(isTyping);
            }
            catch { /* non-fatal */ }
        }

        // ---- per-message actions ----------------------------------------------

        private void ReplyButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string messageId)
            {
                var message = _messages.FirstOrDefault(m => m.Id == messageId);
                if (message != null)
                {
                    _replyToMessageId = messageId;
                    ReplyUsernameText.Text = message.Username;
                    ReplyPreviewPanel.IsVisible = true;
                    MessageInput.Focus();
                }
            }
        }

        private void CancelReply_Click(object? sender, RoutedEventArgs e)
        {
            _replyToMessageId = null;
            ReplyPreviewPanel.IsVisible = false;
        }

        private async void EditButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string messageId) return;
            var message = _messages.FirstOrDefault(m => m.Id == messageId);
            if (message == null) return;

            var dialog = new EditMessageDialog(message.Content);
            await dialog.ShowDialog(this);
            if (!dialog.Confirmed) return;
            try
            {
                if (_mode == ConnectionMode.Central) await _centralClient!.EditMessageAsync(messageId, dialog.NewContent);
                else await _lanClient!.EditMessageAsync(messageId, dialog.NewContent);
            }
            catch (Exception ex) { await Dialogs.Error(this, $"Failed to edit: {ex.Message}"); }
        }

        private async void DeleteButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string messageId) return;
            if (!await Dialogs.Confirm(this, "Delete this message?")) return;
            try
            {
                if (_mode == ConnectionMode.Central) await _centralClient!.DeleteMessageAsync(messageId);
                else await _lanClient!.DeleteMessageAsync(messageId);
            }
            catch (Exception ex) { await Dialogs.Error(this, $"Failed to delete: {ex.Message}"); }
        }

        private async void ReactionButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ValueTuple<string, string> t)
                await SendReaction(t.Item1, t.Item2);
        }

        private async void AddReactionButton_Click(object? sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string messageId) return;
            var dialog = new ReactionPickerDialog();
            await dialog.ShowDialog(this);
            if (dialog.Confirmed && !string.IsNullOrEmpty(dialog.SelectedEmoji))
                await SendReaction(messageId, dialog.SelectedEmoji);
        }

        private async Task SendReaction(string messageId, string emoji)
        {
            try
            {
                if (_mode == ConnectionMode.Central) await _centralClient!.SendReactionAsync(messageId, emoji);
                else await _lanClient!.SendReactionAsync(messageId, emoji);
            }
            catch (Exception ex) { await Dialogs.Error(this, $"Failed to react: {ex.Message}"); }
        }

        private void InsertEmoji_Click(object? sender, RoutedEventArgs e)
        {
            Dispatcher.UIThread.Post(async () =>
            {
                var dialog = new ReactionPickerDialog();
                await dialog.ShowDialog(this);
                if (dialog.Confirmed && !string.IsNullOrEmpty(dialog.SelectedEmoji))
                {
                    int caret = MessageInput.CaretIndex;
                    MessageInput.Text = (MessageInput.Text ?? string.Empty).Insert(Math.Clamp(caret, 0, (MessageInput.Text ?? string.Empty).Length), dialog.SelectedEmoji);
                    MessageInput.CaretIndex = caret + dialog.SelectedEmoji.Length;
                    MessageInput.Focus();
                }
            });
        }

        private async void AttachImage_Click(object? sender, RoutedEventArgs e)
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select an image",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Images") { Patterns = new[] { "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp" } }
                }
            });
            if (files.Count == 0) return;

            try
            {
                byte[] imageData;
                await using (var stream = await files[0].OpenReadAsync())
                using (var ms = new MemoryStream())
                {
                    await stream.CopyToAsync(ms);
                    imageData = ms.ToArray();
                }

                if (imageData.Length > Configuration.MAX_IMAGE_SIZE)
                {
                    await Dialogs.Error(this, $"Image too large. Maximum is {Configuration.MAX_IMAGE_SIZE / 1024 / 1024}MB.");
                    return;
                }

                string base64 = Convert.ToBase64String(imageData);
                string caption = (MessageInput.Text ?? string.Empty).Trim();
                if (_mode == ConnectionMode.Central) await _centralClient!.SendMessageAsync(caption, _replyToMessageId, base64);
                else await _lanClient!.SendMessageAsync(caption, _replyToMessageId, base64);

                MessageInput.Text = string.Empty;
                _replyToMessageId = null;
                ReplyPreviewPanel.IsVisible = false;
            }
            catch (Exception ex)
            {
                await Dialogs.Error(this, $"Failed to send image: {ex.Message}");
            }
        }

        private async void Admin_Click(object? sender, RoutedEventArgs e)
        {
            if (!_isAdmin)
            {
                var dialog = new AdminAuthDialog();
                await dialog.ShowDialog(this);
                if (!dialog.Confirmed) return;
                try
                {
                    if (_mode == ConnectionMode.Central) await _centralClient!.AuthenticateAdminAsync(dialog.Password);
                    else await _lanClient!.AuthenticateAdminAsync(dialog.Password);
                }
                catch (Exception ex) { await Dialogs.Error(this, $"Admin auth failed: {ex.Message}"); }
            }
            else
            {
                var dialog = new AdminCommandDialog();
                await dialog.ShowDialog(this);
                if (!dialog.Confirmed || string.IsNullOrEmpty(dialog.Command)) return;
                try
                {
                    if (_mode == ConnectionMode.Central) await _centralClient!.SendAdminCommandAsync(dialog.Command);
                    else await _lanClient!.SendAdminCommandAsync(dialog.Command);
                }
                catch (Exception ex) { await Dialogs.Error(this, $"Admin command failed: {ex.Message}"); }
            }
        }

        private async void ChatWindow_Closed(object? sender, EventArgs e)
        {
            _typingTimer?.Stop();
            if (_centralClient != null) { await _centralClient.DisconnectAsync(); _centralClient.Dispose(); }
            if (_lanClient != null) { await _lanClient.DisconnectAsync(); _lanClient.Dispose(); }
        }
    }
}
