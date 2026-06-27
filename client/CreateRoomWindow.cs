using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;

namespace EncryptedChat
{
    /// <summary>
    /// "Create a Room" screen: asks a central server to spin up a new room (name + key +
    /// optional admin password), then drops the user straight into it. Joining others use
    /// the room's key on the Connect screen.
    /// </summary>
    public class CreateRoomWindow : Window
    {
        public bool ChatOpened { get; private set; }

        private readonly Window _menu;
        private readonly TextBox _server, _port, _user, _room, _key, _adminPw;
        private readonly TextBlock _status;

        public CreateRoomWindow(Window menu)
        {
            _menu = menu;
            Title = "Create a Room";
            Width = 560;
            Height = 640;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = AppPalette.BgBrush;

            var s = Settings.Load();
            var stack = new StackPanel { Margin = new Thickness(50, 26), Spacing = 8 };

            var back = Ui.FlatButton("← Back", 90);
            back.HorizontalAlignment = HorizontalAlignment.Left;
            back.Click += (_, _) => Close();
            stack.Children.Add(back);

            stack.Children.Add(new TextBlock
            {
                Text = "➕ Create a Room",
                FontSize = 22, FontWeight = FontWeight.Bold, Foreground = AppPalette.AccentBrush,
                HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 6, 0, 2)
            });
            stack.Children.Add(new TextBlock
            {
                Text = "Spin up a new room on a central server. Share its key to invite people.",
                FontSize = 12, Foreground = AppPalette.MutedBrush, TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 12)
            });

            stack.Children.Add(Ui.Label("Server address (host or IP):"));
            _server = Ui.Field(s.ServerAddress, "chat.example.com"); stack.Children.Add(_server);

            stack.Children.Add(Ui.Label("Port:"));
            _port = Ui.Field((s.ServerPort > 0 ? s.ServerPort : Configuration.DEFAULT_SERVER_PORT).ToString()); stack.Children.Add(_port);

            stack.Children.Add(Ui.Label("Room name:"));
            _room = Ui.Field(watermark: "My Room"); stack.Children.Add(_room);

            stack.Children.Add(Ui.Label("Room key (the shared secret to join — pick a strong one):"));
            _key = Ui.Password(); stack.Children.Add(_key);

            stack.Children.Add(Ui.Label("Admin password for this room (optional):"));
            _adminPw = Ui.Password(); stack.Children.Add(_adminPw);

            stack.Children.Add(Ui.Label("Your username:"));
            _user = Ui.Field(s.Username, "Your name"); stack.Children.Add(_user);

            var create = Ui.AccentButton("Create & Join", 220);
            create.HorizontalAlignment = HorizontalAlignment.Center;
            create.Margin = new Thickness(0, 14, 0, 0);
            create.Click += Create_Click;
            stack.Children.Add(create);

            _status = new TextBlock
            {
                Foreground = AppPalette.MutedBrush, HorizontalAlignment = HorizontalAlignment.Center,
                TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center, Margin = new Thickness(0, 10, 0, 0)
            };
            stack.Children.Add(_status);

            Content = new ScrollViewer { Content = stack };
        }

        private async void Create_Click(object? sender, RoutedEventArgs e)
        {
            string host = (_server.Text ?? "").Trim();
            string username = (_user.Text ?? "").Trim();
            string roomName = (_room.Text ?? "").Trim();
            string key = _key.Text ?? "";
            string adminPw = _adminPw.Text ?? "";

            if (string.IsNullOrEmpty(host)) { await Dialogs.Error(this, "Please enter a server address."); return; }
            if (!int.TryParse((_port.Text ?? "").Trim(), out int port) || port <= 0) { await Dialogs.Error(this, "Please enter a valid port."); return; }
            if (string.IsNullOrEmpty(roomName)) { await Dialogs.Error(this, "Please enter a room name."); return; }
            if (string.IsNullOrEmpty(key)) { await Dialogs.Error(this, "Please enter a room key."); return; }
            if (string.IsNullOrEmpty(username)) { await Dialogs.Error(this, "Please enter a username."); return; }

            _status.Text = "Creating room...";
            IsEnabled = false;
            try
            {
                var (ok, message) = await CentralClient.CreateRoomAsync(host, port, roomName, key, adminPw);
                if (!ok)
                {
                    IsEnabled = true;
                    _status.Text = "Couldn't create room.";
                    await Dialogs.Error(this, string.IsNullOrEmpty(message) ? "Could not create the room." : message);
                    return;
                }

                // Room created — now join it with the key.
                var chat = new ChatWindow(username, key, ChatWindow.ConnectionMode.Central, host, port);
                bool connected = await chat.ConnectAsync();
                if (connected)
                {
                    new Settings { ServerAddress = host, ServerPort = port, Username = username, EncryptionKey = key }.Save();
                    ChatOpened = true;
                    chat.Closed += (_, _) => _menu.Show();
                    chat.Show();
                    Close();
                }
                else
                {
                    IsEnabled = true;
                    _status.Text = "Room created, but joining failed.";
                    await Dialogs.Error(this, "The room was created but the connection to join it failed. Try Connect to Server with the same key.");
                }
            }
            catch (Exception ex)
            {
                IsEnabled = true;
                _status.Text = "Error.";
                await Dialogs.Error(this, ex.Message);
            }
        }
    }
}
