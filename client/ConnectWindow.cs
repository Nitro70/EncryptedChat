using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;

namespace EncryptedChat
{
    /// <summary>
    /// Central-server connect screen: the user types in ANY server address + port + key.
    /// No server is hardcoded. On success it opens the chat and re-shows the menu on close.
    /// </summary>
    public class ConnectWindow : Window
    {
        public bool ChatOpened { get; private set; }

        private readonly Window _menu;
        private readonly TextBox _server, _port, _user, _key;
        private readonly TextBlock _status;

        public ConnectWindow(Window menu)
        {
            _menu = menu;
            Title = "Connect to Server";
            Width = 560;
            Height = 560;
            CanResize = false;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = AppPalette.BgBrush;

            var s = Settings.Load();
            var stack = new StackPanel { Margin = new Thickness(50, 30), Spacing = 8 };

            var back = Ui.FlatButton("← Back", 90);
            back.HorizontalAlignment = HorizontalAlignment.Left;
            back.Click += (_, _) => Close();
            stack.Children.Add(back);

            stack.Children.Add(new TextBlock
            {
                Text = "🌐 Connect to a Server",
                FontSize = 22,
                FontWeight = FontWeight.Bold,
                Foreground = AppPalette.AccentBrush,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 8, 0, 2)
            });
            stack.Children.Add(new TextBlock
            {
                Text = "Enter the address of a host running the EncryptedChat server.",
                FontSize = 12,
                Foreground = AppPalette.MutedBrush,
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 14)
            });

            stack.Children.Add(Ui.Label("Server address (host or IP):"));
            _server = Ui.Field(s.ServerAddress, "chat.example.com");
            stack.Children.Add(_server);

            stack.Children.Add(Ui.Label("Port:"));
            _port = Ui.Field((s.ServerPort > 0 ? s.ServerPort : Configuration.DEFAULT_SERVER_PORT).ToString());
            stack.Children.Add(_port);

            stack.Children.Add(Ui.Label("Username:"));
            _user = Ui.Field(s.Username, "Your name");
            stack.Children.Add(_user);

            stack.Children.Add(Ui.Label("Encryption key (selects which room you join):"));
            _key = Ui.Password(s.EncryptionKey);
            stack.Children.Add(_key);

            var connect = Ui.AccentButton("Connect", 200);
            connect.HorizontalAlignment = HorizontalAlignment.Center;
            connect.Margin = new Thickness(0, 16, 0, 0);
            connect.Click += Connect_Click;
            stack.Children.Add(connect);

            _status = new TextBlock
            {
                Foreground = AppPalette.MutedBrush,
                HorizontalAlignment = HorizontalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 10, 0, 0)
            };
            stack.Children.Add(_status);

            Content = new ScrollViewer { Content = stack };
        }

        private async void Connect_Click(object? sender, RoutedEventArgs e)
        {
            string host = (_server.Text ?? string.Empty).Trim();
            string username = (_user.Text ?? string.Empty).Trim();
            string key = _key.Text ?? string.Empty;

            if (string.IsNullOrEmpty(host)) { await Dialogs.Error(this, "Please enter a server address."); return; }
            if (!int.TryParse((_port.Text ?? string.Empty).Trim(), out int port) || port <= 0)
            { await Dialogs.Error(this, "Please enter a valid port number."); return; }
            if (string.IsNullOrEmpty(username)) { await Dialogs.Error(this, "Please enter a username."); return; }
            if (string.IsNullOrEmpty(key)) { await Dialogs.Error(this, "Please enter an encryption key."); return; }

            _status.Text = "Connecting...";
            IsEnabled = false;
            try
            {
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
                    _status.Text = "Connection failed.";
                    await Dialogs.Error(this, "Could not join. Check the address, port and key — and note the room must already exist (use \"Create a Room\" first, or ask whoever made it for the key).");
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
