using Avalonia.Controls;
using Avalonia.Interactivity;

namespace EncryptedChat;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void SelectLanMode_Click(object? sender, RoutedEventArgs e)
    {
        var w = new LanModeWindow(this);
        Hide();
        w.Closed += (_, _) => { if (!w.ChatOpened) Show(); };
        w.Show();
    }

    private void SelectServerMode_Click(object? sender, RoutedEventArgs e)
    {
        var w = new ConnectWindow(this);
        Hide();
        w.Closed += (_, _) => { if (!w.ChatOpened) Show(); };
        w.Show();
    }

    private void CreateRoom_Click(object? sender, RoutedEventArgs e)
    {
        var w = new CreateRoomWindow(this);
        Hide();
        w.Closed += (_, _) => { if (!w.ChatOpened) Show(); };
        w.Show();
    }
}
