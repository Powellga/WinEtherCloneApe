using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WinEtherCloneApe
{
    /// <summary>Asks for the SSH user name and port before connecting.</summary>
    public class SshDialog : Window
    {
        private readonly TextBox userBox;
        private readonly TextBox portBox;
        private readonly TextBlock error;

        public string UserName { get; private set; } = "";
        public int Port { get; private set; } = 22;

        public SshDialog(string target, string defaultUser, int defaultPort)
        {
            Title = "Connect with SSH";
            Width = 380;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Icon = MainWindow.AppIcon;

            var panel = new StackPanel { Margin = new Thickness(14) };
            panel.Children.Add(new TextBlock { Text = $"Connect to {target}", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 10) });

            panel.Children.Add(new TextBlock { Text = "User name" });
            userBox = new TextBox { Text = defaultUser, Margin = new Thickness(0, 2, 0, 8) };
            panel.Children.Add(userBox);

            panel.Children.Add(new TextBlock { Text = "Port" });
            portBox = new TextBox { Text = defaultPort.ToString(), Width = 80, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 8) };
            panel.Children.Add(portBox);

            error = new TextBlock { Foreground = Brushes.Firebrick, TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
            panel.Children.Add(error);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0) };
            var ok = new Button { Content = "Connect", Width = 85, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
            ok.Click += (_, _) => Accept();
            var cancel = new Button { Content = "Cancel", Width = 85, IsCancel = true };
            buttons.Children.Add(ok);
            buttons.Children.Add(cancel);
            panel.Children.Add(buttons);

            Content = panel;
            Loaded += (_, _) =>
            {
                userBox.Focus();
                userBox.SelectAll();
            };
        }

        private void Accept()
        {
            string user = userBox.Text.Trim();
            if (!ExternalTools.IsSafeUserName(user))
            {
                ShowError("Enter a user name using letters, numbers, dots, dashes, underscores, @ or \\.");
                return;
            }
            if (!int.TryParse(portBox.Text.Trim(), out int port) || port is < 1 or > 65535)
            {
                ShowError("The port must be a number from 1 to 65535.");
                return;
            }

            UserName = user;
            Port = port;
            DialogResult = true;
        }

        private void ShowError(string message)
        {
            error.Text = message;
            error.Visibility = Visibility.Visible;
        }
    }
}
