using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WinEtherCloneApe
{
    /// <summary>Router address, login and interfaces for remote capture over SSH.</summary>
    public class RemoteCaptureDialog : Window
    {
        private readonly AppSettings settings;
        private readonly TextBox hostBox;
        private readonly TextBox portBox;
        private readonly TextBox userBox;
        private readonly PasswordBox passwordBox;
        private readonly CheckBox rememberCheck;
        private readonly TextBox interfacesBox;
        private readonly TextBlock message;
        private readonly Button findButton;

        public string Host { get; private set; } = "";
        public int Port { get; private set; } = 22;
        public string User { get; private set; } = "";
        public string Password { get; private set; } = "";
        public List<string> Interfaces { get; private set; } = new();

        public RemoteCaptureDialog(AppSettings settings)
        {
            this.settings = settings;
            Title = "Capture from router over SSH";
            Width = 520;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Icon = MainWindow.AppIcon;

            var panel = new StackPanel { Margin = new Thickness(14) };
            panel.Children.Add(new TextBlock
            {
                Text = "Watches all traffic that passes through your UniFi gateway (or any Linux router with tcpdump). " +
                       "The app logs in over SSH and streams the router's packets here. Nothing is installed on the router.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            });

            string defaultHost = settings.RouterHost.Length > 0 ? settings.RouterHost
                : LocalNetwork.Gateways.FirstOrDefault(g => !g.Contains(':')) ?? "";

            hostBox = AddField(panel, "Router address", defaultHost, 200);
            portBox = AddField(panel, "SSH port", settings.RouterPort.ToString(), 80);
            userBox = AddField(panel, "User name (UniFi uses root)", settings.RouterUser, 200);

            panel.Children.Add(new TextBlock { Text = "Password (the SSH password set in UniFi OS)" });
            passwordBox = new PasswordBox { Width = 200, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 4) };
            panel.Children.Add(passwordBox);
            rememberCheck = new CheckBox
            {
                Content = "Remember password in Windows Credential Manager",
                IsChecked = true,
                Margin = new Thickness(0, 0, 0, 8)
            };
            panel.Children.Add(rememberCheck);

            panel.Children.Add(new TextBlock
            {
                Text = "Router interfaces to watch, separated by commas. br0 is the main LAN; each VLAN has its own bridge " +
                       "(such as br10). Add the WAN port (such as eth8) to also see blocked probes from the internet.",
                TextWrapping = TextWrapping.Wrap
            });
            var interfaceRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 8) };
            interfacesBox = new TextBox { Text = settings.RouterInterfaces, Width = 260 };
            findButton = new Button { Content = "Find interfaces", Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(8, 1, 8, 1) };
            findButton.Click += async (_, _) => await FindInterfaces();
            interfaceRow.Children.Add(interfacesBox);
            interfaceRow.Children.Add(findButton);
            panel.Children.Add(interfaceRow);

            panel.Children.Add(new TextBlock
            {
                Text = "To allow SSH from this PC only, add two UniFi firewall rules for traffic to the gateway: allow TCP port 22 " +
                       "from this PC's address, then block TCP port 22 from all internal networks.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = Brushes.DimGray,
                Margin = new Thickness(0, 0, 0, 8)
            });

            message = new TextBlock { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed, Margin = new Thickness(0, 0, 0, 6) };
            panel.Children.Add(message);

            var buttons = new DockPanel { Margin = new Thickness(0, 6, 0, 0), LastChildFill = false };
            var forget = new Button { Content = "Forget saved password and router key", Padding = new Thickness(8, 1, 8, 1) };
            forget.Click += (_, _) => Forget();
            DockPanel.SetDock(forget, Dock.Left);
            buttons.Children.Add(forget);
            var cancel = new Button { Content = "Cancel", Width = 85, IsCancel = true };
            DockPanel.SetDock(cancel, Dock.Right);
            buttons.Children.Add(cancel);
            var ok = new Button { Content = "Start", Width = 85, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
            ok.Click += (_, _) => Accept();
            DockPanel.SetDock(ok, Dock.Right);
            buttons.Children.Add(ok);
            panel.Children.Add(buttons);

            Content = panel;
            Loaded += (_, _) =>
            {
                LoadSavedPassword();
                if (passwordBox.Password.Length == 0) passwordBox.Focus();
            };
        }

        private static TextBox AddField(Panel panel, string label, string value, double width)
        {
            panel.Children.Add(new TextBlock { Text = label });
            var box = new TextBox { Text = value, Width = width, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 8) };
            panel.Children.Add(box);
            return box;
        }

        private void LoadSavedPassword()
        {
            if (!int.TryParse(portBox.Text.Trim(), out int port)) return;
            string? saved = CredentialStore.Load(CredentialStore.RouterTarget(userBox.Text.Trim(), hostBox.Text.Trim(), port));
            if (saved != null) passwordBox.Password = saved;
        }

        private bool Validate()
        {
            string host = hostBox.Text.Trim();
            if (!RemoteCaptureSession.IsValidHost(host)) return Fail("Enter the router's address, such as 192.168.0.1.");
            if (!int.TryParse(portBox.Text.Trim(), out int port) || port is < 1 or > 65535) return Fail("The port must be a number from 1 to 65535.");
            string user = userBox.Text.Trim();
            if (!ExternalTools.IsSafeUserName(user)) return Fail("Enter a user name using letters, numbers, dots, dashes or underscores.");
            if (passwordBox.Password.Length == 0) return Fail("Enter the router's SSH password.");

            Host = host;
            Port = port;
            User = user;
            Password = passwordBox.Password;
            return true;
        }

        private void Accept()
        {
            if (!Validate()) return;
            var interfaces = RemoteCaptureSession.ParseInterfaces(interfacesBox.Text);
            if (interfaces.Count == 0) { Fail("Enter at least one interface, such as br0."); return; }
            var bad = interfaces.FirstOrDefault(i => !RemoteCaptureSession.IsValidInterface(i));
            if (bad != null) { Fail($"\"{bad}\" is not a valid interface name."); return; }
            Interfaces = interfaces;

            settings.RouterHost = Host;
            settings.RouterPort = Port;
            settings.RouterUser = User;
            settings.RouterInterfaces = string.Join(", ", interfaces);
            settings.Save();

            string target = CredentialStore.RouterTarget(User, Host, Port);
            try
            {
                if (rememberCheck.IsChecked == true) CredentialStore.Save(target, User, Password);
                else CredentialStore.Delete(target);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            DialogResult = true;
        }

        private async Task FindInterfaces()
        {
            if (!Validate()) return;
            findButton.IsEnabled = false;
            Show("Connecting to the router...", Brushes.DimGray);
            var session = new RemoteCaptureSession(Host, Port, User, Password, settings, this);
            try
            {
                string list = await Task.Run(() =>
                {
                    session.Connect();
                    return session.ListInterfaces();
                });

                // Bridges carry the LAN and VLANs: suggest them, ignoring ones with no address
                var bridges = list.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    .Where(p => p.Length >= 3 && p[0].StartsWith("br") && p[0].All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_'))
                    .Select(p => p[0])
                    .Distinct()
                    .ToList();
                if (bridges.Count > 0) interfacesBox.Text = string.Join(", ", bridges);
                Show(bridges.Count > 0
                        ? $"Found {bridges.Count} LAN and VLAN bridge(s), filled in above. All interfaces with addresses:\n{list.Trim()}"
                        : $"No bridges found. Interfaces with addresses:\n{list.Trim()}",
                    Brushes.DarkGreen);
            }
            catch (Exception ex)
            {
                Show(ex.Message, Brushes.Firebrick);
            }
            finally
            {
                session.Dispose();
                findButton.IsEnabled = true;
            }
        }

        private void Forget()
        {
            string host = hostBox.Text.Trim();
            if (int.TryParse(portBox.Text.Trim(), out int port))
            {
                CredentialStore.Delete(CredentialStore.RouterTarget(userBox.Text.Trim(), host, port));
                settings.RouterHostKeys.Remove($"{host}:{port}");
                settings.Save();
            }
            passwordBox.Password = "";
            Show("Saved password and router key removed. The next connection will ask you to trust the router again.", Brushes.DimGray);
        }

        private bool Fail(string text)
        {
            Show(text, Brushes.Firebrick);
            return false;
        }

        private void Show(string text, Brush color)
        {
            message.Text = text;
            message.Foreground = color;
            message.Visibility = Visibility.Visible;
        }
    }
}
