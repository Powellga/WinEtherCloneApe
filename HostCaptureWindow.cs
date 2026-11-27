using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace WinEtherCloneApe
{
    /// <summary>One packet recorded for a host capture, with the columns shown in the list.</summary>
    public sealed class CapturedPacket
    {
        public int Number { get; set; }
        public DateTime Time { get; init; }
        public string TimeText { get; set; } = "";
        public string Source { get; init; } = "";
        public string Destination { get; init; } = "";
        public string Protocol { get; init; } = "";
        public int Length { get; init; }
        public string Info { get; init; } = "";
        public RawCapture Raw { get; init; } = null!;
    }

    /// <summary>
    /// Records every packet to or from one address while the main capture runs.
    /// Offer() is called on the capture thread; the window drains the queue on the UI thread.
    /// </summary>
    public sealed class HostCapture
    {
        public IPAddress Target { get; }
        public string Ip { get; }
        public ConcurrentQueue<CapturedPacket> Incoming { get; } = new();
        public volatile bool Paused;

        public HostCapture(IPAddress target, string ip)
        {
            Target = target;
            Ip = ip;
        }

        public bool Matches(IPAddress source, IPAddress destination) =>
            source.Equals(Target) || destination.Equals(Target);

        public void Offer(RawCapture raw, Packet packet, IPAddress source, IPAddress destination, string protocol,
            int sourcePort, int destinationPort)
        {
            if (Paused) return;
            Incoming.Enqueue(new CapturedPacket
            {
                Time = raw.Timeval.Date.ToLocalTime(),
                Source = IpUtil.Normalize(source),
                Destination = IpUtil.Normalize(destination),
                Protocol = ProtocolName(protocol, sourcePort, destinationPort),
                Length = raw.Data.Length,
                Info = Summarize(packet, protocol, sourcePort, destinationPort),
                Raw = raw
            });
        }

        private static string ProtocolName(string protocol, int sourcePort, int destinationPort)
        {
            int servicePort = sourcePort > 0 && destinationPort > 0 ? Math.Min(sourcePort, destinationPort) : 0;
            return servicePort > 0 && MainWindow.PortNames.TryGetValue(servicePort, out var name) ? name : protocol;
        }

        private static string Summarize(Packet packet, string protocol, int sourcePort, int destinationPort)
        {
            try
            {
                if (packet.Extract<TcpPacket>() is { } tcp)
                {
                    var flags = new List<string>();
                    if (tcp.Synchronize) flags.Add("SYN");
                    if (tcp.Acknowledgment) flags.Add("ACK");
                    if (tcp.Push) flags.Add("PSH");
                    if (tcp.Finished) flags.Add("FIN");
                    if (tcp.Reset) flags.Add("RST");
                    if (tcp.Urgent) flags.Add("URG");
                    return $"{sourcePort} → {destinationPort} [{string.Join(", ", flags)}] Seq={tcp.SequenceNumber} " +
                           $"Win={tcp.WindowSize} Len={tcp.PayloadData?.Length ?? 0}";
                }
                if (packet.Extract<UdpPacket>() is { } udp)
                    return $"{sourcePort} → {destinationPort} Len={udp.PayloadData?.Length ?? 0}";
                if (packet.Extract<IcmpV4Packet>() is { } icmp)
                    return $"ICMP {icmp.TypeCode}";
                if (packet.Extract<IcmpV6Packet>() is { } icmp6)
                    return $"ICMPv6 {icmp6.Type}";
                if (packet.Extract<ArpPacket>() is { } arp)
                    return arp.Operation == ArpOperation.Request
                        ? $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}"
                        : $"{arp.SenderProtocolAddress} is at {arp.SenderHardwareAddress}";
            }
            catch
            {
                // Fall back to the protocol name
            }
            return protocol;
        }
    }

    /// <summary>
    /// A small Wireshark-style window: a live list of one host's packets, a decode of the selected
    /// packet, and Save / Open in Wireshark as a standard .pcap file.
    /// </summary>
    public class HostCaptureWindow : Window
    {
        private const int MaxPackets = 200_000;
        private const long MaxBytes = 512L * 1024 * 1024;

        public HostCapture Capture { get; }

        private readonly string displayName;
        private readonly Func<bool> isMainCaptureRunning;
        private readonly ObservableCollection<CapturedPacket> packets = new();
        private readonly DispatcherTimer drainTimer;
        private readonly ListView list;
        private readonly TextBox details;
        private readonly TextBlock status;
        private readonly Button pauseButton;
        private readonly CheckBox autoScroll;
        private DateTime? firstTime;
        private long totalBytes;
        private bool limitReached;

        // In the user profile rather than Documents: Documents is often synced to OneDrive,
        // and captures hold raw network traffic
        public static string CaptureFolder { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "WinEtherCloneApe Captures");

        public HostCaptureWindow(HostCapture capture, string displayName, Func<bool> isMainCaptureRunning)
        {
            Capture = capture;
            this.displayName = displayName;
            this.isMainCaptureRunning = isMainCaptureRunning;

            Title = $"Packet capture - {displayName}";
            Width = 1100;
            Height = 720;
            Icon = MainWindow.AppIcon;
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 40));

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(3, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(5) });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(2, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var toolbar = new WrapPanel { Background = new SolidColorBrush(Color.FromRgb(45, 45, 55)) };
            pauseButton = ToolButton("Pause", Colors.DarkGoldenrod);
            pauseButton.Click += (_, _) => SetPaused(!Capture.Paused);
            var clearButton = ToolButton("Clear", Colors.DimGray);
            clearButton.Click += (_, _) => ClearPackets();
            var saveButton = ToolButton("Save .pcap...", Colors.SteelBlue);
            saveButton.Click += (_, _) => SaveAs();
            var wiresharkButton = ToolButton("Open in Wireshark", Colors.SeaGreen);
            wiresharkButton.Click += (_, _) => OpenInWireshark();
            autoScroll = new CheckBox
            {
                Content = "Follow newest",
                IsChecked = true,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0)
            };
            toolbar.Children.Add(pauseButton);
            toolbar.Children.Add(clearButton);
            toolbar.Children.Add(saveButton);
            toolbar.Children.Add(wiresharkButton);
            toolbar.Children.Add(autoScroll);
            Grid.SetRow(toolbar, 0);
            grid.Children.Add(toolbar);

            var view = new GridView();
            AddColumn(view, "No.", nameof(CapturedPacket.Number), 60);
            AddColumn(view, "Time", nameof(CapturedPacket.TimeText), 90);
            AddColumn(view, "Source", nameof(CapturedPacket.Source), 190);
            AddColumn(view, "Destination", nameof(CapturedPacket.Destination), 190);
            AddColumn(view, "Protocol", nameof(CapturedPacket.Protocol), 90);
            AddColumn(view, "Length", nameof(CapturedPacket.Length), 65);
            AddColumn(view, "Info", nameof(CapturedPacket.Info), 420);
            list = new ListView
            {
                View = view,
                ItemsSource = packets,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                Background = new SolidColorBrush(Color.FromRgb(20, 20, 28)),
                Foreground = Brushes.Gainsboro
            };
            VirtualizingPanel.SetIsVirtualizing(list, true);
            VirtualizingPanel.SetVirtualizationMode(list, VirtualizationMode.Recycling);
            var rowStyle = new Style(typeof(ListViewItem));
            var selected = new Trigger { Property = ListBoxItem.IsSelectedProperty, Value = true };
            selected.Setters.Add(new Setter(ForegroundProperty, Brushes.Black));
            rowStyle.Triggers.Add(selected);
            list.ItemContainerStyle = rowStyle;
            list.SelectionChanged += (_, _) =>
            {
                // Stop following new packets so the chosen one stays in view
                if (list.SelectedItem != null) autoScroll!.IsChecked = false;
                ShowDetails(list.SelectedItem as CapturedPacket);
            };
            Grid.SetRow(list, 1);
            grid.Children.Add(list);

            var splitter = new GridSplitter
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                Background = new SolidColorBrush(Color.FromRgb(60, 60, 70))
            };
            Grid.SetRow(splitter, 2);
            grid.Children.Add(splitter);

            details = new TextBox
            {
                IsReadOnly = true,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                Background = new SolidColorBrush(Color.FromRgb(20, 20, 28)),
                Foreground = Brushes.Gainsboro,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Text = "Select a packet to see its layers and bytes."
            };
            Grid.SetRow(details, 3);
            grid.Children.Add(details);

            status = new TextBlock { Foreground = Brushes.LightGray, Margin = new Thickness(8, 4, 8, 4) };
            Grid.SetRow(status, 4);
            grid.Children.Add(status);

            Content = grid;

            drainTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            drainTimer.Tick += (_, _) => Drain();
            drainTimer.Start();
            Closed += (_, _) => drainTimer.Stop();
            UpdateStatus();
        }

        private static Button ToolButton(string text, Color color) => new()
        {
            Content = text,
            Padding = new Thickness(12, 4, 12, 4),
            Margin = new Thickness(6),
            Background = new SolidColorBrush(color),
            Foreground = Brushes.White
        };

        private static void AddColumn(GridView view, string header, string property, double width) =>
            view.Columns.Add(new GridViewColumn
            {
                Header = header,
                Width = width,
                DisplayMemberBinding = new System.Windows.Data.Binding(property)
            });

        private void Drain()
        {
            int added = 0;
            while (added < 3000 && Capture.Incoming.TryDequeue(out var p))
            {
                if (packets.Count >= MaxPackets || totalBytes >= MaxBytes)
                {
                    limitReached = true;
                    SetPaused(true);
                    while (Capture.Incoming.TryDequeue(out _)) { }
                    break;
                }

                firstTime ??= p.Time;
                p.Number = packets.Count + 1;
                p.TimeText = (p.Time - firstTime.Value).TotalSeconds.ToString("0.000000");
                totalBytes += p.Length;
                packets.Add(p);
                added++;
            }

            if (added > 0 && autoScroll.IsChecked == true && packets.Count > 0)
                list.ScrollIntoView(packets[^1]);
            UpdateStatus();
        }

        private void UpdateStatus()
        {
            string state = limitReached
                ? $"Limit reached ({MaxPackets:N0} packets or {MaxBytes / 1024 / 1024} MB). Save, then Clear to keep capturing."
                : Capture.Paused ? "Paused"
                : !isMainCaptureRunning() ? "Waiting: press Start Capture in the main window"
                : "Capturing";
            status.Text = $"{state}   |   {packets.Count:N0} packets, {FormatBytes(totalBytes)}   |   " +
                          $"Everything sent to or from {Capture.Ip}";
        }

        private void SetPaused(bool paused)
        {
            Capture.Paused = paused;
            pauseButton.Content = paused ? "Resume" : "Pause";
            UpdateStatus();
        }

        private void ClearPackets()
        {
            packets.Clear();
            while (Capture.Incoming.TryDequeue(out _)) { }
            firstTime = null;
            totalBytes = 0;
            details.Text = "";
            if (limitReached)
            {
                limitReached = false;
                SetPaused(false);
            }
            UpdateStatus();
        }

        private void ShowDetails(CapturedPacket? p)
        {
            if (p == null) return;
            var sb = new StringBuilder();
            sb.AppendLine($"Packet {p.Number}: {p.Length} bytes at {p.Time:HH:mm:ss.ffffff}, {p.Source} → {p.Destination}");
            sb.AppendLine();
            try
            {
                var packet = Packet.ParsePacket(p.Raw.LinkLayerType, p.Raw.Data);
                sb.AppendLine(packet.ToString(StringOutputType.Verbose));
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Could not decode: {ex.Message}");
            }
            sb.AppendLine();
            sb.Append(HexDump(p.Raw.Data));
            details.Text = sb.ToString();
            details.ScrollToHome();
        }

        private static string HexDump(byte[] data)
        {
            var sb = new StringBuilder();
            for (int offset = 0; offset < data.Length; offset += 16)
            {
                int count = Math.Min(16, data.Length - offset);
                sb.Append(offset.ToString("x4")).Append("  ");
                for (int i = 0; i < 16; i++)
                {
                    sb.Append(i < count ? data[offset + i].ToString("x2") + " " : "   ");
                    if (i == 7) sb.Append(' ');
                }
                sb.Append(' ');
                for (int i = 0; i < count; i++)
                {
                    byte b = data[offset + i];
                    sb.Append(b is >= 32 and < 127 ? (char)b : '.');
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        private string DefaultFileName() =>
            $"capture_{Capture.Ip.Replace(':', '-')}_{DateTime.Now:yyyyMMdd_HHmmss}.pcap";

        /// <summary>Writes every listed packet to a standard .pcap file (opens in Wireshark, tcpdump and others).</summary>
        private bool WritePcap(string path)
        {
            if (packets.Count == 0)
            {
                MessageBox.Show(this, "There are no packets to save yet.", "Packet capture",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return false;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                using var writer = new CaptureFileWriterDevice(path, FileMode.Create);
                writer.Open(new DeviceConfiguration { LinkLayerType = packets[0].Raw.LinkLayerType });
                foreach (var p in packets)
                    writer.Write(p.Raw);
                writer.Close();
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not save the capture: {ex.Message}", "Packet capture",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private void SaveAs()
        {
            Directory.CreateDirectory(CaptureFolder);
            var dialog = new SaveFileDialog
            {
                Title = "Save packet capture",
                InitialDirectory = CaptureFolder,
                FileName = DefaultFileName(),
                Filter = "Packet capture (*.pcap)|*.pcap",
                DefaultExt = ".pcap"
            };
            if (dialog.ShowDialog(this) != true) return;
            if (WritePcap(dialog.FileName))
                status.Text = $"Saved {packets.Count:N0} packets to {dialog.FileName}";
        }

        private void OpenInWireshark()
        {
            string path = Path.Combine(CaptureFolder, DefaultFileName());
            if (!WritePcap(path)) return;

            if (!WiresharkInstalled())
            {
                MessageBox.Show(this,
                    $"Saved to:\n{path}\n\nWireshark does not seem to be installed, so the file is shown in its folder instead. " +
                    "Get Wireshark free from https://www.wireshark.org/download.html",
                    "Packet capture", MessageBoxButton.OK, MessageBoxImage.Information);
                ExternalTools.ShowInFolder(path);
                return;
            }

            ExternalTools.OpenUrl(path);
            status.Text = $"Opened {packets.Count:N0} packets in Wireshark ({path})";
        }

        private static bool WiresharkInstalled()
        {
            if (File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "Wireshark.exe")))
                return true;
            using var key = Registry.ClassesRoot.OpenSubKey(".pcap");
            return key?.GetValue(null) is string handler && handler.Length > 0;
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double size = bytes;
            int order = 0;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }
    }
}
