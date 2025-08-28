using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using static WinEtherCloneApe.NetworkNode;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Main Window for WinEtherCloneApe - A Windows EtherApe Clone
    /// Real-time network traffic visualizer
    /// </summary>
    public partial class MainWindow : Window
    {
        private Canvas networkCanvas;
        private ComboBox deviceCombo;
        private Button startButton;
        private Button stopButton;
        private TextBlock statusText;
        private TextBlock statsText;

        private ICaptureDevice currentDevice;
        private readonly ConcurrentDictionary<string, NetworkNode> nodes = new();
        private readonly ConcurrentDictionary<string, NetworkEdge> edges = new();
        private readonly ConcurrentDictionary<string, string> dnsCache = new();
        private readonly Dictionary<string, string> knownServices = new()
        {
            // Common CDN and service IP ranges - partial list for demonstration
            ["1.1.1.1"] = "Cloudflare DNS",
            ["8.8.8.8"] = "Google DNS",
            ["8.8.4.4"] = "Google DNS",
            ["208.67.222.222"] = "OpenDNS",
            ["208.67.220.220"] = "OpenDNS",
        };
        private readonly DispatcherTimer updateTimer;
        private readonly Random random = new();
        private List<IPAddress> localNetworkRanges = new();

        private long totalPackets = 0;
        private long totalBytes = 0;
        private bool isCapturing = false;

        public MainWindow()
        {
            InitializeComponent();

            updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            updateTimer.Tick += UpdateVisualization;
        }

        private void InitializeComponent()
        {
            Title = "WinEtherCloneApe - Windows Network Visualizer";
            Width = 1200;
            Height = 800;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(Color.FromRgb(20, 20, 30));

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Control Panel
            var controlPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Background = new SolidColorBrush(Color.FromRgb(40, 40, 50)),
                Margin = new Thickness(0, 0, 0, 5)
            };

            deviceCombo = new ComboBox
            {
                Width = 300,
                Margin = new Thickness(10),
                VerticalAlignment = VerticalAlignment.Center
            };

            startButton = new Button
            {
                Content = "Start Capture",
                Width = 100,
                Height = 30,
                Margin = new Thickness(5),
                Background = new SolidColorBrush(Colors.Green),
                Foreground = new SolidColorBrush(Colors.White)
            };
            startButton.Click += StartCapture;

            stopButton = new Button
            {
                Content = "Stop Capture",
                Width = 100,
                Height = 30,
                Margin = new Thickness(5),
                Background = new SolidColorBrush(Colors.Red),
                Foreground = new SolidColorBrush(Colors.White),
                IsEnabled = false
            };
            stopButton.Click += StopCapture;

            var clearButton = new Button
            {
                Content = "Clear",
                Width = 80,
                Height = 30,
                Margin = new Thickness(5),
                Background = new SolidColorBrush(Colors.Orange),
                Foreground = new SolidColorBrush(Colors.White)
            };
            clearButton.Click += ClearVisualization;

            // Legend
            var legendPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(20, 5, 0, 0)
            };

            AddLegendItem(legendPanel, "TCP", Colors.Cyan);
            AddLegendItem(legendPanel, "UDP", Colors.Lime);
            AddLegendItem(legendPanel, "ICMP", Colors.Yellow);
            AddLegendItem(legendPanel, "Other", Colors.Magenta);

            controlPanel.Children.Add(new TextBlock
            {
                Text = "Network Interface:",
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 5, 0)
            });
            controlPanel.Children.Add(deviceCombo);
            controlPanel.Children.Add(startButton);
            controlPanel.Children.Add(stopButton);
            controlPanel.Children.Add(clearButton);
            controlPanel.Children.Add(legendPanel);

            // Network Canvas
            networkCanvas = new Canvas
            {
                Background = new SolidColorBrush(Color.FromRgb(10, 10, 20))
            };

            var canvasBorder = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(60, 60, 80)),
                BorderThickness = new Thickness(2),
                Child = networkCanvas
            };

            // Status Bar
            var statusPanel = new Grid
            {
                Background = new SolidColorBrush(Color.FromRgb(40, 40, 50)),
                Height = 30
            };
            statusPanel.ColumnDefinitions.Add(new ColumnDefinition());
            statusPanel.ColumnDefinitions.Add(new ColumnDefinition());

            statusText = new TextBlock
            {
                Text = "Ready",
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };

            statsText = new TextBlock
            {
                Text = "Packets: 0 | Bytes: 0",
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };

            Grid.SetColumn(statusText, 0);
            Grid.SetColumn(statsText, 1);
            statusPanel.Children.Add(statusText);
            statusPanel.Children.Add(statsText);

            Grid.SetRow(controlPanel, 0);
            Grid.SetRow(canvasBorder, 1);
            Grid.SetRow(statusPanel, 2);

            mainGrid.Children.Add(controlPanel);
            mainGrid.Children.Add(canvasBorder);
            mainGrid.Children.Add(statusPanel);

            Content = mainGrid;

            Loaded += OnWindowLoaded;
            Closing += OnWindowClosing;
        }

        private void AddLegendItem(Panel panel, string protocol, Color color)
        {
            var item = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(10, 0, 0, 0)
            };

            var colorRect = new Rectangle
            {
                Width = 15,
                Height = 15,
                Fill = new SolidColorBrush(color),
                Margin = new Thickness(0, 0, 5, 0)
            };

            var label = new TextBlock
            {
                Text = protocol,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            };

            item.Children.Add(colorRect);
            item.Children.Add(label);
            panel.Children.Add(item);
        }

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            LoadNetworkDevices();
            DetectLocalNetworkRanges();
            StartDnsResolver();
        }

        private void DetectLocalNetworkRanges()
        {
            localNetworkRanges.Clear();

            // Add standard private IP ranges
            localNetworkRanges.Add(IPAddress.Parse("10.0.0.0"));
            localNetworkRanges.Add(IPAddress.Parse("172.16.0.0"));
            localNetworkRanges.Add(IPAddress.Parse("192.168.0.0"));

            // Also detect current machine's subnet
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties properties = ni.GetIPProperties();
                    foreach (UnicastIPAddressInformation ip in properties.UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            localNetworkRanges.Add(ip.Address);
                        }
                    }
                }
            }
        }

        private void StartDnsResolver()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(1000); // Check every second

                    var nodesToResolve = nodes.Values
                        .Where(n => !n.IsLocal && n.DisplayName == n.IP) // Only resolve if DisplayName equals IP
                        .Take(10) // Process more at once
                        .ToList();

                    foreach (var node in nodesToResolve)
                    {
                        try
                        {
                            // Check if it's a known service first
                            if (knownServices.ContainsKey(node.IP))
                            {
                                node.DisplayName = knownServices[node.IP];
                                dnsCache[node.IP] = knownServices[node.IP];
                                System.Diagnostics.Debug.WriteLine($"Known service: {node.IP} = {knownServices[node.IP]}");
                                continue;
                            }

                            if (!dnsCache.ContainsKey(node.IP))
                            {
                                // Try reverse DNS lookup
                                var hostEntry = await Dns.GetHostEntryAsync(node.IP);
                                if (!string.IsNullOrEmpty(hostEntry.HostName) && hostEntry.HostName != node.IP)
                                {
                                    dnsCache[node.IP] = hostEntry.HostName;
                                    node.DisplayName = hostEntry.HostName;

                                    // Debug output to console
                                    System.Diagnostics.Debug.WriteLine($"Resolved {node.IP} to {hostEntry.HostName}");
                                }
                                else
                                {
                                    // Try to identify by IP range
                                    string identified = IdentifyByIPRange(node.IP);
                                    if (identified != node.IP)
                                    {
                                        node.DisplayName = identified;
                                        dnsCache[node.IP] = identified;
                                    }
                                    else
                                    {
                                        // Mark as attempted
                                        dnsCache[node.IP] = node.IP;
                                    }
                                }
                            }
                            else if (dnsCache[node.IP] != node.IP)
                            {
                                node.DisplayName = dnsCache[node.IP];
                            }
                        }
                        catch (Exception ex)
                        {
                            // Try to identify by IP range even if DNS fails
                            string identified = IdentifyByIPRange(node.IP);
                            if (identified != node.IP)
                            {
                                node.DisplayName = identified;
                                dnsCache[node.IP] = identified;
                            }
                            else
                            {
                                // Mark as failed so we don't keep retrying
                                dnsCache[node.IP] = node.IP;
                            }
                            System.Diagnostics.Debug.WriteLine($"DNS lookup failed for {node.IP}: {ex.Message}");
                        }
                    }
                }
            });
        }

        private string IdentifyByIPRange(string ipString)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipString);
                byte[] bytes = ip.GetAddressBytes();

                // Check common cloud provider ranges
                // AWS
                if (bytes[0] == 52 || bytes[0] == 54)
                    return "Amazon AWS";

                // Google Cloud
                if (bytes[0] == 35 || (bytes[0] == 34 && bytes[1] >= 64 && bytes[1] <= 127))
                    return "Google Cloud";

                // Microsoft Azure
                if (bytes[0] == 13 || bytes[0] == 20 || bytes[0] == 23 || bytes[0] == 40)
                    return "Microsoft Azure";

                // Cloudflare
                if ((bytes[0] == 104 && bytes[1] >= 16 && bytes[1] <= 31) ||
                    (bytes[0] == 172 && bytes[1] >= 64 && bytes[1] <= 71))
                    return "Cloudflare";

                // Akamai
                if (bytes[0] == 23 && (bytes[1] >= 0 && bytes[1] <= 79))
                    return "Akamai CDN";

                // Facebook/Meta
                if ((bytes[0] == 31 && bytes[1] == 13) ||
                    (bytes[0] == 157 && bytes[1] == 240) ||
                    (bytes[0] == 179 && bytes[1] == 60))
                    return "Meta/Facebook";

                return ipString;
            }
            catch
            {
                return ipString;
            }
        }

        private bool IsLocalIP(string ipString)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipString);

                // Check for loopback
                if (IPAddress.IsLoopback(ip))
                    return true;

                // Check private IP ranges
                byte[] bytes = ip.GetAddressBytes();

                // 10.0.0.0/8
                if (bytes[0] == 10)
                    return true;

                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    return true;

                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168)
                    return true;

                // 169.254.0.0/16 (link-local)
                if (bytes[0] == 169 && bytes[1] == 254)
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        private void LoadNetworkDevices()
        {
            try
            {
                var devices = CaptureDeviceList.Instance;

                foreach (var device in devices)
                {
                    var item = new ComboBoxItem
                    {
                        Content = $"{device.Description} ({device.Name})",
                        Tag = device
                    };
                    deviceCombo.Items.Add(item);
                }

                if (deviceCombo.Items.Count > 0)
                {
                    deviceCombo.SelectedIndex = 0;
                    statusText.Text = "Network interfaces loaded";
                }
                else
                {
                    statusText.Text = "No network interfaces found";
                    startButton.IsEnabled = false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading network devices: {ex.Message}\n\nMake sure WinPcap or Npcap is installed.",
                    "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
                statusText.Text = "Failed to load network interfaces";
                startButton.IsEnabled = false;
            }
        }

        private void StartCapture(object sender, RoutedEventArgs e)
        {
            if (deviceCombo.SelectedItem == null) return;

            try
            {
                currentDevice = ((ComboBoxItem)deviceCombo.SelectedItem).Tag as ICaptureDevice;

                currentDevice.OnPacketArrival += OnPacketArrival;
                currentDevice.Open(DeviceModes.Promiscuous, 1000);

                Task.Run(() => currentDevice.StartCapture());

                isCapturing = true;
                startButton.IsEnabled = false;
                stopButton.IsEnabled = true;
                deviceCombo.IsEnabled = false;
                statusText.Text = "Capturing packets...";

                updateTimer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting capture: {ex.Message}", "Capture Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                statusText.Text = "Failed to start capture";
            }
        }

        private void StopCapture(object sender, RoutedEventArgs e)
        {
            if (currentDevice != null && isCapturing)
            {
                try
                {
                    currentDevice.StopCapture();
                    currentDevice.Close();
                    currentDevice.OnPacketArrival -= OnPacketArrival;

                    isCapturing = false;
                    startButton.IsEnabled = true;
                    stopButton.IsEnabled = false;
                    deviceCombo.IsEnabled = true;
                    statusText.Text = "Capture stopped";

                    updateTimer.Stop();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error stopping capture: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                ProcessPacket(packet);

                Interlocked.Increment(ref totalPackets);
                Interlocked.Add(ref totalBytes, rawPacket.Data.Length);
            }
            catch
            {
                // Silently ignore malformed packets
            }
        }

        private void ProcessPacket(Packet packet)
        {
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null) return;

            string sourceIP = ipPacket.SourceAddress.ToString();
            string destIP = ipPacket.DestinationAddress.ToString();
            int packetSize = ipPacket.TotalLength;

            // Determine protocol and color
            string protocol = "Other";
            Color protocolColor = Colors.Magenta;

            if (packet.Extract<TcpPacket>() != null)
            {
                protocol = "TCP";
                protocolColor = Colors.Cyan;
            }
            else if (packet.Extract<UdpPacket>() != null)
            {
                protocol = "UDP";
                protocolColor = Colors.Lime;
            }
            else if (packet.Extract<IcmpV4Packet>() != null || packet.Extract<IcmpV6Packet>() != null)
            {
                protocol = "ICMP";
                protocolColor = Colors.Yellow;
            }

            // Add/update nodes
            nodes.AddOrUpdate(sourceIP,
                new NetworkNode
                {
                    IP = sourceIP,
                    DisplayName = sourceIP,
                    LastSeen = DateTime.Now,
                    IsLocal = IsLocalIP(sourceIP),
                    BytesTransferred = packetSize
                },
                (key, node) =>
                {
                    node.LastSeen = DateTime.Now;
                    node.PacketCount++;
                    node.BytesTransferred += packetSize;
                    return node;
                });

            nodes.AddOrUpdate(destIP,
                new NetworkNode
                {
                    IP = destIP,
                    DisplayName = destIP,
                    LastSeen = DateTime.Now,
                    IsLocal = IsLocalIP(destIP),
                    BytesTransferred = packetSize
                },
                (key, node) =>
                {
                    node.LastSeen = DateTime.Now;
                    node.PacketCount++;
                    node.BytesTransferred += packetSize;
                    return node;
                });

            // Add/update edge
            string edgeKey = GetEdgeKey(sourceIP, destIP);
            edges.AddOrUpdate(edgeKey,
                new NetworkEdge
                {
                    Source = sourceIP,
                    Destination = destIP,
                    Protocol = protocol,
                    Color = protocolColor,
                    PacketCount = 1,
                    BytesTransferred = packetSize,
                    LastSeen = DateTime.Now
                },
                (key, edge) =>
                {
                    edge.PacketCount++;
                    edge.BytesTransferred += packetSize;
                    edge.LastSeen = DateTime.Now;
                    edge.Protocol = protocol;
                    edge.Color = protocolColor;
                    return edge;
                });
        }

        private string GetEdgeKey(string ip1, string ip2)
        {
            return string.Compare(ip1, ip2) < 0 ? $"{ip1}-{ip2}" : $"{ip2}-{ip1}";
        }

        private void UpdateVisualization(object sender, EventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                networkCanvas.Children.Clear();

                if (nodes.Count == 0) return;

                double centerX = networkCanvas.ActualWidth / 2;
                double centerY = networkCanvas.ActualHeight / 2;
                double radius = Math.Min(centerX, centerY) * 0.8;

                // Position nodes in a circle
                var nodeList = nodes.ToList();
                var nodePositions = new Dictionary<string, Point>();

                for (int i = 0; i < nodeList.Count; i++)
                {
                    double angle = 2 * Math.PI * i / nodeList.Count;
                    double x = centerX + radius * Math.Cos(angle);
                    double y = centerY + radius * Math.Sin(angle);
                    nodePositions[nodeList[i].Key] = new Point(x, y);
                }

                // Draw edges
                var fadeThreshold = DateTime.Now.AddMinutes(-1); // Changed from 5 seconds to 1 minute
                foreach (var edge in edges.Values.Where(e => e.LastSeen > fadeThreshold))
                {
                    if (nodePositions.ContainsKey(edge.Source) && nodePositions.ContainsKey(edge.Destination))
                    {
                        var line = new Line
                        {
                            X1 = nodePositions[edge.Source].X,
                            Y1 = nodePositions[edge.Source].Y,
                            X2 = nodePositions[edge.Destination].X,
                            Y2 = nodePositions[edge.Destination].Y,
                            Stroke = new SolidColorBrush(edge.Color),
                            StrokeThickness = Math.Min(10, 1 + Math.Log10(Math.Max(1, edge.BytesTransferred / 1000))),
                            Opacity = 1.0 - (DateTime.Now - edge.LastSeen).TotalSeconds / 60.0 // Changed to 60 seconds
                        };
                        networkCanvas.Children.Add(line);
                    }
                }

                // Calculate max bytes for node sizing
                long maxBytes = nodes.Values.Any() ? nodes.Values.Max(n => n.BytesTransferred) : 1;
                maxBytes = Math.Max(maxBytes, 1);

                // Draw nodes
                foreach (var kvp in nodeList)
                {
                    var node = kvp.Value;
                    if (node.LastSeen > fadeThreshold && nodePositions.ContainsKey(kvp.Key))
                    {
                        var pos = nodePositions[kvp.Key];

                        // Calculate node size based on bandwidth (20 to 50 pixels)
                        double sizeRatio = Math.Min(1.0, (double)node.BytesTransferred / maxBytes);
                        double nodeSize = 20 + (sizeRatio * 30);

                        // Determine node color: green for local, red for external
                        Color nodeColor = node.IsLocal ? Colors.LimeGreen : Colors.Red;

                        var ellipse = new Ellipse
                        {
                            Width = nodeSize,
                            Height = nodeSize,
                            Fill = new SolidColorBrush(nodeColor),
                            Stroke = new SolidColorBrush(Colors.White),
                            StrokeThickness = 2,
                            Opacity = 1.0 - (DateTime.Now - node.LastSeen).TotalSeconds / 60.0 // Changed to 60 seconds
                        };

                        Canvas.SetLeft(ellipse, pos.X - nodeSize / 2);
                        Canvas.SetTop(ellipse, pos.Y - nodeSize / 2);
                        networkCanvas.Children.Add(ellipse);

                        // IP/Domain Label - Show full IP or domain name
                        string displayText = !string.IsNullOrEmpty(node.DisplayName) && node.DisplayName != node.IP
                            ? node.DisplayName
                            : node.IP;

                        // Truncate very long domain names
                        if (displayText.Length > 30)
                        {
                            displayText = "..." + displayText.Substring(displayText.Length - 27);
                        }

                        var label = new TextBlock
                        {
                            Text = displayText,
                            Foreground = Brushes.White,
                            FontSize = 10,
                            Background = new SolidColorBrush(Color.FromArgb(180, 0, 0, 0))
                        };

                        Canvas.SetLeft(label, pos.X - 40);
                        Canvas.SetTop(label, pos.Y + nodeSize / 2 + 2);
                        networkCanvas.Children.Add(label);
                    }
                }

                // Clean up old entries (change from 10 seconds to 2 minutes for cleanup)
                var cutoffTime = DateTime.Now.AddMinutes(-2);
                var oldNodes = nodes.Where(n => n.Value.LastSeen < cutoffTime).Select(n => n.Key).ToList();
                foreach (var key in oldNodes)
                {
                    nodes.TryRemove(key, out _);
                }

                var oldEdges = edges.Where(e => e.Value.LastSeen < cutoffTime).Select(e => e.Key).ToList();
                foreach (var key in oldEdges)
                {
                    edges.TryRemove(key, out _);
                }

                // Update stats
                statsText.Text = $"Packets: {totalPackets:N0} | Bytes: {FormatBytes(totalBytes)} | Active Nodes: {nodes.Count}";
            });
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }

        private void ClearVisualization(object sender, RoutedEventArgs e)
        {
            nodes.Clear();
            edges.Clear();
            networkCanvas.Children.Clear();
            totalPackets = 0;
            totalBytes = 0;
            statsText.Text = "Packets: 0 | Bytes: 0";
            statusText.Text = "Visualization cleared";
        }

        private void OnWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (isCapturing)
            {
                StopCapture(null, null);
            }
        }
    }

    public class NetworkNode
    {
        public string IP { get; set; }
        public string DisplayName { get; set; }
        public DateTime LastSeen { get; set; }
        public int PacketCount { get; set; }
        public long BytesTransferred { get; set; }
        public bool IsLocal { get; set; }

        public NetworkNode()
        {
            DisplayName = string.Empty;
        }

        public class NetworkEdge
        {
            public string Source { get; set; }
            public string Destination { get; set; }
            public string Protocol { get; set; }
            public Color Color { get; set; }
            public int PacketCount { get; set; }
            public long BytesTransferred { get; set; }
            public DateTime LastSeen { get; set; }
        }

        public class App : Application
        {
            [STAThread]
            public static void Main()
            {
                var app = new App();
                var window = new MainWindow();
                app.Run(window);
            }
        }
    }
}