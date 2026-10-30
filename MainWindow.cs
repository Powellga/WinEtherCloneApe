using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Path = System.IO.Path;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Main Window for WinEtherCloneApe - A Windows EtherApe Clone
    /// Real-time network traffic visualizer
    /// </summary>
    public partial class MainWindow : Window
    {
        // How long things stay on screen (seconds)
        private const double EdgeFullSeconds = 5;
        private const double EdgeRemoveSeconds = 60;
        private const double NodeFadeStartSeconds = 60;
        private const double NodeRemoveSeconds = 120;
        private const double ThreatNodeRemoveSeconds = 600;
        private const int MaxQueuedPackets = 200_000;

        /// <summary>The few facts the visualizer needs from each packet, captured on the capture thread.</summary>
        private readonly record struct PacketInfo(IPAddress Source, IPAddress Destination, string Protocol,
            int Size, int SourcePort, int DestinationPort, DateTime Time, bool BroadcastFrame = false);

        private Canvas networkCanvas = null!;
        private ComboBox deviceCombo = null!;
        private Button startButton = null!;
        private Button stopButton = null!;
        private CheckBox onlineLookupsCheck = null!;
        private TextBlock statusText = null!;
        private TextBlock threatText = null!;
        private TextBlock statsText = null!;
        private TextBlock feedStatusText = null!;

        private static readonly HttpClient Http = CreateHttpClient();
        private readonly AppSettings settings = AppSettings.Load();
        private readonly ThreatIntel threatIntel = new();
        private readonly DnsResolverService dnsResolver = new();
        private readonly IpInfoService ipInfo;
        private readonly bool demoMode;
        private readonly bool demoOpenMap;

        private ICaptureDevice? currentDevice;
        private readonly ConcurrentQueue<PacketInfo> packetQueue = new();
        private int queuedPackets;
        private readonly Dictionary<string, NetworkNode> nodes = new();
        private readonly Dictionary<string, NetworkEdge> edges = new();
        private readonly Dictionary<string, (DateTime Time, string Name, ThreatMatch Match)> threatsSeen = new();
        private readonly Dictionary<Color, SolidColorBrush> brushCache = new();
        private readonly DispatcherTimer updateTimer;
        private int nextNodeOrder;
        private int tickCount;
        private long totalPackets;
        private long totalBytes;
        private bool isCapturing;
        private GeoInfo? homeGeo;

        public MainWindow(bool demoMode = false, bool demoOpenMap = false)
        {
            this.demoMode = demoMode;
            this.demoOpenMap = demoOpenMap;
            ipInfo = new IpInfoService(Http) { Enabled = settings.OnlineLookups };

            InitializeComponent();

            updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            updateTimer.Tick += UpdateVisualization;
        }

        public static readonly ImageSource AppIcon =
            System.Windows.Media.Imaging.BitmapFrame.Create(new Uri("pack://application:,,,/app.ico"));

        private static HttpClient CreateHttpClient()
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("WinEtherCloneApe/2.0");
            return client;
        }

        #region Layout

        private void InitializeComponent()
        {
            Title = "WinEtherCloneApe - Windows Network Visualizer";
            Width = 1400;
            Height = 900;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(Color.FromRgb(20, 20, 30));
            Icon = AppIcon;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Control Panel
            var controlPanel = new WrapPanel
            {
                Orientation = Orientation.Horizontal,
                Background = new SolidColorBrush(Color.FromRgb(40, 40, 50)),
                Margin = new Thickness(0, 0, 0, 5)
            };

            deviceCombo = new ComboBox
            {
                Width = 420,
                Margin = new Thickness(5, 10, 10, 10),
                VerticalAlignment = VerticalAlignment.Center
            };

            startButton = MakeButton("Start Capture", 110, Colors.Green);
            startButton.Click += StartCapture;

            stopButton = MakeButton("Stop Capture", 110, Colors.Firebrick);
            stopButton.IsEnabled = false;
            stopButton.Click += StopCapture;

            var clearButton = MakeButton("Clear", 80, Colors.DarkOrange);
            clearButton.Click += ClearVisualization;

            var mapButton = MakeButton("World Map", 100, Color.FromRgb(30, 100, 180));
            mapButton.ToolTip = "Show every internet host on a world map";
            mapButton.Click += (_, _) => OpenWorldMap();

            onlineLookupsCheck = new CheckBox
            {
                Content = "Online lookups",
                IsChecked = settings.OnlineLookups,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(15, 0, 10, 0),
                ToolTip = "Look up who owns each internet address and where it is (ip-api.com).\n" +
                          "Needed for company colors and the world map. Turn off to keep addresses private."
            };
            onlineLookupsCheck.Checked += (_, _) => SetOnlineLookups(true);
            onlineLookupsCheck.Unchecked += (_, _) => SetOnlineLookups(false);

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
            controlPanel.Children.Add(mapButton);
            controlPanel.Children.Add(onlineLookupsCheck);

            // Network Canvas + legend
            networkCanvas = new Canvas
            {
                Background = new SolidColorBrush(Color.FromRgb(10, 10, 20)),
                ClipToBounds = true
            };

            var canvasBorder = new Border
            {
                BorderBrush = new SolidColorBrush(Color.FromRgb(60, 60, 80)),
                BorderThickness = new Thickness(2),
                Child = networkCanvas
            };

            var middleGrid = new Grid();
            middleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            middleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
            var legend = BuildLegend();
            Grid.SetColumn(canvasBorder, 0);
            Grid.SetColumn(legend, 1);
            middleGrid.Children.Add(canvasBorder);
            middleGrid.Children.Add(legend);

            // Status Bar
            var statusPanel = new Grid
            {
                Background = new SolidColorBrush(Color.FromRgb(40, 40, 50)),
                Height = 30
            };
            statusPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
            statusPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
            statusPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });

            statusText = new TextBlock
            {
                Text = "Ready",
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(10, 0, 0, 0)
            };

            threatText = new TextBlock
            {
                Text = "Threats this session: 0",
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                Cursor = Cursors.Hand,
                ToolTip = "Click to list every threat seen this session"
            };
            threatText.MouseLeftButtonUp += (_, _) => ShowThreatList();

            statsText = new TextBlock
            {
                Text = "Packets: 0 | Bytes: 0",
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };

            Grid.SetColumn(statusText, 0);
            Grid.SetColumn(threatText, 1);
            Grid.SetColumn(statsText, 2);
            statusPanel.Children.Add(statusText);
            statusPanel.Children.Add(threatText);
            statusPanel.Children.Add(statsText);

            Grid.SetRow(controlPanel, 0);
            Grid.SetRow(middleGrid, 1);
            Grid.SetRow(statusPanel, 2);

            mainGrid.Children.Add(controlPanel);
            mainGrid.Children.Add(middleGrid);
            mainGrid.Children.Add(statusPanel);

            Content = mainGrid;

            Loaded += OnWindowLoaded;
            Closing += OnWindowClosing;
        }

        private static Button MakeButton(string text, double width, Color color) => new()
        {
            Content = text,
            Width = width,
            Height = 30,
            Margin = new Thickness(5),
            Background = new SolidColorBrush(color),
            Foreground = Brushes.White
        };

        private FrameworkElement BuildLegend()
        {
            var panel = new StackPanel { Margin = new Thickness(10, 5, 5, 5) };

            AddLegendHeader(panel, "HOSTS");
            AddLegendItem(panel, "Threat (blocklisted)", NodePalette.Threat, isLine: false);
            AddLegendItem(panel, "DNS server", NodePalette.DnsServer, isLine: false);
            AddLegendItem(panel, "Local network", NodePalette.LocalLan, isLine: false);
            AddLegendItem(panel, "Broadcast / multicast", NodePalette.Broadcast, isLine: false);
            foreach (var p in NodePalette.Providers)
                AddLegendItem(panel, p.Name, p.Color, isLine: false);
            AddLegendItem(panel, "Other internet", NodePalette.External, isLine: false);

            AddLegendHeader(panel, "CONNECTIONS");
            AddLegendItem(panel, "TCP", NodePalette.TcpLine, isLine: true);
            AddLegendItem(panel, "UDP", NodePalette.UdpLine, isLine: true);
            AddLegendItem(panel, "ICMP", NodePalette.IcmpLine, isLine: true);
            AddLegendItem(panel, "ARP", NodePalette.ArpLine, isLine: true);
            AddLegendItem(panel, "Other", NodePalette.OtherLine, isLine: true);
            AddLegendItem(panel, "Broadcast", NodePalette.BroadcastLine, isLine: true);

            AddLegendHeader(panel, "THREAT FEEDS");
            feedStatusText = new TextBlock
            {
                Text = "Loading...",
                Foreground = Brushes.LightGray,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            };
            panel.Children.Add(feedStatusText);

            panel.Children.Add(new TextBlock
            {
                Text = "Inner ring: your network\nOuter ring: the internet\n\nHover a host for details.\nRight-click for Zenmap,\nWhere is? and more.",
                Foreground = Brushes.Gray,
                FontSize = 11,
                Margin = new Thickness(0, 14, 0, 0),
                TextWrapping = TextWrapping.Wrap
            });

            return new ScrollViewer
            {
                Content = panel,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = new SolidColorBrush(Color.FromRgb(25, 25, 35))
            };
        }

        private static void AddLegendHeader(Panel panel, string text)
        {
            panel.Children.Add(new TextBlock
            {
                Text = text,
                Foreground = Brushes.Silver,
                FontWeight = FontWeights.Bold,
                FontSize = 11,
                Margin = new Thickness(0, 10, 0, 4)
            });
        }

        private static void AddLegendItem(Panel panel, string text, Color color, bool isLine)
        {
            var item = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 2, 0, 2)
            };

            FrameworkElement swatch = isLine
                ? new Rectangle { Width = 18, Height = 3, Fill = new SolidColorBrush(color), VerticalAlignment = VerticalAlignment.Center }
                : new Ellipse { Width = 13, Height = 13, Fill = new SolidColorBrush(color), Stroke = Brushes.White, StrokeThickness = 1 };
            swatch.Margin = new Thickness(0, 0, 8, 0);

            item.Children.Add(swatch);
            item.Children.Add(new TextBlock
            {
                Text = text,
                Foreground = Brushes.White,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            });
            panel.Children.Add(item);
        }

        #endregion

        #region Startup and capture

        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            LocalNetwork.Refresh();
            if (!demoMode) LoadNetworkDevices();

            threatIntel.Updated += () => Dispatcher.BeginInvoke(OnThreatFeedsUpdated);
            _ = threatIntel.InitializeAsync(Http);

            updateTimer.Start();
            if (demoMode) StartDemo();
        }

        private void LoadNetworkDevices()
        {
            try
            {
                var devices = CaptureDeviceList.Instance
                    .Select(d => (Device: d, Label: DescribeDevice(d, out var ipv4s), Ipv4s: ipv4s))
                    .OrderByDescending(x => x.Ipv4s.Count > 0)
                    .ToList();

                foreach (var (device, label, _) in devices)
                {
                    deviceCombo.Items.Add(new ComboBoxItem { Content = label, Tag = device });
                }

                // Prefer the last adapter used, then the one with the default gateway
                int index = devices.FindIndex(x => x.Device.Name == settings.LastAdapterName);
                if (index < 0 && LocalNetwork.PrimaryAddress != null)
                    index = devices.FindIndex(x => x.Ipv4s.Contains(LocalNetwork.PrimaryAddress));

                if (deviceCombo.Items.Count > 0)
                {
                    deviceCombo.SelectedIndex = Math.Max(0, index);
                    statusText.Text = "Network interfaces loaded - press Start Capture";
                }
                else
                {
                    statusText.Text = "No network interfaces found";
                    startButton.IsEnabled = false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading network devices: {ex.Message}\n\nMake sure Npcap is installed (https://npcap.com).",
                    "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
                statusText.Text = "Failed to load network interfaces";
                startButton.IsEnabled = false;
            }
        }

        private static string DescribeDevice(ICaptureDevice device, out List<string> ipv4s)
        {
            ipv4s = new List<string>();
            if (device is LibPcapLiveDevice { Interface: not null } live)
            {
                ipv4s = live.Interface.Addresses
                    .Select(a => a.Addr?.ipAddress)
                    .Where(ip => ip != null && ip.AddressFamily == AddressFamily.InterNetwork)
                    .Select(ip => ip!.ToString())
                    .ToList();
                string name = live.Interface.FriendlyName ?? device.Description ?? device.Name;
                return ipv4s.Count > 0 ? $"{name}  ({string.Join(", ", ipv4s)})" : name;
            }
            return device.Description ?? device.Name;
        }

        private void StartCapture(object sender, RoutedEventArgs e)
        {
            if (deviceCombo.SelectedItem is not ComboBoxItem { Tag: ICaptureDevice device }) return;

            try
            {
                LocalNetwork.Refresh();
                device.OnPacketArrival += OnPacketArrival;
                device.Open(DeviceModes.Promiscuous, 1000);
                device.StartCapture();
                currentDevice = device;

                settings.LastAdapterName = device.Name;
                settings.Save();

                isCapturing = true;
                startButton.IsEnabled = false;
                stopButton.IsEnabled = true;
                deviceCombo.IsEnabled = false;
                statusText.Text = "Capturing packets...";
            }
            catch (Exception ex)
            {
                device.OnPacketArrival -= OnPacketArrival;
                MessageBox.Show($"Error starting capture: {ex.Message}\n\nPacket capture needs administrator rights and Npcap.",
                    "Capture Error", MessageBoxButton.OK, MessageBoxImage.Error);
                statusText.Text = "Failed to start capture";
            }
        }

        private void StopCapture(object? sender, RoutedEventArgs? e)
        {
            if (currentDevice == null || !isCapturing) return;

            try
            {
                currentDevice.OnPacketArrival -= OnPacketArrival;
                currentDevice.StopCapture();
                currentDevice.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error stopping capture: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                currentDevice = null;
                isCapturing = false;
                startButton.IsEnabled = true;
                stopButton.IsEnabled = false;
                deviceCombo.IsEnabled = true;
                statusText.Text = "Capture stopped";
            }
        }

        /// <summary>Runs on the capture thread: parse, count, and hand off to the UI thread.</summary>
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                Interlocked.Increment(ref totalPackets);
                Interlocked.Add(ref totalBytes, rawPacket.Data.Length);

                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                if (ExtractPacketInfo(packet, rawPacket.Data.Length) is { } info)
                    Enqueue(info);
            }
            catch
            {
                // Silently ignore malformed packets
            }
        }

        private void Enqueue(PacketInfo info)
        {
            if (Interlocked.Increment(ref queuedPackets) <= MaxQueuedPackets)
                packetQueue.Enqueue(info);
            else
                Interlocked.Decrement(ref queuedPackets); // UI is falling behind - drop rather than grow forever
        }

        private static PacketInfo? ExtractPacketInfo(Packet packet, int size)
        {
            // Sent to ff:ff:ff:ff:ff:ff means broadcast, whatever the subnet looks like
            bool broadcastFrame = packet is EthernetPacket eth
                && eth.DestinationHardwareAddress.GetAddressBytes().All(b => b == 0xFF);

            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                string protocol = "Other";
                int sourcePort = 0, destPort = 0;

                if (packet.Extract<TcpPacket>() is { } tcp)
                {
                    protocol = "TCP";
                    sourcePort = tcp.SourcePort;
                    destPort = tcp.DestinationPort;
                }
                else if (packet.Extract<UdpPacket>() is { } udp)
                {
                    protocol = "UDP";
                    sourcePort = udp.SourcePort;
                    destPort = udp.DestinationPort;
                }
                else if (packet.Extract<IcmpV4Packet>() != null || packet.Extract<IcmpV6Packet>() != null)
                {
                    protocol = "ICMP";
                }

                return new PacketInfo(ipPacket.SourceAddress, ipPacket.DestinationAddress, protocol,
                    size, sourcePort, destPort, DateTime.Now, broadcastFrame);
            }

            // ARP requests are broadcasts; draw them to the broadcast node
            var arp = packet.Extract<ArpPacket>();
            if (arp != null && !arp.SenderProtocolAddress.Equals(IPAddress.Any))
            {
                var target = arp.Operation == ArpOperation.Request ? IPAddress.Broadcast : arp.TargetProtocolAddress;
                return new PacketInfo(arp.SenderProtocolAddress, target, "ARP", size, 0, 0, DateTime.Now);
            }

            return null;
        }

        #endregion

        #region Packet processing (UI thread)

        private void ApplyPacket(PacketInfo p)
        {
            var source = GetOrCreateNode(p.Source, p.Time);
            var dest = GetOrCreateNode(p.Destination, p.Time, p.BroadcastFrame);
            bool isBroadcast = source.IsBroadcast || dest.IsBroadcast;

            foreach (var node in new[] { source, dest })
            {
                node.LastSeen = p.Time;
                node.PacketCount++;
                node.BytesTransferred += p.Size;
            }

            // The side using port 53 (or 853 for DNS over TLS) is the DNS server
            if (!isBroadcast)
            {
                if (p.SourcePort is 53 or 853) source.IsDnsServer = true;
                if (p.DestinationPort is 53 or 853) dest.IsDnsServer = true;
            }

            // Remember the service port on the server side (the lower port number)
            if (p.SourcePort > 0 && p.DestinationPort > 0)
            {
                var (server, port) = p.DestinationPort <= p.SourcePort ? (dest, p.DestinationPort) : (source, p.SourcePort);
                if (server.ServicePorts.Count < 12) server.ServicePorts.Add(port);
            }

            string edgeKey = GetEdgeKey(source.IP, dest.IP);
            Color color = isBroadcast ? NodePalette.BroadcastLine : NodePalette.LineColorFor(p.Protocol);

            if (!edges.TryGetValue(edgeKey, out var edge))
            {
                edge = new NetworkEdge
                {
                    Source = source.IP,
                    Destination = dest.IP,
                    Line = new Line { IsHitTestVisible = false }
                };
                Panel.SetZIndex(edge.Line, 0);
                networkCanvas.Children.Add(edge.Line);
                edges[edgeKey] = edge;
            }

            edge.Protocol = p.Protocol;
            edge.Color = color;
            edge.PacketCount++;
            edge.BytesTransferred += p.Size;
            edge.LastSeen = p.Time;
        }

        private static string GetEdgeKey(string ip1, string ip2)
        {
            return string.CompareOrdinal(ip1, ip2) < 0 ? $"{ip1}-{ip2}" : $"{ip2}-{ip1}";
        }

        private NetworkNode GetOrCreateNode(IPAddress address, DateTime now, bool broadcastFrame = false)
        {
            string ip = IpUtil.Normalize(address);
            if (nodes.TryGetValue(ip, out var existing)) return existing;

            bool isBroadcast = broadcastFrame || LocalNetwork.IsBroadcastOrMulticast(address, ip);
            var node = new NetworkNode
            {
                IP = ip,
                Address = address,
                FirstSeen = now,
                LastSeen = now,
                Order = nextNodeOrder++,
                IsBroadcast = isBroadcast,
                IsLocal = IpUtil.IsPrivate(address) || LocalNetwork.LocalAddresses.Contains(ip),
                IsThisPc = LocalNetwork.LocalAddresses.Contains(ip),
                IsGateway = LocalNetwork.Gateways.Contains(ip),
                IsDnsServer = !isBroadcast && (LocalNetwork.DnsServers.Contains(ip) || NodePalette.KnownPublicResolvers.Contains(ip))
            };

            if (!isBroadcast)
            {
                dnsResolver.Request(ip);
                if (!node.IsLocal)
                {
                    node.Threat = threatIntel.Check(address);
                    if (node.Threat != null) RecordThreat(node);
                    ipInfo.Request(ip);
                }
            }

            CreateVisuals(node);
            nodes[ip] = node;
            return node;
        }

        private void CreateVisuals(NetworkNode node)
        {
            node.Shape = new Ellipse
            {
                Stroke = Brushes.White,
                StrokeThickness = 1.5,
                Cursor = Cursors.Hand,
                Tag = node
            };
            node.Label = new TextBlock
            {
                Foreground = Brushes.White,
                FontSize = 10,
                Padding = new Thickness(2, 0, 2, 0),
                Background = new SolidColorBrush(Color.FromArgb(170, 0, 0, 0)),
                Cursor = Cursors.Hand,
                Tag = node
            };
            node.Halo = new Ellipse
            {
                Stroke = BrushFor(NodePalette.Threat),
                StrokeThickness = 3,
                IsHitTestVisible = false,
                Visibility = Visibility.Collapsed
            };

            foreach (FrameworkElement element in new FrameworkElement[] { node.Shape, node.Label })
            {
                // Tooltip text is built when it opens, so it is always current
                var tip = new TextBlock();
                element.ToolTip = tip;
                element.ToolTipOpening += (_, _) => tip.Text = BuildTooltipText(node);
                ToolTipService.SetInitialShowDelay(element, 250);
                ToolTipService.SetShowDuration(element, 60_000);
                element.MouseRightButtonUp += Node_RightClick;
            }

            Panel.SetZIndex(node.Halo, 1);
            Panel.SetZIndex(node.Shape, 2);
            Panel.SetZIndex(node.Label, 3);
            networkCanvas.Children.Add(node.Halo);
            networkCanvas.Children.Add(node.Shape);
            networkCanvas.Children.Add(node.Label);
        }

        private void RemoveVisuals(NetworkNode node)
        {
            networkCanvas.Children.Remove(node.Halo);
            networkCanvas.Children.Remove(node.Shape);
            networkCanvas.Children.Remove(node.Label);
        }

        /// <summary>Applies finished DNS and ip-api lookups to nodes.</summary>
        private void ApplyLookupResults()
        {
            foreach (var node in nodes.Values)
            {
                if (node.IsBroadcast) continue;

                if (!node.HostLookupDone && dnsResolver.TryGet(node.IP, out string? host))
                {
                    node.HostLookupDone = true;
                    node.HostName = host;
                    if (!node.IsLocal && node.Provider == null && host != null)
                        node.Provider = NodePalette.MatchHost(host);
                }

                if (!node.IsLocal && node.Geo == null && ipInfo.TryGet(node.IP, out var geo))
                {
                    ApplyGeo(node, geo);
                }
            }
        }

        private static void ApplyGeo(NetworkNode node, GeoInfo geo)
        {
            node.Geo = geo;
            if (geo.Success && node.Provider == null)
                node.Provider = NodePalette.MatchAsn(geo.AsNumber) ?? NodePalette.MatchOrg(geo.Org, geo.Isp, geo.AsName);
        }

        private void RecordThreat(NetworkNode node)
        {
            if (node.Threat == null || threatsSeen.ContainsKey(node.IP)) return;

            threatsSeen[node.IP] = (DateTime.Now, node.HostName ?? node.IP, node.Threat);
            try
            {
                Directory.CreateDirectory(AppSettings.DataFolder);
                File.AppendAllText(Path.Combine(AppSettings.DataFolder, "threats.log"),
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\t{node.IP}\t{node.Threat.Summary}{Environment.NewLine}");
            }
            catch
            {
                // The on-screen list still has it
            }
        }

        private void OnThreatFeedsUpdated()
        {
            feedStatusText.Text = threatIntel.Status;

            // Re-check everything already on screen against the fresh lists
            foreach (var node in nodes.Values.Where(n => !n.IsLocal && !n.IsBroadcast))
            {
                node.Threat = threatIntel.Check(node.Address);
                RecordThreat(node);
            }
        }

        private void SetOnlineLookups(bool enabled)
        {
            settings.OnlineLookups = enabled;
            settings.Save();
            ipInfo.Enabled = enabled;
            if (enabled)
            {
                foreach (var node in nodes.Values.Where(n => !n.IsLocal && !n.IsBroadcast && n.Geo == null))
                    ipInfo.Request(node.IP);
            }
        }

        #endregion

        #region Rendering

        private void UpdateVisualization(object? sender, EventArgs e)
        {
            var now = DateTime.Now;
            tickCount++;

            int processed = 0;
            while (processed < 50_000 && packetQueue.TryDequeue(out var packet))
            {
                Interlocked.Decrement(ref queuedPackets);
                ApplyPacket(packet);
                processed++;
            }

            if (tickCount % 5 == 0) ApplyLookupResults();

            RemoveExpired(now);
            LayoutAndRender(now);

            // Update stats
            statsText.Text = $"Packets: {Interlocked.Read(ref totalPackets):N0} | Bytes: {FormatBytes(Interlocked.Read(ref totalBytes))} | " +
                             $"Hosts: {nodes.Count} | Connections: {edges.Count}";
            if (threatsSeen.Count > 0)
            {
                threatText.Text = $"⚠ Threats this session: {threatsSeen.Count}";
                threatText.Foreground = BrushFor(NodePalette.Threat);
                threatText.FontWeight = FontWeights.Bold;
            }
        }

        private void LayoutAndRender(DateTime now)
        {
            double width = networkCanvas.ActualWidth;
            double height = networkCanvas.ActualHeight;
            if (width < 100 || height < 100) return;

            var center = new Point(width / 2, height / 2);
            double outerRadius = Math.Max(80, Math.Min(width, height) / 2 - 90);

            // Inner ring: this network. Outer ring: the internet, grouped by color.
            var inner = nodes.Values.Where(n => n.IsLocal || n.IsBroadcast)
                .OrderBy(n => n.IsThisPc ? 0 : n.IsGateway ? 1 : n.IsBroadcast ? 3 : 2)
                .ThenBy(n => n.Order)
                .ToList();
            var outer = nodes.Values.Where(n => !n.IsLocal && !n.IsBroadcast)
                .OrderBy(n => n.Category)
                .ThenBy(n => n.Provider?.Name)
                .ThenBy(n => n.Order)
                .ToList();

            double innerRadius = outer.Count == 0 ? outerRadius * 0.7 : outerRadius * 0.42;
            PlaceRing(inner, center, inner.Count == 1 ? 0 : innerRadius, -Math.PI / 2);
            PlaceRing(outer, center, outerRadius, -Math.PI / 2 + Math.PI / Math.Max(1, outer.Count));

            foreach (var edge in edges.Values)
            {
                if (!nodes.TryGetValue(edge.Source, out var a) || !nodes.TryGetValue(edge.Destination, out var b)) continue;

                double idle = (now - edge.LastSeen).TotalSeconds;
                double opacity = idle <= EdgeFullSeconds
                    ? 0.9
                    : Math.Max(0.06, 0.9 * (1 - (idle - EdgeFullSeconds) / (EdgeRemoveSeconds - EdgeFullSeconds)));

                var line = edge.Line;
                line.X1 = a.Position.X;
                line.Y1 = a.Position.Y;
                line.X2 = b.Position.X;
                line.Y2 = b.Position.Y;
                line.Stroke = BrushFor(edge.Color);
                line.StrokeThickness = Math.Clamp(1 + Math.Log10(1 + edge.BytesTransferred / 1000.0), 1, 7);
                line.Opacity = opacity;
            }

            double pulse = 0.35 + 0.65 * Math.Abs(Math.Sin(now.TimeOfDay.TotalSeconds * 3));
            foreach (var node in nodes.Values)
            {
                RenderNode(node, now, center, pulse);
            }
        }

        private static void PlaceRing(List<NetworkNode> ring, Point center, double radius, double startAngle)
        {
            for (int i = 0; i < ring.Count; i++)
            {
                double angle = startAngle + 2 * Math.PI * i / ring.Count;
                var target = new Point(center.X + radius * Math.Cos(angle), center.Y + radius * Math.Sin(angle));
                var node = ring[i];

                if (!node.HasPosition)
                {
                    node.Position = target;
                    node.HasPosition = true;
                }
                else
                {
                    // Glide toward the new spot instead of jumping when the ring changes
                    node.Position = new Point(
                        node.Position.X + (target.X - node.Position.X) * 0.2,
                        node.Position.Y + (target.Y - node.Position.Y) * 0.2);
                }
            }
        }

        private void RenderNode(NetworkNode node, DateTime now, Point center, double pulse)
        {
            double idle = (now - node.LastSeen).TotalSeconds;
            double removeAt = node.Threat != null ? ThreatNodeRemoveSeconds : NodeRemoveSeconds;
            double opacity = idle <= NodeFadeStartSeconds
                ? 1
                : Math.Max(0.15, 1 - (idle - NodeFadeStartSeconds) / (removeAt - NodeFadeStartSeconds));

            // Size grows with traffic on a log scale: about 14px for a few KB up to 48px for a GB
            double size = 12 + Math.Clamp(6 * Math.Log10(1 + node.BytesTransferred / 1000.0), 0, 36);
            double x = node.Position.X, y = node.Position.Y;

            var shape = node.Shape;
            shape.Width = size;
            shape.Height = size;
            shape.Fill = BrushFor(NodePalette.ColorFor(node));
            shape.StrokeThickness = node.IsThisPc ? 3 : 1.5;
            shape.Opacity = opacity;
            Canvas.SetLeft(shape, x - size / 2);
            Canvas.SetTop(shape, y - size / 2);

            if (node.Threat != null)
            {
                double haloSize = size + 14;
                node.Halo.Visibility = Visibility.Visible;
                node.Halo.Width = haloSize;
                node.Halo.Height = haloSize;
                node.Halo.Opacity = pulse * opacity;
                Canvas.SetLeft(node.Halo, x - haloSize / 2);
                Canvas.SetTop(node.Halo, y - haloSize / 2);
            }
            else
            {
                node.Halo.Visibility = Visibility.Collapsed;
            }

            var label = node.Label;
            string text = LabelText(node);
            if (label.Text != text) label.Text = text;
            label.Foreground = node.Threat != null ? BrushFor(NodePalette.Threat) : Brushes.White;
            label.Opacity = opacity;

            // Put the label just outside the node, pointing away from the center
            double angle = Math.Atan2(y - center.Y, x - center.X);
            if (Math.Abs(x - center.X) < 1 && Math.Abs(y - center.Y) < 1) angle = Math.PI / 2;
            double offset = size / 2 + 4;
            double lx = x + Math.Cos(angle) * offset;
            double ly = y + Math.Sin(angle) * offset - label.ActualHeight / 2;
            if (Math.Cos(angle) < -0.2) lx -= label.ActualWidth;
            else if (Math.Abs(Math.Cos(angle)) <= 0.2) lx -= label.ActualWidth / 2;
            Canvas.SetLeft(label, lx);
            Canvas.SetTop(label, ly);
        }

        private static string LabelText(NetworkNode node)
        {
            string text;
            if (node.IsThisPc) text = $"This PC ({node.IP})";
            else if (node.IsBroadcast) text = IpUtil.WellKnownName(node.IP)
                ?? $"{node.IP} ({(IpUtil.IsMulticast(node.Address) ? "multicast" : "broadcast")})";
            else if (node.HostName != null) text = node.HostName;
            else if (node.Provider != null) text = $"{node.Provider.Name} {node.IP}";
            else text = node.IP;

            if (node.Threat != null) text = "⚠ " + text;
            return text.Length > 36 ? "…" + text[^35..] : text;
        }

        private void RemoveExpired(DateTime now)
        {
            var deadNodes = nodes.Values
                .Where(n => (now - n.LastSeen).TotalSeconds > (n.Threat != null ? ThreatNodeRemoveSeconds : NodeRemoveSeconds))
                .ToList();
            foreach (var node in deadNodes)
            {
                RemoveVisuals(node);
                nodes.Remove(node.IP);
            }

            var deadEdges = edges
                .Where(kv => (now - kv.Value.LastSeen).TotalSeconds > EdgeRemoveSeconds
                             || !nodes.ContainsKey(kv.Value.Source) || !nodes.ContainsKey(kv.Value.Destination))
                .ToList();
            foreach (var (key, edge) in deadEdges)
            {
                networkCanvas.Children.Remove(edge.Line);
                edges.Remove(key);
            }
        }

        private SolidColorBrush BrushFor(Color color)
        {
            if (!brushCache.TryGetValue(color, out var brush))
            {
                brush = new SolidColorBrush(color);
                brush.Freeze();
                brushCache[color] = brush;
            }
            return brush;
        }

        private static string FormatBytes(long bytes)
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

        #endregion

        #region Tooltip and right-click menu

        private static readonly Dictionary<int, string> PortNames = new()
        {
            [20] = "FTP-data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS",
            [67] = "DHCP", [68] = "DHCP", [80] = "HTTP", [110] = "POP3", [123] = "NTP", [137] = "NetBIOS",
            [138] = "NetBIOS", [139] = "NetBIOS", [143] = "IMAP", [161] = "SNMP", [389] = "LDAP", [443] = "HTTPS",
            [445] = "SMB", [465] = "SMTPS", [514] = "Syslog", [587] = "SMTP", [853] = "DNS-over-TLS", [993] = "IMAPS",
            [995] = "POP3S", [1900] = "SSDP", [3389] = "RDP", [3478] = "STUN", [5353] = "mDNS", [5355] = "LLMNR",
            [8080] = "HTTP-alt", [8443] = "HTTPS-alt"
        };

        private static string BuildTooltipText(NetworkNode node)
        {
            var sb = new StringBuilder();
            sb.AppendLine(node.HostName ?? LabelText(node));
            if (node.HostName != null || node.IsThisPc) sb.AppendLine($"IP: {node.IP}");
            sb.AppendLine($"Type: {NodePalette.CategoryName(node)}");

            if (node.Threat != null)
            {
                sb.AppendLine();
                sb.AppendLine("⚠ THREAT - this address is on a blocklist:");
                foreach (var feed in node.Threat.Feeds)
                    sb.AppendLine($"   {feed.Name}: {feed.Description}");
                sb.AppendLine();
            }

            if (node.Geo is { Success: true } geo)
            {
                sb.AppendLine($"Owner: {geo.Owner}");
                if (geo.AsNumber > 0) sb.AppendLine($"Network: AS{geo.AsNumber} {geo.AsName}");
                if (geo.Place.Length > 0) sb.AppendLine($"Location: {geo.Place}");
                if (geo.Hosting) sb.AppendLine("Data center / hosting provider");
                if (geo.Proxy) sb.AppendLine("Flagged as a proxy, VPN or Tor exit");
            }

            if (node.ServicePorts.Count > 0)
            {
                sb.AppendLine("Ports: " + string.Join(", ", node.ServicePorts.Select(p =>
                    PortNames.TryGetValue(p, out var name) ? $"{p} ({name})" : p.ToString())));
            }

            sb.AppendLine($"Packets: {node.PacketCount:N0}    Data: {FormatBytes(node.BytesTransferred)}");
            sb.AppendLine($"First seen: {node.FirstSeen:T}    Last seen: {node.LastSeen:T}");
            sb.Append("Right-click for Zenmap, Where is? and more");
            return sb.ToString();
        }

        private void Node_RightClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is not FrameworkElement { Tag: NetworkNode node } element) return;

            var menu = BuildContextMenu(node);
            menu.PlacementTarget = element;
            menu.IsOpen = true;
            e.Handled = true;
        }

        private ContextMenu BuildContextMenu(NetworkNode node)
        {
            var menu = new ContextMenu();
            string title = node.HostName != null ? $"{node.HostName}  ({node.IP})" : LabelText(node);
            menu.Items.Add(new MenuItem { Header = title, IsEnabled = false, FontWeight = FontWeights.Bold });
            menu.Items.Add(new Separator());

            var zenmap = new MenuItem { Header = "Interrogate with Zenmap", IsEnabled = !node.IsBroadcast };
            foreach (string profile in ExternalTools.ZenmapProfiles)
            {
                var item = new MenuItem { Header = profile };
                item.Click += (_, _) => RunZenmap(node, profile);
                zenmap.Items.Add(item);
            }
            menu.Items.Add(zenmap);

            var whereIs = new MenuItem { Header = "Where is?", IsEnabled = !node.IsBroadcast };
            whereIs.Click += async (_, _) => await ShowWhereIs(node);
            menu.Items.Add(whereIs);

            if (node.Threat != null)
            {
                var details = new MenuItem { Header = "⚠ Threat details...", Foreground = BrushFor(NodePalette.Threat) };
                details.Click += (_, _) => ShowThreatDetails(node);
                menu.Items.Add(details);
            }

            var reputation = new MenuItem { Header = "Check reputation online", IsEnabled = !node.IsLocal && !node.IsBroadcast };
            AddLink(reputation, "AbuseIPDB", $"https://www.abuseipdb.com/check/{node.IP}");
            AddLink(reputation, "VirusTotal", $"https://www.virustotal.com/gui/ip-address/{node.IP}");
            AddLink(reputation, "Shodan", $"https://www.shodan.io/host/{node.IP}");
            AddLink(reputation, "Whois (ARIN)", $"https://search.arin.net/rdap/?query={node.IP}");
            menu.Items.Add(reputation);

            menu.Items.Add(new Separator());
            var copyIp = new MenuItem { Header = "Copy IP address" };
            copyIp.Click += (_, _) => Clipboard.SetText(node.IP);
            menu.Items.Add(copyIp);

            if (node.HostName != null)
            {
                var copyHost = new MenuItem { Header = "Copy host name" };
                copyHost.Click += (_, _) => Clipboard.SetText(node.HostName);
                menu.Items.Add(copyHost);
            }

            return menu;
        }

        private static void AddLink(MenuItem parent, string header, string url)
        {
            var item = new MenuItem { Header = header };
            item.Click += (_, _) => ExternalTools.OpenUrl(url);
            parent.Items.Add(item);
        }

        private void RunZenmap(NetworkNode node, string profile)
        {
            string? path = ExternalTools.FindZenmap(settings.ZenmapPath);
            if (path == null)
            {
                var result = MessageBox.Show(this,
                    "Zenmap was not found. It comes with Nmap (https://nmap.org/download).\n\nDo you want to locate zenmap.exe yourself?",
                    "Zenmap not found", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result != MessageBoxResult.Yes) return;

                var dialog = new OpenFileDialog { Filter = "Zenmap|zenmap.exe|Programs|*.exe", Title = "Locate zenmap.exe" };
                if (dialog.ShowDialog(this) != true) return;
                path = dialog.FileName;
                settings.ZenmapPath = path;
                settings.Save();
            }

            try
            {
                ExternalTools.LaunchZenmap(path, node.IP, profile);
                statusText.Text = $"Zenmap: {profile} on {node.IP}";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not start Zenmap: {ex.Message}", "Zenmap", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task ShowWhereIs(NetworkNode node)
        {
            if (node.IsLocal)
            {
                MessageBox.Show(this,
                    $"{LabelText(node)} is on your own local network, so it is physically close to you " +
                    "(same building or Wi-Fi). Private addresses have no internet location to map.",
                    "Where is?", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            statusText.Text = $"Looking up the location of {node.IP}...";
            var geo = node.Geo is { Success: true } ? node.Geo : await ipInfo.LookupNowAsync(node.IP);
            if (geo is not { Success: true })
            {
                statusText.Text = "Location lookup failed";
                MessageBox.Show(this, $"Could not find a location for {node.IP}. Check the internet connection and try again.",
                    "Where is?", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ApplyGeo(node, geo);
            var home = await GetHomePointAsync();
            statusText.Text = $"{node.IP} is in {geo.Place}";
            new MapWindow($"Where is {node.HostName ?? node.IP}?", home, new List<MapPoint> { ToMapPoint(node) }) { Owner = this }.Show();
        }

        private async void OpenWorldMap()
        {
            var points = nodes.Values
                .Where(n => n.Geo is { Success: true } g && (g.Lat != 0 || g.Lon != 0))
                .Select(ToMapPoint)
                .ToList();

            if (points.Count == 0)
            {
                string why = settings.OnlineLookups
                    ? "No internet hosts have been located yet. Start a capture and give it a few seconds."
                    : "Online lookups are turned off, so internet hosts have no locations. Tick \"Online lookups\" to fill the map.";
                MessageBox.Show(this, why, "World Map", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var home = await GetHomePointAsync();
            new MapWindow($"World Map - {points.Count} internet hosts", home, points) { Owner = this }.Show();
        }

        private async Task<MapPoint?> GetHomePointAsync()
        {
            homeGeo ??= await ipInfo.LookupNowAsync(null);
            if (homeGeo is not { Success: true } g) return null;
            return new MapPoint
            {
                Lat = g.Lat,
                Lon = g.Lon,
                Title = "Your network",
                Lines = { $"Public IP: {g.Ip}", $"Provider: {g.Owner}", $"Location: {g.Place}" },
                Color = NodePalette.ToHex(NodePalette.LocalLan)
            };
        }

        private static MapPoint ToMapPoint(NetworkNode node)
        {
            var geo = node.Geo!;
            var point = new MapPoint
            {
                Lat = geo.Lat,
                Lon = geo.Lon,
                Title = node.HostName ?? node.IP,
                Color = NodePalette.ToHex(NodePalette.ColorFor(node)),
                Threat = node.Threat != null
            };
            if (node.Threat != null) point.Lines.Add($"THREAT - listed on {node.Threat.Summary}");
            if (node.HostName != null) point.Lines.Add($"IP: {node.IP}");
            point.Lines.Add($"Type: {NodePalette.CategoryName(node)}");
            point.Lines.Add($"Owner: {geo.Owner}");
            if (geo.AsNumber > 0) point.Lines.Add($"Network: AS{geo.AsNumber} {geo.AsName}");
            point.Lines.Add($"Location: {geo.Place}");
            point.Lines.Add($"Traffic: {FormatBytes(node.BytesTransferred)} in {node.PacketCount:N0} packets");
            return point;
        }

        private void ShowThreatDetails(NetworkNode node)
        {
            if (node.Threat == null) return;
            var sb = new StringBuilder();
            sb.AppendLine($"{node.HostName ?? node.IP} ({node.IP}) is on these blocklists:");
            sb.AppendLine();
            foreach (var feed in node.Threat.Feeds)
                sb.AppendLine($"• {feed.Name}: {feed.Description}");
            sb.AppendLine();
            sb.AppendLine($"Traffic: {FormatBytes(node.BytesTransferred)} in {node.PacketCount:N0} packets, first seen {node.FirstSeen:T}.");
            if (node.ServicePorts.Count > 0) sb.AppendLine($"Ports: {string.Join(", ", node.ServicePorts)}");
            sb.AppendLine();
            sb.AppendLine("Next steps: right-click > Check reputation online, or Interrogate with Zenmap.");
            MessageBox.Show(this, sb.ToString(), "Threat details", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        private void ShowThreatList()
        {
            if (threatsSeen.Count == 0)
            {
                MessageBox.Show(this, "No blocklisted addresses have been seen this session.", "Threats",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var sb = new StringBuilder();
            foreach (var (ip, entry) in threatsSeen.OrderBy(t => t.Value.Time))
            {
                string name = nodes.TryGetValue(ip, out var n) && n.HostName != null ? $"{n.HostName} " : "";
                sb.AppendLine($"{entry.Time:T}   {name}{ip}   ({entry.Match.Summary})");
            }
            sb.AppendLine();
            sb.AppendLine($"Full log: {Path.Combine(AppSettings.DataFolder, "threats.log")}");
            MessageBox.Show(this, sb.ToString(), $"Threats this session ({threatsSeen.Count})",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        #endregion

        #region Clear, close, demo

        private void ClearVisualization(object sender, RoutedEventArgs e)
        {
            while (packetQueue.TryDequeue(out _)) Interlocked.Decrement(ref queuedPackets);
            foreach (var node in nodes.Values) RemoveVisuals(node);
            foreach (var edge in edges.Values) networkCanvas.Children.Remove(edge.Line);
            nodes.Clear();
            edges.Clear();
            Interlocked.Exchange(ref totalPackets, 0);
            Interlocked.Exchange(ref totalBytes, 0);
            statsText.Text = "Packets: 0 | Bytes: 0";
            statusText.Text = "Visualization cleared";
        }

        private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            updateTimer.Stop();
            StopCapture(null, null);
            settings.Save();
        }

        /// <summary>Simulated traffic so the display can be tried and tested without capturing.</summary>
        private void StartDemo()
        {
            Title += "   [DEMO - simulated traffic]";
            statusText.Text = "Demo mode: simulated traffic";
            deviceCombo.Items.Add(new ComboBoxItem { Content = "Demo - simulated traffic" });
            deviceCombo.SelectedIndex = 0;
            deviceCombo.IsEnabled = false;
            startButton.IsEnabled = false;

            const string pc = "192.168.1.50";
            LocalNetwork.AddLocalAddress(pc);
            var pcAddr = IPAddress.Parse(pc);
            var router = IPAddress.Parse("192.168.1.1");
            var lan = new[] { "192.168.1.20", "192.168.1.31", "192.168.1.44" }.Select(IPAddress.Parse).ToArray();
            var internet = new[]
            {
                "13.107.42.14", "20.190.160.20", "142.250.72.14", "172.217.4.46", "52.95.110.1", "54.239.28.85",
                "17.253.144.10", "157.240.22.35", "104.16.132.229", "23.215.0.136", "45.57.40.1", "151.101.1.140",
                "138.1.33.162", "93.184.215.14", "185.199.108.153"
            }.Select(IPAddress.Parse).ToArray();
            var dnsServer = IPAddress.Parse("8.8.8.8");
            var random = new Random(7);

            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
            timer.Tick += (_, _) =>
            {
                var now = DateTime.Now;
                void Send(IPAddress a, IPAddress b, string proto, int size, int sp, int dp, bool broadcastFrame = false)
                {
                    Interlocked.Increment(ref totalPackets);
                    Interlocked.Add(ref totalBytes, size);
                    Enqueue(new PacketInfo(a, b, proto, size, sp, dp, now, broadcastFrame));
                }

                var host = internet[random.Next(internet.Length)];
                int port = random.Next(49152, 65535);
                Send(pcAddr, host, "TCP", random.Next(60, 1500), port, 443);
                Send(host, pcAddr, "TCP", random.Next(200, 60000), 443, port);

                if (random.Next(4) == 0)
                {
                    Send(pcAddr, router, "UDP", 80, port, 53);
                    Send(router, pcAddr, "UDP", 140, 53, port);
                    Send(router, dnsServer, "UDP", 80, port, 53);
                    Send(dnsServer, router, "UDP", 140, 53, port);
                }
                if (random.Next(6) == 0)
                    Send(lan[random.Next(lan.Length)], IPAddress.Parse("239.255.255.250"), "UDP", 300, 50000, 1900);
                if (random.Next(8) == 0)
                    Send(lan[random.Next(lan.Length)], IPAddress.Broadcast, "ARP", 60, 0, 0);
                if (random.Next(10) == 0)
                    Send(pcAddr, IPAddress.Parse("192.168.1.255"), "UDP", 230, 137, 137, broadcastFrame: true);
                if (random.Next(5) == 0)
                    Send(lan[random.Next(lan.Length)], pcAddr, "TCP", 900, 445, port);
                if (random.Next(12) == 0)
                    Send(pcAddr, IPAddress.Parse("8.8.4.4"), "ICMP", 98, 0, 0);
                if (random.Next(10) == 0 && threatIntel.SampleListedIp() is { } bad)
                {
                    var badAddr = IPAddress.Parse(bad);
                    Send(pcAddr, badAddr, "TCP", 120, port, 8080);
                    Send(badAddr, pcAddr, "TCP", 800, 8080, port);
                }
            };
            timer.Start();

            if (demoOpenMap)
            {
                var mapTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
                mapTimer.Tick += (_, _) =>
                {
                    mapTimer.Stop();
                    OpenWorldMap();
                };
                mapTimer.Start();
            }
        }

        #endregion
    }
}
