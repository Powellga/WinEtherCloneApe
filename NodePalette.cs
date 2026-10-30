using System.Windows.Media;

namespace WinEtherCloneApe
{
    /// <summary>
    /// A major internet company, recognized by its network numbers (ASNs), host names or organization name.
    /// </summary>
    public sealed class Provider
    {
        public required string Name { get; init; }
        public required Color Color { get; init; }
        public required int[] Asns { get; init; }
        public required string[] HostSuffixes { get; init; }
        public required string[] OrgKeywords { get; init; }
    }

    /// <summary>
    /// Node and connection colors. Red is reserved for threats.
    /// </summary>
    public static class NodePalette
    {
        // Node colors
        public static readonly Color Threat = Color.FromRgb(255, 23, 68);
        public static readonly Color DnsServer = Color.FromRgb(255, 214, 0);
        public static readonly Color LocalLan = Color.FromRgb(50, 205, 50);
        public static readonly Color Broadcast = Color.FromRgb(120, 120, 120);
        public static readonly Color External = Color.FromRgb(176, 190, 197);

        // Connection colors
        public static readonly Color TcpLine = Colors.Cyan;
        public static readonly Color UdpLine = Colors.Lime;
        public static readonly Color IcmpLine = Colors.Yellow;
        public static readonly Color ArpLine = Colors.Orchid;
        public static readonly Color OtherLine = Colors.Magenta;
        public static readonly Color BroadcastLine = Color.FromRgb(128, 128, 128);

        public static Color LineColorFor(string protocol) => protocol switch
        {
            "TCP" => TcpLine,
            "UDP" => UdpLine,
            "ICMP" => IcmpLine,
            "ARP" => ArpLine,
            _ => OtherLine
        };

        /// <summary>Top 10 internet companies most home and office traffic goes to.</summary>
        public static readonly Provider[] Providers =
        {
            new()
            {
                Name = "Microsoft", Color = Color.FromRgb(0, 176, 255),
                Asns = new[] { 8075, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 12076, 3598, 6584, 23468 },
                HostSuffixes = new[] { "microsoft.com", "msn.com", "live.com", "windows.net", "windows.com", "azure.com",
                    "msedge.net", "office.com", "office.net", "office365.com", "outlook.com", "bing.com", "skype.com",
                    "xboxlive.com", "windowsupdate.com", "azureedge.net", "trafficmanager.net", "cloudapp.net",
                    "microsoftonline.com", "sharepoint.com", "msftncsi.com", "msocsp.com", "1drv.com", "onedrive.com" },
                OrgKeywords = new[] { "microsoft" }
            },
            new()
            {
                Name = "Amazon", Color = Color.FromRgb(255, 145, 0),
                Asns = new[] { 16509, 14618, 8987, 7224, 9059, 17493, 38895, 39111, 62785 },
                HostSuffixes = new[] { "amazonaws.com", "amazon.com", "cloudfront.net", "awsglobalaccelerator.com",
                    "a2z.com", "amazonvideo.com", "media-amazon.com", "aws.dev" },
                OrgKeywords = new[] { "amazon" }
            },
            new()
            {
                Name = "Google", Color = Color.FromRgb(170, 0, 255),
                Asns = new[] { 15169, 396982, 36040, 36384, 36385, 43515, 19527, 139070, 36492, 16550, 41264 },
                HostSuffixes = new[] { "1e100.net", "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
                    "youtube.com", "googlevideo.com", "ytimg.com", "googlesyndication.com", "doubleclick.net",
                    "google-analytics.com", "gvt1.com", "gvt2.com" },
                OrgKeywords = new[] { "google" }
            },
            new()
            {
                Name = "Apple", Color = Color.FromRgb(244, 143, 177),
                Asns = new[] { 714, 6185, 2709 },
                HostSuffixes = new[] { "apple.com", "icloud.com", "aaplimg.com", "apple-dns.net", "mzstatic.com",
                    "icloud-content.com", "cdn-apple.com" },
                OrgKeywords = new[] { "apple inc", "apple computer" }
            },
            new()
            {
                Name = "Meta", Color = Color.FromRgb(48, 79, 254),
                Asns = new[] { 32934, 54115, 63293 },
                HostSuffixes = new[] { "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net", "whatsapp.com",
                    "tfbnw.net", "facebook.net", "fbsbx.com", "cdninstagram.com" },
                OrgKeywords = new[] { "facebook", "meta platforms" }
            },
            new()
            {
                Name = "Cloudflare", Color = Color.FromRgb(161, 136, 127),
                Asns = new[] { 13335, 209242, 395747 },
                HostSuffixes = new[] { "cloudflare.com", "cloudflare.net", "one.one.one.one", "cloudflare-dns.com" },
                OrgKeywords = new[] { "cloudflare" }
            },
            new()
            {
                Name = "Akamai", Color = Color.FromRgb(0, 191, 165),
                Asns = new[] { 20940, 16625, 16702, 12222, 21342, 21357, 23454, 23455, 24319, 33905, 34164, 35993, 35994, 63949 },
                HostSuffixes = new[] { "akamai.net", "akamaitechnologies.com", "akamaiedge.net", "akamaized.net",
                    "edgekey.net", "edgesuite.net", "akamaihd.net", "linodeusercontent.com" },
                OrgKeywords = new[] { "akamai", "linode" }
            },
            new()
            {
                Name = "Netflix", Color = Color.FromRgb(255, 255, 255),
                Asns = new[] { 2906, 40027, 55095 },
                HostSuffixes = new[] { "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com" },
                OrgKeywords = new[] { "netflix" }
            },
            new()
            {
                Name = "Oracle", Color = Color.FromRgb(175, 180, 43),
                Asns = new[] { 31898, 792, 793, 794, 7160, 1215, 1216, 1217, 1218, 1219 },
                HostSuffixes = new[] { "oracle.com", "oraclecloud.com", "oraclevcn.com" },
                OrgKeywords = new[] { "oracle" }
            },
            new()
            {
                Name = "Fastly", Color = Color.FromRgb(255, 171, 145),
                Asns = new[] { 54113 },
                HostSuffixes = new[] { "fastly.net", "fastlylb.net", "fastly.com" },
                OrgKeywords = new[] { "fastly" }
            },
        };

        /// <summary>Well-known public DNS resolvers, recognized before any DNS traffic is seen.</summary>
        public static readonly HashSet<string> KnownPublicResolvers = new()
        {
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2", "94.140.14.14", "94.140.15.15",
            "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:119:35::35"
        };

        private static readonly Dictionary<int, Provider> ProviderByAsn =
            Providers.SelectMany(p => p.Asns.Select(a => (a, p))).ToDictionary(x => x.a, x => x.p);

        public static Provider? MatchAsn(int asn) =>
            ProviderByAsn.TryGetValue(asn, out var p) ? p : null;

        public static Provider? MatchHost(string host)
        {
            string h = host.TrimEnd('.').ToLowerInvariant();
            return Providers.FirstOrDefault(p =>
                p.HostSuffixes.Any(s => h == s || h.EndsWith("." + s, StringComparison.Ordinal)));
        }

        public static Provider? MatchOrg(params string?[] names)
        {
            string text = string.Join(" ", names.Where(n => n != null)).ToLowerInvariant();
            if (text.Length == 0) return null;
            return Providers.FirstOrDefault(p => p.OrgKeywords.Any(k => text.Contains(k)));
        }

        public static Color ColorFor(NetworkNode node) => node.Category switch
        {
            NodeCategory.Threat => Threat,
            NodeCategory.Broadcast => Broadcast,
            NodeCategory.DnsServer => DnsServer,
            NodeCategory.Provider => node.Provider!.Color,
            NodeCategory.LocalLan => LocalLan,
            _ => External
        };

        public static string CategoryName(NetworkNode node) => node.Category switch
        {
            NodeCategory.Threat => "THREAT",
            NodeCategory.Broadcast => "Broadcast / multicast",
            NodeCategory.DnsServer => node.IsLocal ? "DNS server (local network)" : "DNS server",
            NodeCategory.Provider => node.Provider!.Name,
            NodeCategory.LocalLan => node.IsThisPc ? "This PC" : node.IsGateway ? "Router / gateway" : "Local network device",
            _ => "Internet host"
        };

        public static string ToHex(Color c) => $"#{c.R:X2}{c.G:X2}{c.B:X2}";
    }
}
