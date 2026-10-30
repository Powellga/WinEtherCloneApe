using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace WinEtherCloneApe
{
    public enum NodeCategory
    {
        Threat,
        DnsServer,
        Provider,
        LocalLan,
        Broadcast,
        External
    }

    /// <summary>
    /// Location and ownership of an IP address, from ip-api.com
    /// </summary>
    public class GeoInfo
    {
        public string Ip { get; set; } = "";
        public bool Success { get; set; }
        public string? Country { get; set; }
        public string? CountryCode { get; set; }
        public string? Region { get; set; }
        public string? City { get; set; }
        public double Lat { get; set; }
        public double Lon { get; set; }
        public string? Isp { get; set; }
        public string? Org { get; set; }
        public int AsNumber { get; set; }
        public string? AsName { get; set; }
        public bool Proxy { get; set; }
        public bool Hosting { get; set; }

        public string Owner => !string.IsNullOrWhiteSpace(Org) ? Org! : Isp ?? "Unknown";

        public string Place => string.Join(", ", new[] { City, Region, Country }
            .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());
    }

    /// <summary>
    /// A host seen on the wire. Only touched on the UI thread.
    /// </summary>
    public class NetworkNode
    {
        public string IP { get; init; } = "";
        public IPAddress Address { get; init; } = IPAddress.None;
        public string? HostName { get; set; }
        public bool HostLookupDone { get; set; }
        public DateTime FirstSeen { get; init; }
        public DateTime LastSeen { get; set; }
        public long PacketCount { get; set; }
        public long BytesTransferred { get; set; }
        public int Order { get; init; }

        public bool IsLocal { get; init; }
        public bool IsBroadcast { get; init; }
        public bool IsThisPc { get; init; }
        public bool IsGateway { get; init; }
        public bool IsDnsServer { get; set; }

        public Provider? Provider { get; set; }
        public GeoInfo? Geo { get; set; }
        public ThreatMatch? Threat { get; set; }
        public SortedSet<int> ServicePorts { get; } = new();

        public NodeCategory Category =>
            Threat != null ? NodeCategory.Threat
            : IsBroadcast ? NodeCategory.Broadcast
            : IsDnsServer ? NodeCategory.DnsServer
            : Provider != null ? NodeCategory.Provider
            : IsLocal ? NodeCategory.LocalLan
            : NodeCategory.External;

        // Visual elements, created once and updated every frame
        public Ellipse Shape { get; set; } = null!;
        public Ellipse Halo { get; set; } = null!;
        public TextBlock Label { get; set; } = null!;
        public Point Position { get; set; }
        public bool HasPosition { get; set; }
    }

    /// <summary>
    /// Traffic between two hosts (direction-independent). Only touched on the UI thread.
    /// </summary>
    public class NetworkEdge
    {
        public string Source { get; init; } = "";
        public string Destination { get; init; } = "";
        public string Protocol { get; set; } = "";
        public Color Color { get; set; }
        public long PacketCount { get; set; }
        public long BytesTransferred { get; set; }
        public DateTime LastSeen { get; set; }
        public Line Line { get; set; } = null!;
    }
}
