using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WinEtherCloneApe
{
    /// <summary>
    /// IP address helpers: private/multicast/reserved checks and IPv4 integer conversion
    /// </summary>
    public static class IpUtil
    {
        private static readonly Dictionary<string, string> WellKnownAddresses = new()
        {
            ["255.255.255.255"] = "Broadcast",
            ["224.0.0.1"] = "All hosts (multicast)",
            ["224.0.0.2"] = "All routers (multicast)",
            ["224.0.0.22"] = "IGMP (multicast)",
            ["224.0.0.251"] = "mDNS (multicast)",
            ["224.0.0.252"] = "LLMNR (multicast)",
            ["239.255.255.250"] = "SSDP / UPnP (multicast)",
            ["ff02::1"] = "All nodes (IPv6 multicast)",
            ["ff02::2"] = "All routers (IPv6 multicast)",
            ["ff02::fb"] = "mDNS (IPv6 multicast)",
            ["ff02::1:3"] = "LLMNR (IPv6 multicast)",
            ["ff02::c"] = "SSDP (IPv6 multicast)",
            ["ff02::16"] = "MLDv2 (IPv6 multicast)",
        };

        public static string? WellKnownName(string ip) =>
            WellKnownAddresses.TryGetValue(ip, out var name) ? name : null;

        public static bool TryToUInt(IPAddress ip, out uint value)
        {
            value = 0;
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = ip.GetAddressBytes();
            value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return true;
        }

        public static IPAddress FromUInt(uint value) =>
            new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

        /// <summary>Strips any IPv6 scope id so the text matches what the packet parser produces.</summary>
        public static string Normalize(IPAddress ip) =>
            ip.AddressFamily == AddressFamily.InterNetworkV6 ? new IPAddress(ip.GetAddressBytes()).ToString() : ip.ToString();

        /// <summary>Private, loopback, link-local and carrier-grade NAT addresses.</summary>
        public static bool IsPrivate(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte first = ip.GetAddressBytes()[0];
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (first & 0xFE) == 0xFC;
            }

            byte[] b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }

        public static bool IsMulticast(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetworkV6) return ip.IsIPv6Multicast;
            byte first = ip.GetAddressBytes()[0];
            return first >= 224 && first <= 239;
        }

        /// <summary>0.0.0.0/8 and 240.0.0.0/4 (which includes 255.255.255.255).</summary>
        public static bool IsReserved(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.Equals(IPAddress.IPv6Any);
            byte first = ip.GetAddressBytes()[0];
            return first == 0 || first >= 240;
        }
    }

    /// <summary>
    /// Facts about this PC's own network: its addresses, subnet broadcasts, DNS servers and gateways.
    /// Each set is rebuilt and swapped whole, so readers on other threads always see a complete set.
    /// </summary>
    public static class LocalNetwork
    {
        public static HashSet<string> LocalAddresses { get; private set; } = new();
        public static HashSet<string> BroadcastAddresses { get; private set; } = new() { "255.255.255.255" };
        public static HashSet<string> DnsServers { get; private set; } = new();
        public static HashSet<string> Gateways { get; private set; } = new();

        /// <summary>IPv4 address of the adapter that has the default gateway (the internet-facing one).</summary>
        public static string? PrimaryAddress { get; private set; }

        public static void Refresh()
        {
            var local = new HashSet<string>();
            var broadcast = new HashSet<string> { "255.255.255.255" };
            var dns = new HashSet<string>();
            var gateways = new HashSet<string>();
            string? primary = null;

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                try
                {
                    var props = ni.GetIPProperties();
                    string? firstV4 = null;

                    foreach (var ua in props.UnicastAddresses)
                    {
                        local.Add(IpUtil.Normalize(ua.Address));
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        firstV4 ??= ua.Address.ToString();

                        if (ua.IPv4Mask != null && !ua.IPv4Mask.Equals(IPAddress.Any)
                            && IpUtil.TryToUInt(ua.Address, out uint addr) && IpUtil.TryToUInt(ua.IPv4Mask, out uint mask))
                        {
                            broadcast.Add(IpUtil.FromUInt(addr | ~mask).ToString());
                        }
                    }

                    foreach (var d in props.DnsAddresses)
                        dns.Add(IpUtil.Normalize(d));

                    foreach (var g in props.GatewayAddresses)
                    {
                        if (g.Address.Equals(IPAddress.Any) || g.Address.Equals(IPAddress.IPv6Any)) continue;
                        gateways.Add(IpUtil.Normalize(g.Address));
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork)
                            primary ??= firstV4;
                    }
                }
                catch
                {
                    // Some virtual adapters throw on GetIPProperties - skip them
                }
            }

            LocalAddresses = local;
            BroadcastAddresses = broadcast;
            DnsServers = dns;
            Gateways = gateways;
            PrimaryAddress = primary;
        }

        public static void AddLocalAddress(string ip)
        {
            LocalAddresses = new HashSet<string>(LocalAddresses) { ip };
        }

        public static bool IsBroadcastOrMulticast(IPAddress ip, string text) =>
            BroadcastAddresses.Contains(text) || IpUtil.IsMulticast(ip);
    }
}
